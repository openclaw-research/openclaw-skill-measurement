# Sources

A source discovers skills and fetches their artifacts. All sources implement
[`BaseSource`](../sources/base.py) and are resolved through a single registry in
[`cli.py`](../cli.py) (`_source_registry()`), so a crawl is selected with
`crawl --source <name>`.

The contract (`BaseSource`):

- `source_name` — the value written to the `skills.source` / `crawl_runs.source` column.
- `discover() -> Iterator[SkillMetadata]` — yield lightweight stubs (no artifact bytes).
- `fetch_artifact(source_id, version, detail=None) -> {path: bytes}` — download a skill's
  files; called by the pipeline only when needed (new skill, changed revision, or
  `--verify-existing`).
- `pagination_stopped_early: bool` — set True if discovery aborted before the end of the
  catalog (used to mark a run `failed`). Defaults to False.

`SkillMetadata.raw_detail` carries an already-fetched detail payload from `discover()` through
to `fetch_artifact()` so the artifact step avoids a redundant request. It is **never persisted**.

## Field conventions

These four fields determine identity, versioning, and dedup. Get them right when adding a source.

| Field | Meaning | ClawHub | GitHub (`github-skills`) |
|-------|---------|---------|--------------------------|
| `source_id` | Stable unique id **within** the source | skill `slug` | `"{owner}/{repo}//{skill_dir}"` — `//` separates repo from the intra-repo path so one repo holds many skills (`skill_dir` is `""` for a repo-root `SKILL.md`) |
| `version` | Human/semantic version | API version string | `"unversioned"` (a git branch has no semantic version) |
| `revision` | Immutable/semi-immutable pointer, **not** part of the uniqueness key | `NULL` (ClawHub has no VCS revision) | default-branch HEAD **commit SHA** |
| `artifact_hash` | Byte identity of the stored artifact (SHA-256 over sorted `filename+content`) | over ZIP entries + `_detail.json` | over the skill subtree + content-stable `_github.json` |

The `skills` uniqueness key is `(source, source_id, version, artifact_hash)`. `revision` is
tracked and indexed but deliberately **excluded** — byte identity is already captured by the
hash (see [data-model-and-storage.md](data-model-and-storage.md)).

## Update detection

`pipeline._needs_artifact_fetch(existing, discovered_revision, verify_existing)` decides whether
to (re)download:

- no existing row, or `--verify-existing`, or the existing row is a metadata-only stub
  (`artifact_hash IS NULL`), or the discovered `revision` differs from the stored one → **fetch**;
- otherwise (an artifact is already stored at the same revision) → **skip** (touch timestamps).

For ClawHub both revisions are `NULL`, so the comparison is `None == None` and behaviour is the
original version-keyed skip. For GitHub a changed HEAD SHA triggers a re-fetch; identical
re-fetched bytes refresh the existing row (revision advances, no duplicate), changed bytes insert
a new hash row (mutation evidence).

## ClawHub (`clawhub`) — [`sources/clawhub.py`](../sources/clawhub.py)

First-party production source using the public ClawHub REST API (no auth).

- **Discover:** cursor-paginate `/api/v1/skills` (sort=createdAt), fetch `/api/v1/skills/{slug}`
  detail per skill.
- **Fetch:** download the ZIP from `/api/v1/download`, extract all entries, append `_detail.json`
  (the raw API detail) for provenance.
- **Rate limits:** reads `ratelimit-remaining` / `ratelimit-reset` headers and pauses near the
  watermark. List/detail allow ~3000/window, download ~1200/window.
- **Retries:** `_fetch_with_retry()` wraps only list pagination (429/5xx/timeouts, 1-hour budget,
  exponential backoff, respects `Retry-After`). Per-skill errors are logged and skipped.
- **Mutation:** ClawHub has been observed serving different bytes under the same version string;
  each distinct snapshot becomes its own hash row.

## GitHub skills (`github-skills`) — [`sources/github.py`](../sources/github.py)

Crawls an allowlist of GitHub repos for files named **exactly** `SKILL.md`.

- **Discover:** for each seed repo, resolve the default-branch HEAD commit SHA, fetch the
  recursive git tree pinned to that SHA, and yield one stub per `SKILL.md` blob. No fuzzy
  heuristics yet (only the exact filename; not `.claude/skills/` etc.).
- **Fetch:** download the pinned commit tarball, extract just the skill's subtree as
  `{path: bytes}`, and add a `_github.json` provenance file. Only regular files (symlinks/
  hardlinks/devices skipped); path traversal rejected; **nothing is executed**. The repo tarball
  is cached per `(owner, repo, sha)` so a multi-skill repo downloads once.

#### Capture caps (host protection, not a content filter)

This is a **security-research corpus** — we want large and suspicious skills too — so the caps
are set generously and exist only to bound a decompression bomb / runaway artifact on an
un-sandboxed host, not to reject content. Two tiers:

| Dimension | Hard cap (reject) | Near-cap warning (still captured) |
|-----------|-------------------|------------------------------------|
| Compressed tarball | 500 MB | 250 MB |
| Per-file | 100 MB | 50 MB |
| Total uncompressed / skill | 250 MB | 100 MB |
| File count / skill | 10,000 | 5,000 |

- **Near-cap:** the skill is captured normally, but `capture_metadata()` flags it in
  `metadata` (`capture_status="near_limit"`, `capture_warnings`, and `observed_*` sizes).
- **Hard cap exceeded:** `fetch_artifact()` raises `CaptureLimitExceeded`; the pipeline does
  **not** store a partial artifact — it records a **stub** row (`artifact_uri`/`artifact_hash`
  NULL, `revision` set) with `metadata.capture_status="limit_exceeded"`, `limit_exceeded`,
  `observed_size`, and `capture_error`, so the skill's existence and the reason stay queryable.
  See [data-model-and-storage.md](data-model-and-storage.md#capture-status-finding-flagged-skills).
- A `limit_exceeded` stub has a NULL hash, so a later crawl re-attempts it (re-downloading that
  repo's tarball) — bounded and rare given the generous caps; raising the caps further or running
  `--verify-existing` re-captures such skills if they later fit.
- **`_github.json` is content-stable** — it deliberately omits the commit SHA. Embedding the
  repo HEAD would change every skill's hash on every repo commit (false "mutations"); the SHA
  lives in `skills.revision` instead. (Trade-off: because `_github.json` includes `skill_dir`,
  `artifact_hash` does not detect the *same* skill mirrored under a *different* dir — see the
  mirror note in the exploration doc.)
- **Auth:** uses `GITHUB_TOKEN` from the environment if present (60→5000 req/hr); not required.

### Seed file policy

The allowlist is [`config/github_skills_seeds.txt`](../config/github_skills_seeds.txt), loaded by
`load_seeds()`:

- one `owner/repo` per line; blank lines and everything after `#` are ignored (inline notes OK);
- **only uncommented lines are crawled**;
- hand-maintained only — **no** automated GitHub search or awesome-list expansion in scope;
- candidates were probed for existence + `SKILL.md` presence; repos with 0 `SKILL.md` and 404s
  are kept as commented entries for provenance;
- large/heavily-mirrored repos are enabled but flagged with warning comments (expect raw
  `SKILL.md` counts to exceed the number of *distinct* skills).

## Adding a new source

1. Create `sources/<name>.py` with a `BaseSource` subclass: set `source_name`, implement
   `discover()` and `fetch_artifact()`. Choose `source_id` / `version` / `revision` per the
   conventions above (a git-style source populates `revision`; a registry-style source may leave
   it `NULL`).
2. Register it in `cli.py` `_source_registry()` (one line).
3. Keep `fetch_artifact()` safe: read bytes only, never execute; enforce size/file-count caps and
   reject path traversal for any archive.
4. If it needs config (seeds, tokens), read from a file under `config/` and/or the environment —
   not hardcoded.
5. Add offline unit tests for the pure mapping/extraction logic (see `tests/test_github_*`).
6. Add a per-source systemd timer (see [operations.md](operations.md)); the templated service
   handles any source by instance name.
