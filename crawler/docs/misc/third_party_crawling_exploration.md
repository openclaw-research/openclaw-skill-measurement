# Third-Party Skill Crawling — Exploratory Design Note

**Status:** exploratory design proposal. No production crawler implemented; no DB schema
changes applied. This note is grounded in the current codebase as of branch `main`.

---

## 1. Executive summary

The repository already has a clean, layered design (`sources/` → `pipeline.py` → `storage/`
→ `db/`) that is **80% source-agnostic**. Adding third-party sources is feasible without a
rewrite and without abandoning the synchronous, single-node model. The work needed falls
into three buckets:

1. **Small refactors** to close ClawHub-specific leaks: promote `fetch_artifact()` into the
   `BaseSource` ABC, make `run_backfill()` stop calling ClawHub private methods, and replace
   the duplicated `source_map` dicts in `cli.py` with one registry. These are low-risk and
   unblock everything else.
2. **One additive schema change**: a `revision` column (git commit SHA / tag / branch@sha)
   distinct from the human `version`. The current `(source, source_id, version,
   artifact_hash)` uniqueness model survives multi-source largely intact; `artifact_hash`
   already gives us cross-source dedup and mutation evidence.
3. **An S3 layout change**: include `artifact_hash` (or revision) in the key so mutated
   third-party bytes are not silently overwritten. For mutable git branches, overwriting is
   no longer acceptable.

**Recommended operational model:** one CLI with per-source invocation (`crawl --source X`),
**separate systemd timers per source**, per-source lock files, and one `crawl_runs` row per
source per execution. Do **not** collapse all sources into one global crawl — a GitHub
rate-limit stall must not block the ClawHub crawl.

**Recommended first source:** GitHub skill repositories (official + curated seed list),
fetched as immutable commit tarballs via `codeload`. It exercises every hard case (no
version string, commit SHAs, mutable branches, multiple skills per repo) and most candidate
sources reduce to "a GitHub repo," so the GitHub source is high-leverage.

> **Note (resolved):** an earlier `sample-scripts/github_skill_crawler.py` contained a
> hardcoded GitHub Personal Access Token. The script has since been removed and the token
> handled. The remaining open item is purely forward-looking: how the GitHub source's token
> should be provisioned (env `GITHUB_TOKEN`) — see Open Questions.

---

## 2. Current architecture assessment

### What is genuinely source-agnostic (keep as-is)

| Component | Why it generalizes |
|---|---|
| [`storage/base.py`](../storage/base.py), [`local.py`](../storage/local.py), [`s3.py`](../storage/s3.py) | `ArtifactStore` ABC takes `(source, skill_id, version, files)` — no ClawHub assumptions. Local store already has a zip-slip guard. |
| [`db/models.py`](../db/models.py) | `source`/`source_id`/`version` are generic; `metadata_` JSONB absorbs source-specific fields; `idx_skills_artifact_hash` already enables cross-source dedup. |
| [`sources/base.py`](../sources/base.py) `SkillMetadata` | Already supports multi-file `artifacts` dict, `extra` JSONB, and `raw_detail` pass-through. Designed for more than ClawHub. |
| `run_crawl()` core loop in [`pipeline.py`](../pipeline.py) | Discovery → hash → dedup-by-hash → upsert is fully generic; only touches the source via `discover()` / `fetch_artifact()` / `source_name`. |

### What still assumes ClawHub (must change to add sources)

| Location | ClawHub coupling | Impact |
|---|---|---|
| [`pipeline.py:252-340`](../pipeline.py#L252) `run_backfill()` | Calls **private** `source._fetch_detail()`, `source._fetch_artifact_zip()`, `source._extract_zip()` and injects `_detail.json`. | Backfill cannot run for any non-ClawHub source. |
| [`sources/base.py:50`](../sources/base.py#L50) `BaseSource` | `fetch_artifact()` is **not declared** on the ABC — it exists only on `ClawHubSource`. `run_crawl()` calls it via duck typing. | New sources have no contract telling them to implement it. |
| [`cli.py:43`](../cli.py#L43) & [`cli.py:75`](../cli.py#L75) | `source_map = {"clawhub": ClawHubSource}` is **duplicated** in `cmd_crawl` and `cmd_backfill`. | Every new source = edit two dicts; constructor kwargs (`page_size`, etc.) are ClawHub-shaped. |
| [`pipeline.py:211`](../pipeline.py#L211) | `getattr(source, "pagination_stopped_early", False)` — informal attribute convention. | Works, but undocumented contract; should be a declared ABC attribute. |
| `deploy/openclaw-crawler.service` (since replaced by templated per-source units) | Hardcodes `crawl --source clawhub` and one lock file. | One timer cannot isolate per-source failures or intervals. |
| Hashing logic | Duplicated verbatim in `run_crawl()` ([L141-145](../pipeline.py#L141)) and `run_backfill()` ([L300-304](../pipeline.py#L300)). | Drift risk; should be one helper. |

### Duplication / awkwardness that multi-source will amplify

- **Two source registries** (`cli.py`) → drift. Collapse to one `SOURCE_REGISTRY`.
- **Backfill reaching into private methods** → the cleanest fix is to have `run_backfill()`
  call the public `fetch_artifact()` (it already does the identical work, including
  `_detail.json` injection), removing all ClawHub coupling from the pipeline.
- **Per-source constructor shapes** — `page_size`/`delay`/`max_skills` are ClawHub-list
  concepts. GitHub will want `token`, `repo_seeds`, `topics`. The CLI should pass a generic
  `--limit` / `--delay` and let each source read its own config from env.

**Bottom line:** the seams are in the right places. The leaks are concentrated in
`run_backfill()` and `cli.py`, both fixable in a small PR before any new source lands.

---

## 3. Candidate source inventory

Legend — **Fit**: how well it maps to the current `skills` model today. **Complexity**: rough
crawl effort.

| # | Source | Location | Artifact type | Access mechanism | Versioning | Bytes mutable under same version? | Legal/ops | Complexity | Fit to current model |
|---|---|---|---|---|---|---|---|---|---|
| 1 | **ClawHub** (first-party, existing) | `clawhub.ai/api/v1` | ZIP (SKILL.md + _meta.json + files) | REST API | Explicit `version` string | Yes (observed — the reason `artifact_hash` is in the uniqueness key) | Public API, documented rate limits | Done | Native |
| 2 | **GitHub — official/org skill monorepos** | e.g. `github.com/openclaw/skills` | Skill folders (`SKILL.md` + assets) inside a repo | GitHub REST/GraphQL for discovery + `codeload` tarball per commit | Git **tags** + **commit SHA**; branch HEAD mutable | Yes — branch HEAD moves; pin to SHA | Public repos; GitHub API 5000 req/hr (auth), tarball cheap; ToS allows | Medium | Good w/ `revision` col + source_id convention |
| 3 | **GitHub — community/individual skill repos** | The hand-maintained allowlist [`config/github_skills_seeds.txt`](../config/github_skills_seeds.txt) (e.g. `alirezarezvani/claude-skills`, `kepano/obsidian-skills`; 21 repos verified to contain `SKILL.md`) | Heterogeneous: `SKILL.md`, `.claude/skills/`, loose markdown | Same as #2 | Mostly **absent** (branch HEAD only); some tagged | Yes (branch HEAD) | Public; same as #2 | Medium-High (layout heuristics vary per repo) | Good (same as #2) |
| 4 | **GitHub — curated "awesome" indexes** | `VoltAgent/awesome-openclaw-skills`, `libukai/awesome-agent-skills`, `skillmatic-ai/awesome-agent-skills` | **README link lists** — pointers, not artifacts | Fetch README, parse markdown links → expand into #2/#3 repo seeds | N/A (index) | N/A | Public | Low (parsing) but indirection | Seed source, not stored as skills |
| 5 | **GitHub code/topic search** | `api.github.com/search/code?q=filename:SKILL.md` / `topic:openclaw` | Discovery of #2/#3 repos | GitHub Search API (stricter limits: 30 req/min) | N/A (discovery) | N/A | Public; search rate limits tight | Low-Medium | Discovery feeder |
| 6 | **MCP server directories / marketplaces** (adjacent) | MCP registries / marketplace sites | MCP **server** (package + manifest), not a skill folder | API where available, else GitHub repo behind the listing | Package/semver or git | Yes (package re-publish) | Varies per registry; check ToS/robots | Medium-High | Poor today — different artifact semantics; would want its own normalization |
| 7 | **Package registries (npm/PyPI)** | npmjs.org / pypi.org | Generic packages | Registry JSON API | Explicit semver (immutable per published version) | No (versions immutable; yanks aside) | Public APIs, generous | Low | Poor unless a package *is* a packaged skill — skip until a concrete skill-packaging convention exists |

**Curation:** start with **#2 + #4 + #5** (GitHub as one source with a seed list expanded by
awesome-indexes and code search). #1 stays as-is. Treat **#6 (MCP)** as a separate, later
adjacent-ecosystem source with its own normalizer — do not force it into the skill model now.
**#7** is out of scope until a real artifact type appears.

---

## 4. Source-by-source crawling feasibility

### ClawHub (#1) — done
Already crawled. Note for multi-source: some third-party sources **mirror ClawHub skills**, so
their artifact bytes may hash-equal a ClawHub row. The existing `idx_skills_artifact_hash`
lets us detect mirrors via a hash join (see §7 reproducibility / §6 mirrors).

### GitHub repos (#2/#3) — recommended first new source
- **Discovery:** seed repo list ([`config/github_skills_seeds.txt`](../config/github_skills_seeds.txt) + awesome-index expansion + code search) → for each repo,
  resolve default branch HEAD **commit SHA**, then enumerate skills by locating `SKILL.md`
  files (and known dirs: `.claude/skills/`, `.agents/skills/`, `.github/skills/`).
- **Artifact fetch:** download the **commit tarball** from `codeload.github.com/{owner}/{repo}/tar.gz/{sha}`
  (one request, immutable, no per-file API spend), extract only the skill subtree, store files
  verbatim. Pin to the SHA so the artifact is reproducible.
- **One repo → many skills:** a monorepo yields N `SkillMetadata`, each with a distinct
  `source_id` encoding the path (see §5). This is the main new shape vs ClawHub.
- **Versioning:** `version` = git tag if the skill subtree is tagged, else `"unversioned"`;
  `revision` = commit SHA (always). Mutable branch handled by re-resolving HEAD each crawl.
- **Auth/limits:** authenticated API = 5000 req/hr; tarball downloads are not metered like the
  API. Search API is the tight constraint (30 req/min) — use sparingly, cache seeds.
- **Guardrails:** never execute repo contents; cap tarball size and uncompressed size (zip/tar
  bomb), file count, and per-file size; reuse the existing zip-slip pattern for tar extraction.

### Awesome indexes (#4) / code search (#5) — discovery feeders
Parse-only. Produce/refresh the repo seed list. Store the seed list in the repo (versioned
config) rather than the DB; they are inputs, not skills.

### MCP directories (#6) — adjacent, later
Different artifact (a server, often itself a GitHub repo or npm package). Feasible but wants a
distinct normalizer and possibly its own `source` value(s). Defer; revisit once the GitHub
source is stable.

---

## 5. DB model assessment

### Does `(source, source_id, version, artifact_hash)` still work? — Mostly yes.

The uniqueness key holds up well because `artifact_hash` already does the heavy lifting:
distinct bytes = distinct row = mutation evidence, across any source. The pain points are about
**identity** (`source_id`) and **revision semantics** (`version`), not uniqueness.

| Hard case | Current behavior | Verdict / recommendation |
|---|---|---|
| **No version string** | Defaults to `"unversioned"`; mutations still distinguished by hash. | OK. Add `revision` to carry the real pointer (SHA). |
| **Git commit instead of version** | No column for it; would land in `metadata_`. | **Add a first-class `revision` column** for queryability. |
| **Mutable branch** | Each changed HEAD → new hash row under same `version` (acceptable — mutation evidence). | OK; pin `revision`=SHA so each snapshot is identifiable, not just hash-distinct. |
| **Multiple skills per repo** | `source_id` must be unique per skill. | Encode as `owner/repo//<path-to-skill-dir>` (double-slash separator). No schema change; convention only. Document it. |
| **Multiple artifacts per skill** | `artifacts` dict already supports many files under one skill; hashed together. | OK. |
| **No clean author** | `author` is nullable. | OK; fall back to repo owner. |
| **Metadata that doesn't map** | `metadata_` JSONB. | OK; keep raw response too (§7). |

### Recommendation (ranked)

1. **✅ Implemented — nullable `revision TEXT` column** on `skills` (commit SHA / tag /
   branch@sha / package digest), with `idx_skills_revision`. It is **not** in the unique
   constraint — `artifact_hash` already disambiguates bytes, and two commits producing
   identical bytes are genuinely the same artifact (correct to dedup). `SkillMetadata` carries
   `revision`; the crawl `upsert()` persists it. ClawHub sets `revision = None` (it exposes a
   semantic `version` but no VCS-style revision; duplicating `version` would muddy the column).
   Applied via standalone `scripts/migrate_add_revision.py` (Alembic deferred — see §10).
2. **Keep the single `skills` table as canonical.** Do **not** split discovered/normalized/
   artifacts into separate tables — that is distributed-system-shaped complexity unjustified
   for a single-node research crawler. The current row already *is* the normalized record;
   the raw response lives as an artifact file + `metadata_`.
3. **Do not add a `sources` table yet.** A handful of sources is better served by an in-code
   `SOURCE_REGISTRY` (also fixes the CLI duplication). Revisit only if per-source config grows
   beyond a few fields or needs runtime mutation.
4. **`crawl_runs` is already per-source** (`source` column). Keep one run row per source per
   execution; no umbrella-run table.
5. **`source_id` convention for nested skills:** standardize `owner/repo//path` and document it
   in `CLAUDE.md` so `find_by_version()` / `touch()` keys stay stable.

### Migration plan — ✅ done (standalone style)

- **Decision:** standalone migration, not Alembic. For a single additive nullable column,
  scaffolding Alembic (env.py + a baseline reproducing the hand-evolved schema) is
  disproportionate churn; the repo already has a clean idempotent standalone convention.
  Alembic stays deferred to the first genuinely multi-step schema evolution (see §10).
- **`scripts/migrate_add_revision.py`:** `ALTER TABLE skills ADD COLUMN IF NOT EXISTS revision
  TEXT`; `CREATE INDEX IF NOT EXISTS idx_skills_revision`. Idempotent, additive, zero downtime.
- **Existing ClawHub rows keep `revision = NULL`** (no backfill, no full-table rewrite):
  ClawHub has no VCS revision, so NULL is the honest value. Backfilling `revision = version`
  was rejected — it would duplicate `version` and blur the column's meaning for git sources.
- No constraint changes required for the GitHub source.

---

## 6. S3 / artifact storage assessment

> **Status: implemented.** The hash-segmented layout below has shipped. `ArtifactStore.save()`
> / `save_many()` take an optional `artifact_hash`; the pipeline passes the hash it already
> computes, so all crawl and backfill writes now use
> `{source}/{skill_id}/{version}/{artifact_hash[:12]}/{filename}`. Omitting the hash yields the
> legacy flat layout, used only by `scripts/migrate_to_s3.py` so it keeps relocating historical
> artifacts to the keys their DB rows already reference. Old flat paths and new hash paths
> coexist; no old objects were migrated and no existing `artifact_uri` rows were rewritten.

### Current layout is insufficient for multi-source

`{source}/{skill_id}/{version}/{filename}` ([`storage/s3.py:34`](../storage/s3.py#L34)) has two
problems for third-party crawling:

1. **Overwrite on mutation.** A mutated artifact at the same `(source, skill_id, version)`
   **overwrites** prior bytes; only the DB retains the old hash. For ClawHub this was an
   accepted trade-off. For **mutable git branches** (`version="unversioned"`), *every* changed
   crawl overwrites the previous snapshot — we would keep DB hash rows pointing at S3 paths
   that no longer contain those bytes. That breaks reproducibility of historical snapshots.
2. **`skill_id` with slashes.** GitHub `source_id = owner/repo//path` contains `/`, which is
   fine for S3 keys but must be deliberately structured, and the local store would create
   nested dirs (acceptable, already path-safe via the zip-slip guard).

### Recommendation — include `artifact_hash` in the key

Adopt: `{source}/{safe_skill_id}/{version_or_revision}/{artifact_hash[:12]}/{filename}`

- **Decision: yes, add `artifact_hash` to the path.** Each distinct snapshot becomes immutable
  in S3, matching the DB's "each hash is its own row" model. Storage cost is trivial for
  text/markdown skills; the win is true reproducibility for the measurement paper.
- **Cutover policy — hash paths apply to all sources after the cutover, not just new ones.**
  Once the hash-segmented layout ships, **every new artifact write uses it**, including future
  ClawHub crawl uploads and future ClawHub `--verify-existing` mutations. The policy is *not*
  "new sources get hash paths, ClawHub keeps flat paths forever" — that would leave ClawHub
  mutations overwriting bytes indefinitely, which is the exact problem we're fixing. Going
  forward, all sources write immutable hash paths.
- **Existing old ClawHub objects stay as-is.** Pre-cutover S3 objects and their `artifact_uri`
  values remain valid historical records and are **not migrated blindly**. A migration/rewrite
  of old objects should only happen later as part of a deliberate integrity audit (verify
  stored bytes still match the recorded hash, then re-key), never as a blind bulk rewrite.
- `artifact_uri` continues to point at the directory with a trailing slash, now one level
  deeper (`.../{hash12}/`). DB already stores the full URI per row, so old rows keep pointing
  at old flat paths and new rows point at hash paths — both resolve correctly.

---

## 7. Scheduling and operation recommendation

### Topology: per-source timers, shared CLI, per-source locks

- **One CLI, per-source invocation.** Keep `crawl --source <name>`; add `--all` as a manual
  convenience that loops sources sequentially (each still its own `crawl_runs` row).
- **Separate systemd timer + service per source.** A GitHub rate-limit stall or a multi-hour
  GitHub crawl must not delay or block the ClawHub daily crawl. Different sources also want
  different intervals (ClawHub daily; GitHub maybe weekly).
- **Per-source lock files:** `flock -n /tmp/openclaw-crawler-<source>.lock` so two sources can
  run concurrently but a single source never overlaps itself.
- **`crawl_runs`:** one row per source per execution (the `source` column already supports
  this). Do not model a multi-source umbrella run — it complicates status semantics for no
  analytical benefit. `--all` simply produces N rows.

### CLI design

```
crawl     --source clawhub | github | ...   [--limit N] [--delay S] [--dry-run] [--verify-existing] [--metadata-only]
crawl     --all                              # sequential, one run row per source
backfill  --source <name>                    [--force] [--limit N] [--dry-run]
verify-existing == crawl --source X --verify-existing   # keep as the existing flag, per-source
```

- `--verify-existing` stays per-source (re-download known revisions, insert new hash row on
  change). For GitHub, "verify" = re-resolve branch HEAD and re-fetch if SHA changed.
- Add `--metadata-only` (discover + persist stub, skip artifact download) for legally-sensitive
  sources or fast inventory passes. This is distinct from `--dry-run` (which writes nothing).

### Failure isolation & observability

- Per-source runs already capture `stats.error_details` and downgrade to `partial_success`
  at ≥5% per-skill failure — keep this.
- Add per-source `RandomizedDelaySec` and source-appropriate `OnUnitActiveSec`.
- Journal remains authoritative; per-source log filenames already include the source
  ([`cli.py:189`](../cli.py#L189)).

---

## 8. Versioning / update-detection recommendation

### Strategy matrix

| Source revision style | `version` (human) | `revision` (immutable pointer) | Update detection |
|---|---|---|---|
| Explicit version (ClawHub) | API version string | = version (or NULL) | Re-fetch on `--verify-existing`; new bytes → new hash row |
| Git tag | tag name | tag's commit SHA | New tag → new revision |
| Git commit SHA | `"unversioned"` | the SHA | New SHA → new revision/row |
| Branch HEAD (mutable) | branch name (e.g. `main`) | resolved HEAD SHA at crawl time | Re-resolve HEAD; unchanged SHA → `touch()`; changed → fetch, new row |
| Package version | semver | registry digest | Immutable per version; only new versions add rows |
| Content-hash only | `"unversioned"` | NULL | `artifact_hash` is the sole identity |

### Normalized storage model

Per snapshot store: `version`, **`revision`** (new column), `artifact_hash`, `first_seen_at`,
`last_seen_at`, `first/last_crawl_run_id`. **Mutation evidence** = multiple rows sharing
`(source, source_id, version)` (or `revision`) with different `artifact_hash` — exactly today's
model, extended by `revision`.

### Re-crawl / verify behavior

- **Cheap pre-check first.** For git sources, resolve HEAD SHA (1 API call) *before*
  downloading the tarball; if the SHA matches the latest stored `revision`, `touch()` and skip
  the download. This is the GitHub analogue of ClawHub's "known version → touch, skip".
- `--verify-existing` forces a re-download to detect byte mutation even when the visible
  pointer is unchanged (matches current ClawHub semantics).

### Third-party mirrors of ClawHub

Some third-party repos simply copy ClawHub skills. Handle via **content identity**, not source:
- After hashing, if `artifact_hash` already exists under `source='clawhub'`, record the
  relationship — e.g. `metadata_.mirror_of = {"source": "clawhub", "source_id": ...}` — so the
  dataset can distinguish *original* from *mirror* without deleting either row.
- This needs no new mechanism: the existing `idx_skills_artifact_hash` makes the lookup a
  single indexed query during the crawl. Document mirrors as first-class in the dataset so
  downstream measurement doesn't double-count copied skills.

---

## 9. Safety & research-quality concerns

Crawling arbitrary third-party repos means ingesting **untrusted code and prompt artifacts**.
Guardrails (most are cheap, several already exist):

| Guardrail | Status / action |
|---|---|
| **Never execute downloaded code** | Already true (we only read bytes). Make it an explicit invariant in `CLAUDE.md`; no `import`, `exec`, `subprocess`, or archive auto-run, ever. |
| **Archive traversal (zip/tar-slip)** | Local store guards it ([`storage/local.py:52`](../storage/local.py#L52)). Add the same guard to GitHub **tar** extraction. |
| **Decompression bomb** | Add caps: max compressed size, max **uncompressed** total, max file count, max per-file size. Abort + record failure if exceeded. |
| **Download timeout / size cap** | Set request timeouts (ClawHub already uses 15–30s) and a hard byte ceiling on artifact downloads. |
| **MIME / content checks** | Trust bytes, not extensions. Optionally record detected content type per file in `metadata_`; do not block on it (research wants the weird files too). |
| **Metadata-only mode** | Add `--metadata-only` for sources where storing full artifacts is legally sensitive. |
| **Symlink handling** | Skip or neutralize symlink entries in archives (don't follow them out of the extraction root). |

### Reproducibility / dataset quality (for the measurement paper)

Store, per snapshot:
- **Raw provenance:** the raw API/manifest response (ClawHub already saves `_detail.json`; do
  the same for GitHub — repo metadata, resolved SHA, tag, default branch).
- **Exact source coordinates:** canonical URL, `owner/repo`, path, resolved commit SHA, and
  HTTP `ETag`/`Last-Modified` where available.
- **Crawl linkage:** `first/last_crawl_run_id` (already present) + fetch timestamp.
- **License** (already a column) — important for redistribution analysis.
- **Immutable bytes in S3** (per §6, hash in path) so a paper can be re-run against the exact
  artifact set, and mutation history is fully recoverable.

This makes the corpus suitable for downstream **static analysis** (we keep raw files, never
execute) and **longitudinal mutation measurement** (every distinct snapshot is preserved in
both DB and S3).

---

## 10. Migration / refactor recommendations (priority order)

**PR 1 — refactor only (first; do before any new source). Deliberately boring and mechanical:
no schema changes, no migration-strategy decision, no Alembic.**
1. Promote `fetch_artifact()` and a `pagination_stopped_early` attribute into the
   [`BaseSource`](../sources/base.py) ABC (declared contract, default `False`).
2. Make [`run_backfill()`](../pipeline.py#L252) call the public `fetch_artifact()` instead of
   ClawHub privates — removes all ClawHub coupling from `pipeline.py`.
3. Extract the duplicated artifact-hashing into one helper used by both `run_crawl()` and
   `run_backfill()`.
4. Replace the two `source_map` dicts in [`cli.py`](../cli.py) with a single `SOURCE_REGISTRY`;
   let each source read its own config from env so the CLI stays generic.

ClawHub crawl/backfill behavior must be preserved byte-for-byte by PR 1. The Alembic
question (below) is explicitly **out of scope** for PR 1 and stays a future decision.

**Schema (separate PR, only when approved):**
5. Add `revision` column + index (§5 migration plan).

**Storage (separate PR): ✅ done.**
6. Hash-segmented layout implemented and cut over for all sources (§6): every new write —
   including ClawHub crawl and verify-existing — uses hash paths. Old ClawHub objects/URIs are
   left as historical records, not migrated blindly.

**Deploy:**
7. Split the single systemd unit into per-source service+timer with per-source lock files (§7).

### Alembic decision (revisiting the "No Alembic" constraint)

`alembic==1.18.4` is **already in [`requirements.txt`](../requirements.txt)** and the models
note they are "Alembic-compatible" — the dependency is vendored but unconfigured.

**This is a future schema-migration decision, explicitly deferred — it is not part of PR 1
(the no-schema refactor).** When the first schema change (the `revision` column) is actually
approved, the recommendation is to **adopt Alembic at that point**, with a baseline migration
capturing the current schema. Rationale:
- Multi-source will produce a *sequence* of coordinated schema changes (revision column,
  possibly mirror tracking, future MCP fields). Standalone scripts have no ordering or
  applied-state tracking, which gets risky with more than one contributor and more than one
  environment.
- The dependency is already present, so this isn't new weight.
- Keep it light: one `alembic/` dir, autogenerate off the existing models, baseline = current
  schema, then `revision` as the first real migration. Existing `scripts/migrate_*.py` stay as
  historical record; no need to retro-convert them.

This is a judgment call and a **decision for the maintainer** — if multi-source is expected to
need only the single `revision` change, one more standalone script is also defensible. Flagged
in Open Questions.

---

## 11. Open questions

1. **GitHub auth (token provisioning).** The earlier hardcoded-PAT issue is resolved. The
   remaining question is forward-looking: how is the crawler's GitHub token provisioned (env
   `GITHUB_TOKEN`)? One token's 5000 req/hr likely suffices given tarball-based fetching.
2. **Skill-discovery heuristic inside repos.** Canonical marker set? (`SKILL.md` +
   `.claude/skills/` + `.agents/skills/` + `.github/skills/`?) Repos in the seed list use
   varied layouts — we need an agreed detection rule and how to handle false positives.
3. **Mirror policy.** Keep mirrors as separate rows tagged `mirror_of`, or suppress them?
   (Recommendation: keep + tag, for honest provenance.) **Finding from the first expanded crawl
   (run 45, 5,066 rows):** `artifact_hash` does **not** catch cross-location mirrors — repeated
   `artifact_hash` count was **0**, because each artifact's `_github.json` embeds `skill_dir`,
   so the same skill copied under a different dir hashes differently. Mirroring is instead
   visible by skill-dir basename: 4,125 distinct names, 555 repeated, ~1,496 rows sharing a
   name. A real de-dup pass would need a content hash that excludes `_github.json` (or compares
   only the skill's own files). Deferred.
4. **S3 retention/cost.** Preserving every mutated snapshot grows storage. For text skills this
   is negligible, but confirm there's no binary-heavy source before committing.
5. **Alembic now vs later** (§10).
6. **MCP ecosystem scope.** In-scope for this paper, or explicitly out? Determines whether we
   design the adjacent normalizer now.
7. **Awesome-list trust.** Curated lists vary in quality; do we crawl everything they link or
   apply a star/activity threshold?
8. **Legal/ToS per source.** GitHub public API is clearly fine; confirm no per-repo license
   prohibits redistribution of stored artifacts (license column helps triage).

---

## 12. Concrete next steps

1. ✅ **Done — refactor PR (no schema, no Alembic):** items 1–4 in §10 — `fetch_artifact()`
   /`pagination_stopped_early` on the ABC, de-coupled `run_backfill()`, shared hashing helper,
   single source registry. ClawHub behavior preserved.
2. ✅ **Done — `revision` column** (§5), applied via standalone migration; Alembic deferred.
   Hash-segmented storage cutover also shipped (§6).
3. ✅ **Done — GitHub discovery:** `sources/github.py` (`GitHubSkillsSource`, registered as
   `github-skills`). `discover()` walks the seed allowlist
   [`config/github_skills_seeds.txt`](../config/github_skills_seeds.txt), resolves each repo's
   default-branch HEAD commit SHA into `revision`, and yields one stub per exact `SKILL.md` with
   `source_id = owner/repo//<dir>`. Uses `GITHUB_TOKEN` if set, not required. Validated live
   against `alirezarezvani/claude-skills` (763 raw `SKILL.md`, 420 distinct dirs) and
   `kepano/obsidian-skills` (5); the enabled default seed set is kept small/clean.
4. ✅ **Done — artifact fetch + metadata-only:** `fetch_artifact()` downloads the pinned commit
   tarball (SHA carried via `raw_detail`), extracts the skill subtree as `{path: bytes}` under
   hard caps (compressed-tarball / per-file / total-uncompressed / file-count), skips symlinks,
   rejects path traversal, never executes anything, and adds a `_github.json` provenance file.
   Stored via the existing hash-segmented layout. New `crawl --metadata-only` persists stubs
   (no fetch/store). Validated live (small `--limit` full crawl + metadata-only) against the
   enabled seed set.
5. ✅ **Done — revision-aware update detection** (`pipeline._needs_artifact_fetch`): a re-crawl
   skips the download only when an artifact is already stored at the same `revision`; a changed
   HEAD SHA (or a metadata-only stub) triggers a re-fetch. To make this meaningful the GitHub
   `_github.json` provenance is **content-stable** (no commit SHA — that would make every repo
   commit hash as a skill mutation); the SHA lives in `skills.revision`. Identical re-fetched
   bytes update the existing row (revision advances, no duplicate); changed bytes insert a new
   hash row (mutation evidence). ClawHub behavior (revision `NULL`) is unchanged. Validated
   live: unchanged HEAD → skip; simulated SHA change with unchanged content → update-in-place;
   with changed content → new row.
6. ✅ **Done — per-source scheduling + expanded coverage (spike → initial production):**
   templated `openclaw-crawler@.service` with per-source timers (`@clawhub` every 48h preserved,
   `@github-skills` daily) and per-source locks (`/tmp/openclaw-crawler-<source>.lock`) so the two
   sources run concurrently but never overlap themselves. The GitHub seed allowlist
   ([`config/github_skills_seeds.txt`](../config/github_skills_seeds.txt)) expanded from the 5-repo
   spike set to all 24 verified repos (large/mirrored ones flagged). The github-skills timer is
   left **disabled** pending a manual expanded validation crawl + approval.

> Note: GitHub has moved from read-only spike to an initial allowlist-based production crawl.
> Still no schema change, no Alembic, no automated GitHub search, and downloaded code is never
> executed. De-duplication of mirrored skills across agent dirs remains a deferred follow-up.
