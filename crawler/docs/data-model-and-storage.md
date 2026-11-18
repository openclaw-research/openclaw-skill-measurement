# Data Model & Storage

What the crawler persists: two PostgreSQL tables and an artifact store (S3 or local).
Schema lives in [`db/models.py`](../db/models.py); changes go through standalone
`scripts/migrate_*.py` (no Alembic).

## Tables

### `crawl_runs` — one row per crawl execution

| Column | Notes |
|--------|-------|
| `id` | BIGSERIAL PK |
| `source` | e.g. `clawhub`, `github-skills` |
| `started_at` / `finished_at` | timestamps |
| `status` | `running` → `success` / `partial_success` / `failed` (CHECK constraint `ck_crawl_runs_status`) |
| `stats` | JSONB summary (`skills_seen`, `skills_inserted`, `artifacts_downloaded`, `failures`, …) |
| `error_message` | set on hard failure |

Status thresholds (`pipeline._compute_run_status`): pagination stopped early or zero skills
attempted → `failed`; ≥ 5% of attempted skills failed → `partial_success`; otherwise `success`.

### `skills` — one row per collected skill snapshot

| Column | Notes |
|--------|-------|
| `id` | BIGSERIAL PK |
| `source`, `source_id`, `source_url` | identity within a source (see [sources.md](sources.md)) |
| `name`, `version` | human fields; `version` defaults to `'unversioned'` |
| `revision` | source-specific immutable pointer (git SHA, tag target, package digest); `NULL` for ClawHub. **Indexed, not in the uniqueness key.** |
| `description`, `author`, `license` | nullable metadata |
| `artifact_uri` | storage location of the artifact directory (authoritative — never reconstructed) |
| `artifact_hash` | SHA-256 byte identity of the artifact |
| `first_crawl_run_id`, `last_crawl_run_id` | FK → `crawl_runs.id` |
| `first_seen_at`, `last_seen_at` | lifecycle timestamps |
| `metadata` | JSONB for source-specific fields (Python attribute is `metadata_` to avoid shadowing SQLAlchemy's `Base.metadata`) |

Indexes: `source`, `name` (hash index — btree rejects oversized names and only equality is
needed), `artifact_hash`, `revision`, `last_seen_at`.

## Uniqueness model

```
UNIQUE (source, source_id, version, artifact_hash)   -- uq_skill_version
```

`artifact_hash` is **intentionally** part of the key: ClawHub (and mutable git branches) can
serve different bytes under the same version string, so each distinct snapshot is its own row —
this is the system's **mutation evidence**. Consequences:

- Re-seeing the exact same artifact → `upsert()` refreshes `last_seen_at` on that row.
- Seeing changed bytes for the same `(source, source_id, version)` → a **new row** is inserted;
  the older hash row is preserved (never deleted in the crawl path).
- `revision` is **not** in the key: two commits producing identical bytes are genuinely the same
  artifact (correct to dedup), and byte identity is already covered by `artifact_hash`.

`SkillRepository.touch()` updates `last_seen_at` across **all** hash variants of a
`(source, source_id, version)`. `update_artifact_content()` (which can delete stale duplicate
rows) is **backfill-only** and must never be used in the crawl path.

### Identity policy: what artifact_hash covers (decided 2026-07-10)

`artifact_hash` is the **full-fidelity byte identity of what the platform serves** — every
file in the downloaded artifact participates, including platform-generated files such as
ClawHub's `skill-card.md`. The only exclusions are **collector-injected** provenance
sidecars (`hash_excluded_files`, e.g. ClawHub's `_detail.json`): files WE add after
download, fully under our control, whose volatility we own.

Do **not** extend `hash_excluded_files` to platform-served files, however metadata-like
they look. Rationale:

- The platform can add/regenerate files at any time (`skill-card.md` was retrofitted onto
  ~93% of skills in mid-2026); an "author files only" hash would force a full corpus
  re-hash (~26h S3 walk + row collapse migration) every time that happens. Not scalable.
- Platform file churn is itself research signal (e.g. ClawScan risk-assessment rewrites);
  hashing it means each wave is captured as ordinary snapshot rows.
- Distinguishing author-content changes from platform-metadata churn is a **semantic**
  question, and semantics live in the **analyzer**: it already excludes `_detail.json` and
  `skill-card.md` from scanning (its `COLLECTOR_METADATA_FILES`), and metric-level
  distinctions (any-byte mutation vs author-content mutation) are analyzer-version
  concerns — cheap to roll out, no crawler data migration needed.

See `docs/misc/artifact-duplication-investigation.md` for the incident that produced this
policy (volatile `_detail.json` in the hash → 65k spurious rows) and the repair tooling
(`scripts/migrate_recompute_artifact_hash.py`) that exists if the definition ever must
change again.

### Capture status: finding flagged skills

Capture annotations live in the `metadata` JSONB (no schema change). The GitHub source sets
`metadata.capture_status` in two cases (see [sources.md](sources.md#capture-caps-host-protection-not-a-content-filter)):

- **`near_limit`** — skill captured normally but crossed a warning threshold; also carries
  `capture_warnings` (list) and `observed_bytes` / `observed_files` / `observed_max_file_bytes` /
  `observed_tarball_bytes`.
- **`limit_exceeded`** — a hard cap was hit; the row is a **stub** (`artifact_hash`/`artifact_uri`
  NULL) carrying `limit_exceeded` (which cap), `observed_size`, and `capture_error`. No partial
  artifact is stored.

Per-run counts also appear in `crawl_runs.stats` as `near_limit` and `capture_limited`.

```sql
-- Skills captured but flagged near a cap
SELECT source_id, revision,
       metadata->'capture_warnings'       AS warnings,
       metadata->>'observed_bytes'        AS bytes,
       metadata->>'observed_files'        AS files
FROM skills
WHERE source = 'github-skills'
  AND metadata->>'capture_status' = 'near_limit'
ORDER BY (metadata->>'observed_bytes')::bigint DESC;

-- Skills observed but NOT captured (hard cap exceeded) — stubs
SELECT source_id, revision,
       metadata->>'limit_exceeded' AS cap,
       metadata->>'observed_size'  AS observed,
       metadata->>'capture_error'  AS error
FROM skills
WHERE source = 'github-skills'
  AND metadata->>'capture_status' = 'limit_exceeded'
ORDER BY source_id;
```

### Why `revision` exists

`version` is a human label; `revision` is the immutable thing a snapshot was taken at. It lets
git-style sources (a) record exactly which commit produced an artifact and (b) drive cheap
update detection — re-crawls compare the discovered HEAD SHA against the stored `revision` and
skip the download when unchanged. Added via `scripts/migrate_add_revision.py` (idempotent).

## Artifact storage layout

New writes use a **hash-segmented, immutable** layout (identical for local and S3):

```
{source}/{skill_id}/{version}/{artifact_hash[:12]}/{filename}
```

The hash segment means a mutated artifact lands at a **new** path instead of overwriting the
previous bytes, so storage preserves every snapshot, matching the per-hash row model. The
pipeline passes the already-computed hash into `ArtifactStore.save_many()` (`save()`); the
segment length is `ARTIFACT_HASH_SEGMENT_LEN` (12). `artifact_uri` points at the artifact
**directory** and ends with a trailing slash, e.g.:

```
s3://<bucket>/github-skills/kepano/obsidian-skills//skills/defuddle/unversioned/aed2b66c6cd9/
```

(The `//` after the repo is the `github-skills` `source_id` separator — it appears verbatim in
the key and is harmless.)

### Coexistence of old and new paths

Artifacts collected before the hash-path cutover remain at the legacy **flat** layout
`{source}/{skill_id}/{version}/{filename}` (no hash segment). Old and new paths coexist:

- old ClawHub objects were **not** migrated and are **not** rewritten;
- every row stores its own full `artifact_uri`, so each resolves correctly regardless of layout;
- omitting `artifact_hash` from a store call reproduces the legacy layout and is used **only** by
  historical tooling such as `scripts/migrate_to_s3.py`.

Always read `artifact_uri`; never rebuild a path from `(source, source_id, version)`.

## S3 prefix conventions

- Active backend is S3 (`ARTIFACT_STORE=s3`); `LocalArtifactStore` mirrors the same layout under
  `ARTIFACT_ROOT`.
- Every object key is namespaced by its source: `clawhub/…`, `github-skills/…`. Because the
  prefixes are disjoint, different sources can crawl concurrently with **no key collisions**, and
  per-source cleanup is a single prefix delete.
- The artifact hash that segments the path is the same value stored in `skills.artifact_hash`, so
  an object's path can always be tied back to its DB row.
