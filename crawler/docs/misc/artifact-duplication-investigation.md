# Artifact Duplication Investigation (Analysis run #70)

**Date:** 2026-07-05 · **Status:** REPAIR COMPLETE 2026-07-09. DB migrated
(154,209 → 93,932 hashable rows; 60,277 collapsed duplicates preserved in
`skills_hash_migration_audit`), S3 orphans deleted (59,836 hash-dir prefixes /
553,245 objects / 3.93 GB, manifest-gated with per-prefix live re-validation),
recurrence proven dead (60/60 sampled old skills re-fetch to matching hashes;
live verify crawl run 60 inserted only genuinely new skills + 1 real mutation),
verify timer re-enabled (next: 2026-07-12 12:06 UTC). Full-DB dumps pre- and
post-migration under `/home/ubuntu/backups/`. Remaining: merge both PRs (the
deployed crawler checkout runs the fix branch; the analyzer fix takes effect
after its PR merges), then re-run production analysis to replace run #70.

## 1. Observed issue

Production Analysis run #70 (analyzer repo, started 2026-07-04 21:06) selected a corpus
of 152,903 entries, up from 86,341 in run #68 (2026-06-29). Many materialized artifacts
contained the same skill content twice — once at the artifact root (`SKILL.md`,
`_meta.json`, `scripts/…`) and once under a 12-hex-character subdirectory
(e.g. `8d8ecf164e6d/SKILL.md`). The analyzer scans every file it finds, so indicator
counts were doubled for affected skills (~75.6% of ClawHub skill-versions), making run
#70's corpus-level distribution unreliable.

## 2. Code paths inspected

Crawler (this repo):
- `sources/clawhub.py` — `fetch_artifact()` / `_extract_zip()`: ZIP entries preserved at
  their original paths; the collector appends `_detail.json` (raw detail API response).
- `pipeline.py` — `compute_artifact_hash()` (SHA-256 over sorted name+content pairs),
  `run_crawl()` (hash → dedup check → `save_many` → `upsert`), `_needs_artifact_fetch()`
  (verify-existing forces re-fetch), `run_backfill()`.
- `storage/s3.py` / `storage/base.py` — key layouts: legacy flat
  `{source}/{skill_id}/{version}/{file}` vs hash-segmented
  `{source}/{skill_id}/{version}/{hash12}/{file}` (cutover commit `3da3be3`, 2026-06-25).
  `S3ArtifactStore` has **no** list/read path — the crawler never re-reads stored artifacts.
- `scripts/migrate_to_s3.py` — uploaded pre-cutover artifacts flat (no hash segment),
  which is why legacy rows carry flat `artifact_uri` values.

Analyzer (`openclaw-skill-analysis`):
- `artifacts/s3_loader.py` — `download_prefix()`: recursive `list_objects_v2` on the
  row's `artifact_uri` with no delimiter and (pre-fix) no path scoping.
- `pipeline/static_pipeline.py` — corpus = all `skills` rows with non-null
  `artifact_uri` (`select_candidate_skills`); `selected` counts rows.
- `analyzers/static/inventory.py` — `scan_tree()` walks the materialized tree with
  `rglob("*")`, no depth limit.

## 3. Hypotheses considered

| Hypothesis | Verdict | Evidence |
|---|---|---|
| Hex dir is part of the upstream ZIP | **No** | `_extract_zip` preserves ZIP paths verbatim; S3 listings show the hex dir only as a *sibling snapshot prefix*, with its own timestamps (2026-07-02) weeks after the flat objects (2026-05-26) |
| Crawler packaging adds the hex dir | **No** | No write path composes nested hash dirs; `save_many` writes each file exactly once, flat or under one `{hash12}/` segment |
| Hash-path S3 logic duplicates objects | **No (by itself)** | New snapshots land at *new* keys; nothing is written twice. But a legacy **flat URI is a string prefix** of every sibling hash-segmented key — the trap consumed below |
| Verify/recrawl logic creates duplicates | **Yes (cause A)** | Verify crawl run 52 (2026-07-02 12:07 → 07-04 17:17, exactly the verify timer schedule) inserted **65,185** new rows, updated only 227 |
| Analyzer corpus prep duplicates content | **Yes (cause B)** | Caught live in run #70 temp dirs: root files + `{hash12}/` copies materialized together for legacy-flat rows |

## 4. Root causes (two, compounding)

**A — volatile `_detail.json` was part of `artifact_hash`.** `fetch_artifact()` injects
the full detail API response; the hash covered every file. `_detail.json` embeds
volatile counters — verified by diffing skill 1167's two S3 copies: `downloads` 94→314,
`installs`, `updatedAt` changed, while `SKILL.md` is sha256-identical. So the
2026-07-02 verify crawl computed a "new" hash for ~99.7% of skills and inserted a
near-total duplicate snapshot set, each with a full S3 copy under
`…/{version}/{hash12}/`. ClawHub `skills` grew from 83,127 distinct
`(source_id, version)` to 148,038 rows — the run #68→#70 corpus growth
(86,341 → 152,903 ≈ 148,038 clawhub + 5,215 github-skills + 3 openclaw).

**B — legacy flat `artifact_uri` is a string prefix of hash-segmented keys.** S3 has no
directories. The analyzer's recursive prefix listing of a flat URI
(`s3://…/slug/1.0.0/`) also returns every `…/1.0.0/<hash12>/…` object, so both copies
were downloaded and scanned. 62,878 / 83,127 (75.6%) ClawHub skill-versions had both
layouts under one prefix — the "~73% affected".

**`artifact_hash` was computed over** the extracted-and-repackaged `{path: bytes}` dict
(ZIP contents + injected `_detail.json`) — not raw ZIP bytes, and not either "copy"
(the two copies are different snapshots, not a packaging duplication).

## 5. Representative examples (verified against production data)

- **Affected:** `traefik-mantrae-diagnostics` 0.1.0 — row 1167 (flat URI,
  first_seen 2026-05-26) + row 94663 (first_seen 2026-07-02, hash `8d8ecf164e6d…` = the
  observed hex dir). This one is a *genuine* mutation too: the new snapshot adds
  `skill-card.md`.
- **Unaffected:** `0codekit` 1.0.4 — single flat row; S3 holds only flat keys.
- **Pre-cutover overwrite:** `1password-old` 1.0.0 — two 2026-05-26 rows *sharing* one
  flat URI (the earlier snapshot's bytes were overwritten before the hash-path cutover)
  plus one verify-crawl hash row.

**Production S3 objects are NOT corrupted or duplicated within an artifact.** Each
snapshot sits at its own key set. The duplication exists only in (1) the DB row
explosion and (2) the analyzer's materialized view of legacy-flat rows.

## 6. Run #70 disposition

Discarded. The process was stopped 2026-07-05 (~54.6k/152.9k processed) and
`analysis_runs` row 70 marked `failed` with an explanatory `error_message`. Its
results must not be used for corpus-level conclusions. Re-run after the DB repair.

## 7. Fixes (implemented)

- **Crawler** (branch `fix-volatile-detail-hash`): `BaseSource.hash_excluded_files`
  (ClawHub: `{"_detail.json"}`); `compute_artifact_hash(files, exclude=…)` applied in
  both crawl and backfill paths. `_detail.json` is still stored — it just no longer
  defines identity. GitHub's `_github.json` is already content-stable and stays hashed.
  Genuine content changes (edits, added/removed files) still produce new snapshot rows;
  distinct rows per version name are unaffected (version remains in the unique key and
  the storage path). Tests: `tests/test_artifact_hash.py`.
- **Analyzer** (branch `fix-scoped-artifact-materialization`): `download_prefix()` skips
  `{12-hex}/` first-segment subtrees when materializing a legacy flat URI;
  hash-segmented URIs stay scoped as before. Bare hex-looking *filenames* are kept.
  Tests: `tests/test_s3_loader_scoping.py`; verified live against skill 1167 (flat URI
  now materializes 5 files, previously 11).
- **Metrics exporters**: methodology strings now state that `artifact_hash` is a content
  hash (post-repair) and that pre-repair exports overcount snapshots/mutations;
  `collapsed_noise_snapshots` is surfaced from the audit table.

## 8. Repair plan (DB + S3)

1. **DB migration** — `scripts/migrate_recompute_artifact_hash.py`. Recomputes every
   stored hash from S3 under the new definition (layout-scoped listing) and collapses
   rows within a `(source, source_id, version)` group that recompute identically —
   the verify-crawl noise. Genuine mutations survive. Dry-run by default with a full
   TSV report; `--execute` requires a prior `pg_dump`, applies each group in its own
   transaction, and preserves every deleted row in `skills_hash_migration_audit`
   (superseded id, survivor id, old hash/URI, seen timestamps, crawl-run refs, name,
   metadata). Idempotent; takes the systemd per-source crawl lock. Expected outcome:
   ClawHub rows drop from ~148k back to ~84-85k.
   - Known caveat: pre-cutover same-URI row pairs (e.g. `1password-old`) collapse too —
     their earlier bytes were already overwritten pre-cutover, so no recoverable data is
     lost; the old hash is preserved in the audit table.
   - Rows whose `artifact_uri` hash segment no longer equals their recomputed
     `artifact_hash` are expected and harmless: per the storage contract, the URI is
     authoritative and paths are never reconstructed from hashes.
2. **Validation** — `--validate-only` prints invariants: rows per source, rows per
   group distribution, zero duplicate `(source, source_id, version, artifact_hash)`
   tuples, audit counts, and the three representative examples (expected rows after:
   traefik-mantrae 2, 1password-old 2, 0codekit 1).
3. **S3 cleanup** — `scripts/cleanup_orphaned_hash_dirs.py`. Manifest-only by default
   (DB-driven, `Delimiter='/'`, only immediate `{12-hex}/` CommonPrefixes, never flat
   keys). Deletion runs only from a reviewed manifest, re-validates each prefix against
   the live DB immediately before deleting, and is gated on separate explicit approval
   after the migration and analyzer fix are validated.
4. **Re-run analysis** — fresh production run replacing #70; compare indicator
   distribution against run #68 (last clean baseline).
5. **Watch the next verify crawl** (2026-07-12 12:00): `skills_inserted` should be
   small (genuine changes only), not ~65k. If the migration has not been executed by
   then, hold the timer first
   (`sudo systemctl disable --now openclaw-crawler-verify@clawhub.timer`) — a verify
   run against un-migrated rows would re-insert the duplicates.

## 9. Risks and rollback

- **DB**: pg_dump backup before `--execute`; per-group transactions (crash-safe,
  resumable); audit table preserves everything deleted; rollback = restore dump.
- **Hash semantics**: consumers must not assume `artifact_hash` covers `_detail.json`.
  Known consumers (pipeline dedup, analyzer skip-logic, metrics exporters) reviewed;
  metric definitions updated. Old analysis runs referencing collapsed row ids become
  historical — they are superseded anyway.
- **S3**: deletion is last, manifest-first, re-validated, hash-dir-only; the only
  irreversible step, hence separately gated. Flat-level keys are never candidates.
- **12-hex false positives** (a legitimate artifact directory named like 12 hex chars):
  would be skipped by the analyzer and excluded from a flat row's hash. No such
  directory exists in the corpus today (the crawler's own layouts never produce one at
  flat level); the migration dry-run report makes any future instance visible.
