# System Design

High-level architecture of the OpenClaw skill collector as it exists today. For deeper
detail see the companion docs:

- [sources.md](sources.md) — how each source discovers and fetches skills; conventions for
  `source_id` / `version` / `revision` / artifact hash; how to add a source.
- [data-model-and-storage.md](data-model-and-storage.md) — DB tables, the uniqueness model,
  and the artifact storage layout.
- [operations.md](operations.md) — running crawls, scheduling, locks, logs.
- [third_party_crawling_exploration.md](misc/third_party_crawling_exploration.md) — the original
  exploration/design note. **Historical**; kept for rationale, not current truth.

## Purpose

Security-research tool that collects AI-agent skills/plugins from ClawHub and other
ecosystems, downloads their full artifacts, stores them (S3 or local), and persists
normalized metadata in PostgreSQL for downstream analysis.

## Architecture

Four layers with strict separation of concerns:

| Layer | Code | Responsibility |
|-------|------|----------------|
| **Sources** | [`sources/`](../sources) | Discovery + artifact fetch. `BaseSource.discover()` yields lightweight `SkillMetadata` stubs; `fetch_artifact()` downloads bytes only when the pipeline asks. |
| **Pipeline** | [`pipeline.py`](../pipeline.py) | Orchestration: `run_crawl()` / `run_backfill()`. Owns all DB transaction boundaries and the hashing/dedup/update-detection logic. |
| **Storage** | [`storage/`](../storage) | Artifact persistence behind the `ArtifactStore` ABC (`LocalArtifactStore`, `S3ArtifactStore`) — interchangeable. |
| **DB** | [`db/`](../db) | SQLAlchemy ORM (`models.py`), repository pattern (`repository.py`), session factory (`session.py`). |

Entry point is [`cli.py`](../cli.py). All runtime configuration comes from `.env`.

## Collection flow

```
source.discover()                 # yields SkillMetadata stubs (no bytes)
   │
   ▼
pipeline.run_crawl()
   ├─ already stored at this revision? ──► touch timestamps, skip download
   ├─ otherwise: source.fetch_artifact() ─► {path: bytes}
   ├─ compute_artifact_hash(files)        ─► canonical SHA-256 identity
   ├─ store.save_many(..., artifact_hash) ─► hash-segmented artifact dir (URI)
   └─ repository.upsert(...)              ─► insert new hash row / refresh existing
        │
        ▼
   crawl_runs row finalized: success / partial_success / failed
```

`discover()` is intentionally cheap (metadata only); the expensive artifact download happens
in `fetch_artifact()` and only when [update detection](sources.md#update-detection) decides it
is needed. See [data-model-and-storage.md](data-model-and-storage.md) for what gets written.

## Where the code lives

```
cli.py                  entry point: init-db, crawl, backfill; logging setup; source registry
pipeline.py             run_crawl(), run_backfill(), compute_artifact_hash(),
                        _needs_artifact_fetch(), run-status computation
sources/
  base.py               BaseSource ABC + SkillMetadata dataclass (the source↔pipeline contract)
  clawhub.py            ClawHub REST API source (first-party)
  github.py             GitHub SKILL.md source + load_seeds()
config/
  github_skills_seeds.txt   hand-maintained GitHub repo allowlist
storage/
  base.py               ArtifactStore ABC (+ ARTIFACT_HASH_SEGMENT_LEN)
  local.py              LocalArtifactStore
  s3.py                 S3ArtifactStore (boto3)
db/
  models.py             Skill, CrawlRun ORM models + constraints/indexes
  repository.py         SkillRepository, CrawlRunRepository
  session.py            SQLAlchemy engine + SessionLocal
scripts/                standalone migrations + S3 utilities (migrate_*.py, verify_s3.py)
deploy/                 templated systemd service + per-source timers
docs/                   this documentation set
```

## Invariants the system relies on

These hold across the codebase; breaking one is a bug:

1. **Repositories never `commit()`.** They only `flush()`. Transaction boundaries are owned
   by `pipeline.py`. (`session.py` `get_session()` is the only other committer.)
2. **Artifact hash is the byte identity.** `compute_artifact_hash()` is the single source of
   truth (sorted `filename+content` SHA-256), shared by crawl and backfill so they can't drift.
3. **Each distinct artifact snapshot is its own row.** The `skills` uniqueness key includes
   `artifact_hash`; historical hash rows are mutation evidence and are never deleted in the
   crawl path. (`update_artifact_content()` may delete duplicates, but is backfill-only.)
4. **`artifact_uri` is authoritative.** Never reconstruct a storage path from
   `(source, source_id, version)` — old flat paths and new hash-segmented paths coexist.
5. **Downloaded third-party content is never executed.** Sources only read bytes; archive
   extraction enforces size/file-count caps, skips symlinks, and rejects path traversal.
6. **Sources are interchangeable through `BaseSource`.** The pipeline touches a source only via
   `discover()`, `fetch_artifact()`, `source_name`, and `pagination_stopped_early`.
7. **Single-node, synchronous.** No async, queues, or workers (see Design constraints below).

## Design constraints

- Synchronous, single-node — no async/queues/workers.
- No Alembic — schema changes go through standalone `scripts/migrate_*.py`.
- Curated, allowlist-based crawling — no automated GitHub search / awesome-list expansion (yet).

## Future extensions

- De-duplicate mirrored skills (same content under multiple dirs) — see the mirror note in the
  exploration doc.
- Split `skills` into skills + skill_versions if the single-table model strains.
- Analysis-results tables for downstream measurement.
