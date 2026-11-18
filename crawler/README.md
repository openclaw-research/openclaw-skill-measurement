# OpenClaw Skill Collector

Security research tool for collecting and storing skills/plugins from ClawHub and other
AI agent ecosystems. Crawls published skills, downloads full ZIP artifacts, and stores
them alongside normalized metadata in PostgreSQL.

## Architecture

```
sources/        discovery layer — one module per ecosystem
storage/        artifact storage abstraction (local filesystem or S3)
db/             SQLAlchemy ORM, session factory, repository layer
pipeline.py     crawl and backfill orchestration
cli.py          entry point (init-db, crawl, backfill)
scripts/        operational utilities (S3 verification, migration)
```

**Collection flow:** `sources/` discovers skills → `pipeline.py` hashes and deduplicates →
`storage/` writes artifacts → `db/` upserts metadata.

## Documentation

This README is the quickstart. The full documentation lives in [`docs/`](docs/):

- **[docs/system-design.md](docs/system-design.md)** — architecture, the source→pipeline→
  storage→DB flow, where the code lives, and the invariants the system relies on. *Start here.*
- **[docs/sources.md](docs/sources.md)** — ClawHub and GitHub source behaviour, the GitHub seed
  file policy, the `source_id` / `version` / `revision` / `artifact_hash` conventions, and how
  to add a new source.
- **[docs/data-model-and-storage.md](docs/data-model-and-storage.md)** — DB tables and
  constraints, the `skills` uniqueness model, the `revision` column, hash-segmented artifact
  paths, and S3 prefix conventions.
- **[docs/operations.md](docs/operations.md)** — manual crawl commands and modes, per-source
  systemd timers and locks, install/enable steps, status/logs, and what not to run concurrently.
- **[docs/misc/third_party_crawling_exploration.md](docs/misc/third_party_crawling_exploration.md)** —
  the original exploration/design note. *Historical context, not current truth.*

## Prerequisites

- Python 3.11+
- PostgreSQL (peer auth as `postgres`)
- AWS credentials with `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`, `s3:DeleteObject`
  on the target bucket (IAM role or `~/.aws/credentials`)

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create `.env` in the project root:

```ini
DATABASE_URL=postgresql://collector_user:user%40123@localhost:5432/skill_collector
ARTIFACT_STORE=s3          # or "local"
S3_BUCKET=your-bucket-name
AWS_REGION=us-east-1
```

For local storage only, `S3_BUCKET` and `AWS_REGION` can be omitted.
Set `ARTIFACT_ROOT` to override the default `./artifacts` directory.

Initialize the database:

```bash
sudo -u postgres psql -c "CREATE USER collector_user WITH PASSWORD 'password';"
sudo -u postgres psql -c "CREATE DATABASE skill_collector OWNER collector_user;"
python3 cli.py init-db
```

## Usage

### Crawl

Discover and store skills from a source:

```bash
python3 cli.py crawl --source clawhub
python3 cli.py crawl --source clawhub --limit 50 --dry-run
```

| Flag | Default | Description |
|------|---------|-------------|
| `--source` | `clawhub` | Source to crawl |
| `--limit N` | none | Stop after N skills |
| `--page-size N` | 50 | API results per page |
| `--delay SECS` | 0.1 | Seconds between HTTP requests |
| `--dry-run` | off | Discover without writing anything |
| `-v` | off | DEBUG logging |

### Backfill

Re-download full ZIP artifacts for skills already in the DB (useful after adding
new file extraction logic or switching storage backends):

```bash
python3 cli.py backfill --source clawhub
python3 cli.py backfill --source clawhub --limit 100 --force
```

`--force` re-downloads even when the artifact hash is unchanged.

### Migrate local artifacts to S3

After switching `ARTIFACT_STORE` from `local` to `s3`, migrate existing artifacts:

```bash
# Dry run first
python3 scripts/migrate_to_s3.py --dry-run

# Test on a small batch
python3 scripts/migrate_to_s3.py --source clawhub --limit 10

# Full migration (resumable if interrupted)
python3 scripts/migrate_to_s3.py 2>&1 | tee logs/migration.log

# Resume from a known row id after interruption
python3 scripts/migrate_to_s3.py --resume-from-id 1234
```

Local artifacts are not deleted — they remain as a backup.

### Verify S3 backend

```bash
python3 scripts/verify_s3.py
```

Exercises `save_many()`, `save()`, and `exists()` with a synthetic artifact,
confirms all objects land in S3, and cleans up.

## Data model & artifact storage

Two tables (`skills`, `crawl_runs`) with the uniqueness key
`(source, source_id, version, artifact_hash)`, and a hash-segmented immutable artifact layout
`{source}/{skill_id}/{version}/{artifact_hash[:12]}/…`. Full details — columns, constraints, the
`revision` column, and how legacy flat ClawHub paths coexist with new hash-segmented paths — are
in **[docs/data-model-and-storage.md](docs/data-model-and-storage.md)**.

## Scheduling (systemd)

Crawls run as one-shot processes under systemd, **one timer per source**, via a templated
service `openclaw-crawler@.service` (instance `%i` = source) with per-source locks
(`/tmp/openclaw-crawler-<source>.lock`) so clawhub and github-skills may run concurrently but
never overlap themselves:

- `openclaw-crawler@clawhub.timer` — every 48h
- `openclaw-crawler@github-skills.timer` — daily

Full install/enable/migration commands, status & log inspection, periodic `--verify-existing`,
and concurrency cautions are in **[docs/operations.md](docs/operations.md)**.

---

## Version mutations

Published versions are not immutable (ClawHub has served different bytes under the same
version; git branches move). The DB preserves each observed artifact state as a separate row
(the uniqueness key includes `artifact_hash`), and new writes use hash-segmented paths so
distinct snapshots are also preserved in storage. (Legacy pre-cutover ClawHub objects used a
flat path and were overwritten on mutation; their DB hash rows remain as evidence. See
[docs/data-model-and-storage.md](docs/data-model-and-storage.md).)

To find skills where a source served different artifact content under the same version:

```sql
SELECT source_id, version,
       COUNT(*)                          AS snapshot_count,
       array_agg(artifact_hash ORDER BY id) AS hashes
FROM skills
WHERE source = 'clawhub'
GROUP BY source_id, version
HAVING COUNT(*) > 1
ORDER BY snapshot_count DESC, source_id;
```

To find skills not seen in the most recent successful crawl (possibly removed from ClawHub):

```sql
SELECT source_id, name, last_seen_at
FROM skills
WHERE source = 'clawhub'
  AND last_crawl_run_id < (
        SELECT id FROM crawl_runs
        WHERE source = 'clawhub' AND status = 'success'
        ORDER BY id DESC LIMIT 1
      )
ORDER BY last_seen_at DESC;
```

---

## Project layout

```
cli.py                  entry point
pipeline.py             run_crawl(), run_backfill()
requirements.txt        pinned direct dependencies
sources/
  base.py               BaseSource ABC, SkillMetadata dataclass
  clawhub.py            ClawHub REST API crawler
  github.py             GitHub SKILL.md crawler (seed allowlist)
config/
  github_skills_seeds.txt  GitHub repo allowlist for github-skills
storage/
  base.py               ArtifactStore ABC
  local.py              LocalArtifactStore
  s3.py                 S3ArtifactStore (boto3)
db/
  models.py             Skill, CrawlRun ORM models
  repository.py         SkillRepository, CrawlRunRepository
  session.py            SQLAlchemy engine and SessionLocal
deploy/
  openclaw-crawler@.service            templated per-source oneshot service (per-source flock)
  openclaw-crawler-verify@.service     templated per-source --verify-existing service
  openclaw-crawler@clawhub.timer       clawhub schedule (every 48h)
  openclaw-crawler-verify@clawhub.timer clawhub verify schedule (~every 10 days)
  openclaw-crawler@github-skills.timer github-skills schedule (daily)
scripts/
  verify_s3.py          S3 backend smoke test
  migrate_to_s3.py      Migrate local artifacts to S3
docs/                   System design, sources, data model & storage, operations
logs/<source>/          Per-run log files, one dir per source (gitignored)
artifacts/              Local artifact storage root (gitignored)
```
