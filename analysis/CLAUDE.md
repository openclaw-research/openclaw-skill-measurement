# CLAUDE.md — OpenClaw Skill Analysis

## Repository Rules

- Keep the design simple and avoid overengineering. Prefer maintainable, incremental solutions over complex abstractions.
- Write clean, well-documented code. Add docstrings/comments where helpful and update README/design docs when behavior changes.
- Preserve historical evidence and reproducibility. Avoid destructive changes to collected artifacts, analysis results, or research data.
- Be careful around shared infrastructure. Do not modify crawler behavior, crawler tables, S3 layouts, or production services unless explicitly instructed.
- Prefer additive, backward-compatible schema and API changes.
- Validate changes before declaring them complete. Report what was tested and any known limitations.
- Make commits at logical checkpoints with concise human-style commit messages.
- Do not add AI attribution, generated-by comments, Claude/Codex references, or AI co-author metadata.
- For measurement-related changes, explain how the change affects corpus statistics, findings, and reproducibility.
- If a design choice involves tradeoffs, document the reasoning and clearly state assumptions.

## What this repository does

Static analysis of OpenClaw skill artifacts. The crawler (`openclaw-skill-crawling`) collects skills from ClawHub, writes rows to the `skills` table in PostgreSQL, and uploads artifact files to S3. This repo reads those rows and artifacts, runs analysis, and writes output to analysis-owned tables in the same database. It does **not** crawl, queue, or dynamically execute anything.

## Running the project

```bash
# Create venv and install deps
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt

# Initialize analysis tables (run once, safe to repeat)
venv/bin/python cli.py init-db

# Analyze a small batch
venv/bin/python cli.py analyze-static --limit 10

# Analyze one skill by ID
venv/bin/python cli.py analyze-static --skill-id 123

# Force re-analysis even if a result exists
venv/bin/python cli.py analyze-static --skill-id 123 --force

# View results
venv/bin/python cli.py summary
venv/bin/python cli.py findings --severity high
```

## Running tests

```bash
venv/bin/python -m pytest tests/ -v
```

Tests are standalone (no database, no S3). They use `tempfile.TemporaryDirectory` to create local fixture directories.

## Project layout

```
analyzers/base.py                     — AnalysisReport dataclass and Analyzer protocol
analyzers/static/analyzer.py          — StaticAnalyzer: high-level orchestrator only
analyzers/static/inventory.py         — single-pass traversal + ScanState; collector metadata handling
analyzers/static/text.py              — text reading and snippet helpers
analyzers/static/extraction.py        — parsed-file context (SKILL.md, manifests, code)
analyzers/static/scoring.py           — risk-level heuristic and result summary
analyzers/static/findings.py          — structured finding construction
analyzers/static/rules/definitions.py — rule/category/pattern/limit constants (data only)
analyzers/static/rules/matching.py    — indicator matching and evidence accumulation
artifacts/s3_loader.py                — S3 download: prefix listing, path safety checks
pipeline/static_pipeline.py           — Orchestrates download → analyze → persist for each skill
db/models.py                          — SQLAlchemy ORM: analysis_runs, analysis_results, analysis_findings
db/repository.py                      — AnalysisRepository: all DB reads and writes
db/session.py                         — Engine and session factory
cli.py                                — Click-free argparse CLI: init-db, analyze-static, summary, findings
config.py                             — Settings from env vars or .env
tests/                                — Pytest tests; currently covers collector metadata exclusion
docs/design/analyzer.md               — Static analyzer module layout and versioning policy
docs/design/database.md               — Table schema, column notes, skip behavior
```

The static analyzer is split by responsibility. **Rules live in `rules/definitions.py`** (the only place to edit categories, match terms, regexes, and limits). **Extraction logic lives in `extraction.py`**. Scanning/evidence is in `rules/matching.py`, traversal in `inventory.py`, scoring in `scoring.py`, findings in `findings.py`, and `analyzer.py` only orchestrates. `analyzer.py` re-exports `StaticAnalyzer` and `COLLECTOR_METADATA_FILES` as the package's public entry point.

## Analyzer versioning

`StaticAnalyzer.version` is a string in [analyzers/static/analyzer.py](analyzers/static/analyzer.py). The class name is intentionally version-agnostic (`StaticAnalyzer`, not `StaticAnalyzerVN`); the active contract is the `version` attribute. Bump this string whenever:
- a new finding category is added or removed
- scanning logic changes in a way that makes old and new results incomparable
- the `result_json` schema changes in a breaking way

A pure refactor that preserves output must **not** change `version`. Skip logic (`has_successful_result`) checks `(skill_id, artifact_hash, analyzer_name, analyzer_version)`. A version bump forces re-analysis of every previously-analyzed skill on the next run without `--force`.

## Collector-generated metadata files

The crawler appends `_detail.json` to each skill artifact prefix. This file contains marketplace metadata (URLs, descriptions, publisher info) — it is **not** developer-authored skill content.

The constant `COLLECTOR_METADATA_FILES` (in [analyzers/static/analyzer.py](analyzers/static/analyzer.py)) lists these files. Files in that set are:
- recorded in `result_json["collector_metadata_files"]` for inventory traceability
- **not** scanned for indicators, URLs, env vars, or file context
- **not** counted in `file_count` or `extension_counts`

`_meta.json` is developer-authored skill metadata and is **not** in this exclusion set.

If the crawler adds new metadata files in the future, add them to `COLLECTOR_METADATA_FILES` and bump the analyzer version.

## Database ownership

Crawler-owned tables (`skills`) are **read-only** from this repo. Do not create, alter, or drop them. The analysis tables (`analysis_runs`, `analysis_results`, `analysis_findings`) are analysis-owned and are created by `cli.py init-db`.

See [docs/design/database.md](docs/design/database.md) for full schema and column notes.

## Design rules

- Keep the design simple. No queues, workers, Redis, Celery, or dynamic execution.
- Preserve historical evidence. Do not delete or retroactively modify existing analysis results.
- Do not modify crawler code or crawler data.
- Artifacts are downloaded to a temporary directory, analyzed, then deleted immediately.
- The static analyzer is deterministic and makes no LLM calls.
- Document any decision that affects measurement validity (see README.md and database.md).

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql://collector_user:user%40123@localhost:5432/skill_collector` | PostgreSQL connection URL |
| `S3_BUCKET` | `openclaw-skill-artifacts` | S3 bucket for skill artifacts |
| `AWS_REGION` | `us-east-1` | AWS region |
| `ARTIFACT_TMP_DIR` | `/tmp/openclaw-analysis` | Temporary directory for downloaded artifacts |

S3 access uses the EC2 instance IAM role. Do not put AWS credentials in this repo.

Copy `.env.example` to `.env` for local overrides.
