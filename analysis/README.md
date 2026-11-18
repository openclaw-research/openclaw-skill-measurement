# OpenClaw Skill Analysis

This repository contains the initial static analysis framework for OpenClaw skill artifacts.

It is separate from `openclaw-skill-crawling`. The crawler collects skills from ClawHub, writes metadata to PostgreSQL, and stores artifacts in S3. This repo does not crawl. It reads the existing `skills` rows and S3 artifacts produced by the crawler, then stores analysis output in new analysis tables in the same PostgreSQL database.

## Current Scope

- Static analysis only.
- Manual CLI execution only.
- No queues, workers, Redis, Celery, or dynamic execution.
- Artifacts are downloaded from S3 into a temporary local directory, analyzed, then deleted.
- Results link to `skills.id`.

Future work can add dynamic sandboxing and LLM-assisted interpretation once the static baseline is stable.

## Setup

Create or refresh the project-local virtual environment:

```bash
python3 -m venv venv
```

Install dependencies into the local venv:

```bash
venv/bin/python -m pip install -r requirements.txt
```

Copy the example environment file if you need local overrides:

```bash
cp .env.example .env
```

The expected defaults are:

```env
DATABASE_URL=postgresql://collector_user:user%40123@localhost:5432/skill_collector
S3_BUCKET=openclaw-skill-artifacts
AWS_REGION=us-east-1
ARTIFACT_TMP_DIR=/tmp/openclaw-analysis
```

S3 access uses the EC2 instance IAM role. Do not put AWS credentials in this repo.

## Database

This repository shares the existing `skill_collector` PostgreSQL database with the crawler. Crawler-owned tables are read-only from this repo; `init-db` creates only analysis-owned tables if they are missing.

The CLI checks the existing `skills` table before creating analysis tables. It verifies `skills.id` and the artifact columns needed for analysis.

Create the analysis tables:

```bash
venv/bin/python cli.py init-db
```

See [docs/design/database.md](docs/design/database.md) for table relationships and column notes.

## Run Static Analysis

Analyze a small batch:

```bash
venv/bin/python cli.py analyze-static --limit 10
```

Analyze one skill:

```bash
venv/bin/python cli.py analyze-static --skill-id 123
```

By default, a skill is skipped if the same artifact hash already has a successful result for the same analyzer name and analyzer version. Use `--force` to analyze it again:

```bash
venv/bin/python cli.py analyze-static --skill-id 123 --force
```

Each result stores its own `artifact_hash`, `analyzer_name`, and `analyzer_version`, so analyzer identity and artifact identity remain visible without joining through the run record.

For larger batches, progress is written to a per-run log file instead of the terminal. The log directory is created automatically, and filenames use local system time:

```text
logs/analyze-static-YYYYMMDD-HHMMSS.log
```

Use `--log-level` to control detail and `--progress-every` to write periodic aggregate progress entries:

```bash
venv/bin/python cli.py analyze-static --limit 100 --log-level INFO --progress-every 25
venv/bin/python cli.py analyze-static --limit 100 --log-level DEBUG --progress-every 10
```

The CLI prints the selected log path at startup. Monitor the latest run in another shell with that filename:

```bash
tail -f logs/analyze-static-<timestamp>.log
```

Print aggregate analysis counts:

```bash
venv/bin/python cli.py summary
```

Print recent findings, optionally filtered by severity:

```bash
venv/bin/python cli.py findings --severity high
```

## Temporary Artifacts

Each artifact URI is downloaded under `ARTIFACT_TMP_DIR` into a per-skill temporary directory. Prefix URIs preserve relative paths, and exact object URIs are saved by basename. The pipeline removes that directory after each skill, including failed downloads or failed analysis attempts.

## Collector-Generated Metadata Files

The OpenClaw crawler appends metadata files to each skill artifact prefix before storing it in S3. These files are crawler infrastructure, not developer-authored skill content.

The current list of excluded files is:

```text
_detail.json   — marketplace listing metadata (URLs, descriptions, publisher info)
```

`_meta.json` is **not** excluded. It is developer-authored skill metadata that the analyzer parses for structured context.

### Why exclude `_detail.json`

Marketplace descriptions in `_detail.json` routinely contain terms such as `token`, `secret`, `authorization`, and `https://` links to listing pages. Scanning this content as if it were skill code would:

- inflate `secret_handling`, `network_access`, and other indicator counts
- add marketplace domains to the `external_urls` list
- elevate `risk_level` to `medium` or `high` for skills with no risky code
- make corpus statistics unsuitable for characterizing actual skill behavior

### How exclusion works

Files listed in `COLLECTOR_METADATA_FILES` are recorded in `collector_metadata_files` inside `result_json` for inventory traceability, but their content is not scanned. They do not contribute to `file_count`, `extension_counts`, indicator counts, `external_urls`, or `env_var_references`. `file_count` and the analysis summary reflect only skill-authored files.

### Impact on existing results

Results recorded with analyzer version `2` include content from `_detail.json` and should be considered polluted for corpus-level statistics. Re-running analysis with `--force` after upgrading to version `3` will produce clean results.

## Static Analyzer

The static analyzer is deterministic and does not make LLM calls. Version 3 collects:

- File inventory (skill-authored files only; collector metadata files listed separately).
- Presence of `SKILL.md`, `_meta.json`, `README.md`, `package.json`, and `requirements.txt`.
- File extension counts.
- Environment variable references.
- External URLs and domains.
- Parsed context from `SKILL.md`, `_meta.json`, `package.json`, and `requirements.txt`.
- Basic context for Python, JavaScript, TypeScript, and shell files.
- Structured findings for `network_access`, `secret_handling`, `filesystem_access`, `process_execution`, `hook_or_tool_exposure`, `dependency_or_install_script`, and `suspicious_prompting`.
- Install script indicators such as `preinstall`, `postinstall`, and `prepare`.
- Suspicious instruction indicators around credentials, persistence, background execution, and exfiltration.

Risk is a simple heuristic:

- `low` when few or no risky indicators are present.
- `medium` when network, process execution, filesystem, secret, dependency/install script, or suspicious prompting indicators exist.
- `high` when stronger combinations appear, such as secret or suspicious prompting indicators plus network or process execution indicators.

### Analyzer structure

The analyzer (`StaticAnalyzer` in `analyzers/static/`) is split by responsibility: rule definitions live in `rules/definitions.py`, indicator matching in `rules/matching.py`, parsed-file extraction in `extraction.py`, traversal in `inventory.py`, scoring in `scoring.py`, findings in `findings.py`, and orchestration in `analyzer.py`. To change the rule set, edit `rules/definitions.py`. See [docs/design/analyzer.md](docs/design/analyzer.md) for the module layout and the analyzer versioning policy.
