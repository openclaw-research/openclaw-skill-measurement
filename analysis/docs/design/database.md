# Database Design

This repository shares the existing `skill_collector` PostgreSQL database with `openclaw-skill-crawling`. The crawler owns collection tables such as `skills`; this repository treats crawler-owned tables as read-only and writes only to analysis-owned tables.

`skills.id` is the stable anchor for analysis output. Every skill-level analysis result links back to one existing `skills.id` row. Each result also stores the artifact hash and analyzer identity that produced it, so the result can be understood without joining back through `skills` or `analysis_runs`.

```text
skills -----------+
                  +--> analysis_results --> analysis_findings
analysis_runs ----+
```

## Result Identity

A result is identified at the application level by:

- `skill_id`
- `artifact_hash`
- `analyzer_name`
- `analyzer_version`

`artifact_hash` is part of this identity because the same skill can be recrawled or republished with changed artifact contents. A successful result for one artifact hash should not cause a different artifact hash to be skipped.

The database does not currently enforce a uniqueness constraint on this identity. This keeps historical re-analysis flexible; skip behavior is enforced by the application.

## Crawler-Owned Tables

The analysis code reads the existing `skills` table to select artifacts and metadata. It expects these columns to exist:

- `id`
- `source`
- `source_id`
- `name`
- `version`
- `artifact_uri`
- `artifact_hash`

This repository does not create, redefine, or modify crawler-owned tables.

## Analysis-Owned Tables

### analysis_runs

One row represents one execution of an analyzer.

| Column | Purpose | Notes |
| --- | --- | --- |
| `id` | Primary key for the analyzer execution. | Referenced by `analysis_results.analysis_run_id`. |
| `analyzer_name` | Analyzer family, such as `static`. | Used with `analyzer_version` for skip logic. |
| `analyzer_version` | Analyzer rule/output version. | New rule-output shapes should use a new version. |
| `status` | Run status. | Currently `running`, `success`, or `failed`. |
| `started_at` | Timestamp when the run started. | Stored with timezone. |
| `finished_at` | Timestamp when the run finished. | Null until completion. |
| `config_json` | Run options. | Stores values such as `limit`, `skill_id`, and `force`. |
| `error_message` | Run-level error text. | Per-skill failures are stored in `analysis_results`. |

### analysis_results

One row represents the result for one skill in one analysis run.

| Column | Purpose | Notes |
| --- | --- | --- |
| `id` | Primary key for the skill-level result. | Referenced by `analysis_findings.analysis_result_id`. |
| `skill_id` | Link to the analyzed skill. | Foreign key to crawler-owned `skills.id`. |
| `analysis_run_id` | Link to the run that produced the result. | Foreign key to `analysis_runs.id`. |
| `artifact_hash` | Hash of the artifact that was analyzed. | Copied from `skills.artifact_hash` when the result is created. |
| `analyzer_name` | Analyzer family that produced the result. | Copied from the current analyzer and mirrors `analysis_runs.analyzer_name`. |
| `analyzer_version` | Analyzer rule/output version. | Copied from the current analyzer and mirrors `analysis_runs.analyzer_version`. |
| `status` | Skill-level analysis status. | Currently `success` or `failed`. |
| `risk_level` | Coarse heuristic risk level. | Currently `low`, `medium`, `high`, or `unknown`. |
| `summary` | Short human-readable result summary. | Intended for quick CLI review. |
| `result_json` | Full structured analyzer output. | Includes inventory, parsed file context, indicators, URLs, and env vars. |
| `created_at` | Timestamp when the result was created. | Stored with timezone. |

### analysis_findings

One row represents one structured finding associated with an analysis result.

| Column | Purpose | Notes |
| --- | --- | --- |
| `id` | Primary key for the finding. | Stable row for reviewing one finding. |
| `analysis_result_id` | Link to the skill-level result. | Foreign key to `analysis_results.id`. |
| `category` | Finding category. | Examples: `network_access`, `secret_handling`, `filesystem_access`. |
| `severity` | Finding severity. | Currently `low`, `medium`, or `high`. |
| `title` | Short finding label. | Suitable for CLI output. |
| `description` | Human-readable explanation. | Rule-based deterministic text. |
| `evidence_json` | Structured finding evidence. | May include file path, indicator, line, snippet, count, URL, or domain. |
| `created_at` | Timestamp when the finding was created. | Stored with timezone. |

## Skip Behavior

By default, analysis skips a skill only when a successful result already exists with the same `skill_id`, `artifact_hash`, `analyzer_name`, and `analyzer_version`. Failed results do not trigger a skip. `--force` bypasses the skip check and records a new result.

Changing the analyzer version causes re-analysis because the result identity changes. Changing the artifact hash also causes re-analysis even when the skill id stays the same.

## Collector-Generated Metadata in result_json

The crawler appends `_detail.json` (marketplace listing metadata) to each skill artifact. Starting with analyzer version `3`, these files are excluded from content analysis and recorded separately.

Inside `result_json`:

| Field | Contents |
| --- | --- |
| `file_inventory` | Skill-authored files only. Does not include collector metadata files. |
| `file_count` | Count of entries in `file_inventory`. Collector metadata files are not counted. |
| `collector_metadata_files` | List of collector-appended files found in the artifact. Each entry records `path`, `size_bytes`, and `extension` for inventory traceability. |
| `extension_counts` | Based on `file_inventory` only. |
| `external_urls` | Extracted from skill-authored files only. Marketplace URLs from `_detail.json` are not included. |
| `env_var_references` | Extracted from skill-authored files only. |
| `indicators` | Counts and evidence from skill-authored files only. |

### Why this matters for corpus statistics

Analyzer version `2` results include content from `_detail.json`. Fields such as `external_urls.domains`, `indicators.secret_handling.count`, and `risk_level` may be inflated by marketplace metadata rather than actual skill behavior. Results from version `2` should not be used for corpus-level measurements without re-analysis under version `3`.
