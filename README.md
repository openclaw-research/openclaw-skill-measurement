# OpenClaw Skill Measurement

Artifact repository for the paper **"Security Measurement of the OpenClaw Skill Ecosystem"**.

## Repository Layout

| Directory | Description |
|-----------|-------------|
| `crawler/` | Skill crawler for ClawHub and GitHub (snapshot collection, deduplication) |
| `analysis/` | Static analyzer, LLM classifier, dynamic sandbox pipeline, and reporting scripts |

## Dataset

The full dataset is archived on Zenodo:

**DOI: [10.5281/zenodo.24329490](https://doi.org/10.5281/zenodo.24329490)**

The deposit includes:

- `skill_collector_oct13_2026.sql.gz` — full PostgreSQL database dump (~2.5 GB compressed)
- `inplace_mutation_analysis.csv` — per-skill in-place mutation analysis
- `scan_coverage_by_month.csv` — ClawScan coverage and lag by publication month
- `moderation_status.csv` — per-skill ClawScan verdicts and timestamps
- `timeseries_skills.csv` — weekly skill publication counts
- `cred_vars_by_category.csv` / `cred_vars_top20.csv` — credential variable detections
- `author_concentration.csv` — author-level skill count distribution
- `reappearance_14day_oct13.csv` — skills removed and reappeared within 14 days
- `runtime_install_labeled.csv` — runtime install behavior labels (sample)
- `README_dataset.md` — schema documentation and loading instructions

## Setup

Each subdirectory has its own `requirements.txt` and `.env.example`.

```bash
# Crawler
cd crawler && pip install -r requirements.txt && cp .env.example .env

# Analysis
cd analysis && pip install -r requirements.txt && cp .env.example .env
```

Edit `.env` in each directory before running.

## Security Notice

The analysis pipeline processes third-party skill content that may include malicious commands. Run the dynamic sandbox only inside an isolated VM. Do not execute any skill content outside a controlled environment.

## License

Code: MIT  
Dataset: CC BY 4.0 (https://doi.org/10.5281/zenodo.24329490)
