"""
Read-only metrics exporter for the OpenClaw/ClawHub measurement paper.

This script computes an initial metrics pack from the live PostgreSQL database
and writes Markdown, JSON, and small CSV tables under an output directory. It is
strictly read-only:

- It opens a single REPEATABLE READ, READ ONLY transaction so every metric sees
  a consistent snapshot and the database cannot be modified by this script.
- It does not crawl, write to S3, or run the analyzer.

The generated output directory is temporary and is git-ignored (see .gitignore).

Usage:
    venv/bin/python scripts/export_paper_metrics.py
    venv/bin/python scripts/export_paper_metrics.py --out-dir paper_metrics/2026-06-initial

Every metric is computed inside a guarded block. If a single metric fails, the
failure is recorded under provenance.failed_metrics and the export continues.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.engine import Connection

# Make the project root importable when run as a standalone script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db.session import build_engine  # noqa: E402
from config import get_settings  # noqa: E402
from skill_metrics_common import (  # noqa: E402
    CANONICAL_CATEGORIES,
    CODE_EXTENSIONS,
    select_analysis_run,
)


DEFAULT_OUT_DIR = "paper_metrics/2026-07-initial"

# CANONICAL_CATEGORIES (14, analyzer v4) and CODE_EXTENSIONS are imported from
# skill_metrics_common so every exporter covers the same capability taxonomy.
IMPORTANT_FILES = ("SKILL.md", "_meta.json", "README.md", "package.json", "requirements.txt")

# Co-occurrence pairs explicitly requested for the paper.
COOCCURRENCE_PAIRS = (
    ("secret_handling", "network_access"),
    ("secret_handling", "process_execution"),
    ("suspicious_prompting", "network_access"),
    ("suspicious_prompting", "process_execution"),
    ("dependency_or_install_script", "network_access"),
    ("dependency_or_install_script", "process_execution"),
)

STATEMENT_TIMEOUT_MS = 180_000


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def frac(numerator: int, denominator: int) -> dict[str, Any]:
    """Return an explicit numerator/denominator/pct triple."""
    pct = round(100.0 * numerator / denominator, 2) if denominator else None
    return {"numerator": numerator, "denominator": denominator, "pct": pct}


def git_commit_hash() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip()
    except Exception:
        return None


def distribution(values: list[float]) -> dict[str, Any]:
    """Min / median / mean / max plus count for a numeric list."""
    if not values:
        return {"count": 0, "min": None, "median": None, "mean": None, "max": None}
    return {
        "count": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "mean": round(statistics.fmean(values), 3),
        "max": max(values),
    }


# --------------------------------------------------------------------------- #
# Exporter
# --------------------------------------------------------------------------- #


class MetricsExporter:
    def __init__(self, conn: Connection):
        self.conn = conn
        self.metrics: dict[str, Any] = {}
        self.failed_metrics: list[dict[str, str]] = []
        self.tables: dict[str, tuple[list[str], list[list[Any]]]] = {}

    def q(self, sql: str, **params: Any) -> list[tuple]:
        return list(self.conn.execute(text(sql), params).all())

    def scalar(self, sql: str, **params: Any) -> Any:
        return self.conn.execute(text(sql), params).scalar()

    def guard(self, name: str, fn: Callable[[], Any]) -> None:
        """Run a metric block; record but do not propagate failures."""
        try:
            self.metrics[name] = fn()
        except Exception as exc:  # noqa: BLE001 - we intentionally capture all
            self.failed_metrics.append(
                {"metric": name, "error": f"{type(exc).__name__}: {exc}",
                 "traceback": traceback.format_exc(limit=3)}
            )

    def add_table(self, name: str, header: list[str], rows: list[list[Any]]) -> None:
        self.tables[name] = (header, rows)

    # ----------------------------------------------------------------- #
    # Provenance
    # ----------------------------------------------------------------- #

    def provenance(self, selected_version: str | None) -> dict[str, Any]:
        try:
            db_name = self.scalar("select current_database()")
        except Exception:
            db_name = None
        try:
            versions = [
                {"analyzer_name": n, "analyzer_version": v, "successful_results": c}
                for (n, v, c) in self.q(
                    "select analyzer_name, analyzer_version, count(*) "
                    "from analysis_results where status='success' "
                    "group by 1,2 order by 1,2"
                )
            ]
        except Exception:
            versions = []

        # Infer pre/post _detail.json fix: v3 introduced the collector_metadata_files
        # key and the fix. If the selected version is < 3 (or no result carries the
        # v3 marker), the analysis metrics predate the fix.
        post_fix_marker = False
        try:
            post_fix_marker = bool(
                self.scalar(
                    "select 1 from analysis_results "
                    "where status='success' and result_json ? 'collector_metadata_files' "
                    "limit 1"
                )
            )
        except Exception:
            post_fix_marker = False

        pre_fix = True
        if selected_version is not None:
            try:
                pre_fix = int(selected_version) < 3
            except ValueError:
                pre_fix = not post_fix_marker

        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "git_commit": git_commit_hash(),
            "database_name": db_name,
            "analyzer_versions_present": versions,
            "selected_analyzer_version": selected_version,
            "selection_policy": {
                "latest_snapshot_per_skill": (
                    "DISTINCT ON (source_id) ordered by last_seen_at DESC, id DESC "
                    "-> one row per distinct skill (source_id)."
                ),
                "latest_result_per_latest_snapshot": (
                    "For each latest snapshot row, the analysis_results row with the "
                    "selected analyzer_version and status='success', chosen by "
                    "created_at DESC, id DESC."
                ),
                "selected_analyzer_version": (
                    "Highest analyzer_version present among successful results "
                    "(latest available). NOT necessarily the latest analyzer in code."
                ),
            },
            "detail_json_fix": {
                "analysis_metrics_are_pre_detail_json_fix": pre_fix,
                "any_result_has_collector_metadata_files_key": post_fix_marker,
                "note": (
                    "Analyzer v3 excludes crawler-added _detail.json from content "
                    "analysis. If analysis metrics are pre-fix, capability/risk "
                    "signals include marketplace metadata pollution and are PRELIMINARY."
                ),
            },
            "read_only_transaction": "REPEATABLE READ, READ ONLY",
            "failed_metrics": self.failed_metrics,
        }


# --------------------------------------------------------------------------- #
# Metric computations (each registered through guard())
# --------------------------------------------------------------------------- #


def compute_dataset_overview(ex: MetricsExporter) -> dict[str, Any]:
    total_rows = ex.scalar("select count(*) from skills")
    distinct_skills = ex.scalar("select count(distinct source_id) from skills")
    distinct_pairs = ex.scalar(
        "select count(*) from (select distinct source_id, version from skills) z"
    )
    distinct_hashes = ex.scalar("select count(distinct artifact_hash) from skills")
    distinct_authors = ex.scalar("select count(distinct author) from skills")
    rows_null_author = ex.scalar("select count(*) from skills where author is null")
    window = ex.q("select min(first_seen_at), max(last_seen_at) from skills")[0]
    by_source = {s: c for (s, c) in ex.q(
        "select source, count(*) from skills group by source order by 2 desc"
    )}

    # The 2026-07 hash repair (crawler scripts/migrate_recompute_artifact_hash.py)
    # collapsed snapshot rows that differed only in volatile collector provenance
    # (_detail.json). Collapsed rows live in skills_hash_migration_audit; surface
    # the count so the paper can report the cleaning step. 0 until the migration
    # has run (to_regclass guards the pre-migration schema).
    collapsed_noise_snapshots = 0
    if ex.scalar("select to_regclass('skills_hash_migration_audit') is not null"):
        collapsed_noise_snapshots = ex.scalar(
            "select count(*) from skills_hash_migration_audit"
        )

    return {
        "denominators_are_distinct": (
            "total_rows (artifact snapshots), distinct_skills (source_id), "
            "distinct_skill_version_pairs (source_id,version), and "
            "distinct_artifact_hashes are FOUR DIFFERENT denominators."
        ),
        "artifact_hash_semantics": (
            "artifact_hash is a CONTENT hash: since the 2026-07 repair it excludes "
            "collector-injected provenance (_detail.json), so one hash = one distinct "
            "set of skill files. Exports produced before the repair overcount "
            "snapshots and mutations (volatile API counters flipped the hash)."
        ),
        "collapsed_noise_snapshots": collapsed_noise_snapshots,
        "total_rows_snapshots": total_rows,
        "distinct_skills_source_id": distinct_skills,
        "distinct_skill_version_pairs": distinct_pairs,
        "distinct_artifact_hashes": distinct_hashes,
        "distinct_authors": distinct_authors,
        "rows_with_null_author": rows_null_author,
        "rows_by_source": by_source,
        "observation_window": {
            "first_seen_min": window[0].isoformat() if window[0] else None,
            "last_seen_max": window[1].isoformat() if window[1] else None,
        },
    }


def compute_crawler_metrics(ex: MetricsExporter) -> dict[str, Any]:
    by_status = {s: c for (s, c) in ex.q(
        "select status, count(*) from crawl_runs group by status order by 2 desc"
    )}
    latest_success = ex.q(
        "select id, started_at, finished_at, stats from crawl_runs "
        "where status='success' order by finished_at desc nulls last, id desc limit 1"
    )
    latest = None
    latest_stats = None
    if latest_success:
        rid, started, finished, stats = latest_success[0]
        latest = {
            "crawl_run_id": rid,
            "started_at": started.isoformat() if started else None,
            "finished_at": finished.isoformat() if finished else None,
        }
        if isinstance(stats, dict):
            # Keep scalar aggregate fields; drop bulky error_details list.
            latest_stats = {k: v for k, v in stats.items() if not isinstance(v, (list, dict))}

    # Aggregate stats across all successful runs for the scalar keys.
    agg_keys = (
        "discovered", "inserted", "updated", "skipped", "backfilled",
        "skills_seen", "skills_inserted", "skills_updated",
        "artifacts_downloaded", "artifacts_skipped", "failures", "errors",
    )
    agg: dict[str, int] = {}
    for (stats,) in ex.q("select stats from crawl_runs where status='success' and stats is not null"):
        if isinstance(stats, dict):
            for k in agg_keys:
                v = stats.get(k)
                if isinstance(v, int):
                    agg[k] = agg.get(k, 0) + v

    # Failure taxonomy from error_details across runs.
    taxonomy: dict[str, int] = {}
    for (stats,) in ex.q("select stats from crawl_runs where stats is not null"):
        if isinstance(stats, dict):
            for err in stats.get("error_details", []) or []:
                msg = (err or {}).get("error", "")
                bucket = classify_error(msg)
                taxonomy[bucket] = taxonomy.get(bucket, 0) + 1

    ex.add_table(
        "crawl_runs_by_status",
        ["status", "count"],
        [[s, c] for s, c in by_status.items()],
    )
    if taxonomy:
        ex.add_table(
            "crawl_failure_taxonomy",
            ["error_class", "count"],
            sorted([[k, v] for k, v in taxonomy.items()], key=lambda r: -r[1]),
        )

    return {
        "runs_by_status": by_status,
        "latest_successful_run": latest,
        "latest_run_stats": latest_stats,
        "aggregate_stats_across_successful_runs": agg,
        "failure_taxonomy": taxonomy,
    }


def classify_error(msg: str) -> str:
    low = (msg or "").lower()
    if "read timed out" in low or "timeout" in low:
        return "http_timeout"
    if "nul (0x00)" in low or "nul character" in low:
        return "nul_byte_in_content"
    if "connection" in low:
        return "connection_error"
    if "404" in low or "not found" in low:
        return "not_found"
    if not low:
        return "unspecified"
    return "other"


def compute_ecosystem_dynamics(ex: MetricsExporter) -> dict[str, Any]:
    total_pairs = ex.scalar(
        "select count(*) from (select distinct source_id, version from skills) z"
    )
    mutated_pairs = ex.scalar(
        "select count(*) from ("
        "  select source_id, version from skills "
        "  group by source_id, version having count(distinct artifact_hash) > 1"
        ") z"
    )

    top_mutated = ex.q(
        "select source_id, version, count(distinct artifact_hash) as hashes, "
        "       min(first_seen_at) as first_seen, max(last_seen_at) as last_seen "
        "from skills group by source_id, version "
        "having count(distinct artifact_hash) > 1 "
        "order by hashes desc, source_id asc limit 20"
    )
    mutation_examples = [
        {
            "source_id": sid,
            "version": ver,
            "artifact_hash_count": hashes,
            "first_seen_at": fs.isoformat() if fs else None,
            "last_seen_at": ls.isoformat() if ls else None,
        }
        for (sid, ver, hashes, fs, ls) in top_mutated
    ]
    ex.add_table(
        "top_mutated_versions",
        ["source_id", "version", "artifact_hash_count", "first_seen_at", "last_seen_at"],
        [[m["source_id"], m["version"], m["artifact_hash_count"],
          m["first_seen_at"], m["last_seen_at"]] for m in mutation_examples],
    )

    # Skills absent from the latest successful crawl.
    latest_crawl_id = ex.scalar(
        "select id from crawl_runs where status='success' "
        "order by finished_at desc nulls last, id desc limit 1"
    )
    distinct_skills = ex.scalar("select count(distinct source_id) from skills")
    absent = None
    if latest_crawl_id is not None:
        # A skill is "present" in the latest crawl if any of its rows has
        # last_crawl_run_id == latest_crawl_id.
        present = ex.scalar(
            "select count(distinct source_id) from skills "
            "where last_crawl_run_id = :rid",
            rid=latest_crawl_id,
        )
        absent = frac(distinct_skills - present, distinct_skills)
        absent["latest_crawl_run_id"] = latest_crawl_id
        absent["present_in_latest_crawl"] = present

    # Versions-per-skill distribution.
    versions_per_skill = [r[0] for r in ex.q(
        "select count(distinct version) from skills group by source_id"
    )]
    rows_per_skill = [r[0] for r in ex.q(
        "select count(*) from skills group by source_id"
    )]

    def bucketize(values: list[int]) -> dict[str, int]:
        buckets = {"1": 0, "2": 0, "3": 0, "4-5": 0, "6+": 0}
        for v in values:
            if v == 1:
                buckets["1"] += 1
            elif v == 2:
                buckets["2"] += 1
            elif v == 3:
                buckets["3"] += 1
            elif v <= 5:
                buckets["4-5"] += 1
            else:
                buckets["6+"] += 1
        return buckets

    vps_buckets = bucketize(versions_per_skill)
    ex.add_table(
        "versions_per_skill_buckets",
        ["versions", "skill_count"],
        [[k, v] for k, v in vps_buckets.items()],
    )

    return {
        "mutation": {
            **frac(mutated_pairs, total_pairs),
            "definition": (
                "(source_id, version) pairs mapping to >1 artifact_hash. "
                "artifact_hash excludes collector provenance (_detail.json), so this "
                "counts genuine re-publishes of different content under the same "
                "version — not volatile API-counter churn."
            ),
        },
        "mutation_examples_top20": mutation_examples,
        "skills_absent_from_latest_successful_crawl": absent,
        "versions_per_skill": {
            "distribution": distribution([float(v) for v in versions_per_skill]),
            "buckets": vps_buckets,
        },
        "snapshot_rows_per_skill": {
            "distribution": distribution([float(v) for v in rows_per_skill]),
        },
    }


def latest_result_rows(ex: MetricsExporter, run_id: int) -> list[dict[str, Any]]:
    """
    One row per distinct skill: the latest successful result from the pinned
    analysis run, attached to that skill's latest snapshot.

    Returns per-result dicts with the scalar signals needed for population,
    anatomy, risk and co-occurrence metrics (single DB pass). Indicator counts
    for all 14 v4 categories are aliased by their category name.
    """
    ind_cols = ",\n            ".join(
        f"(r.result_json#>>'{{indicators,{cat},count}}')::int as \"{cat}\""
        for cat in CANONICAL_CATEGORIES
    )
    sql = f"""
    with latest_snap as (
        select distinct on (source_id) id, source_id
        from skills
        order by source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id)
            r.skill_id,
            r.risk_level,
            (r.result_json->>'file_count')::int                              as file_count,
            (r.result_json->'artifact'->>'downloaded_bytes')::bigint         as bytes,
            (r.result_json->'important_files'->>'SKILL.md')::bool            as has_skill_md,
            (r.result_json->'important_files'->>'_meta.json')::bool         as has_meta,
            (r.result_json->'important_files'->>'README.md')::bool          as has_readme,
            (r.result_json->'important_files'->>'package.json')::bool       as has_pkg,
            (r.result_json->'important_files'->>'requirements.txt')::bool   as has_reqs,
            (r.result_json->'extension_counts') ?| :code_exts                as code_bearing,
            (r.result_json->'env_var_references'->>'count')::int             as env_count,
            (r.result_json->'external_urls'->>'count')::int                  as url_count,
            jsonb_array_length(coalesce(r.result_json->'external_urls'->'domains','[]')) as domain_count,
            {ind_cols}
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id and r.status = 'success'
        order by r.skill_id, r.created_at desc, r.id desc
    )
    select * from res
    """
    rows = ex.conn.execute(
        text(sql), {"run_id": run_id, "code_exts": list(CODE_EXTENSIONS)}
    ).mappings().all()
    return [dict(r) for r in rows]


def compute_population_and_anatomy(ex: MetricsExporter, run_id: int) -> dict[str, Any]:
    rows = latest_result_rows(ex, run_id)
    denom = len(rows)
    if denom == 0:
        return {"denominator_latest_result_per_latest_snapshot": 0,
                "note": "No analysis results for the pinned run."}

    code_bearing = sum(1 for r in rows if r["code_bearing"])
    prompt_only = denom - code_bearing
    file_counts = [float(r["file_count"]) for r in rows if r["file_count"] is not None]
    byte_sizes = [float(r["bytes"]) for r in rows if r["bytes"] is not None]

    important = {
        "SKILL.md": sum(1 for r in rows if r["has_skill_md"]),
        "_meta.json": sum(1 for r in rows if r["has_meta"]),
        "README.md": sum(1 for r in rows if r["has_readme"]),
        "package.json": sum(1 for r in rows if r["has_pkg"]),
        "requirements.txt": sum(1 for r in rows if r["has_reqs"]),
    }
    important_rates = {k: frac(v, denom) for k, v in important.items()}
    manifest_present = sum(1 for r in rows if r["has_pkg"] or r["has_reqs"])

    # Top extensions over the same selection set.
    top_ext = ex.q(
        """
        with latest_snap as (
            select distinct on (source_id) id from skills
            order by source_id, last_seen_at desc, id desc
        ),
        res as (
            select distinct on (r.skill_id) r.skill_id, r.result_json
            from analysis_results r
            join latest_snap ls on ls.id = r.skill_id
            where r.analysis_run_id = :run_id and r.status='success'
            order by r.skill_id, r.created_at desc, r.id desc
        )
        select e.key as ext, sum(e.value::int) as n
        from res, lateral jsonb_each_text(res.result_json->'extension_counts') as e(key, value)
        group by e.key order by n desc limit 25
        """,
        run_id=run_id,
    )
    ex.add_table("top_file_extensions", ["extension", "count"], [[k, v] for k, v in top_ext])

    # License / tags from skills.metadata + license column over latest snapshot.
    licenses = ex.q(
        """
        with latest_snap as (
            select distinct on (source_id) license from skills
            order by source_id, last_seen_at desc, id desc
        )
        select coalesce(nullif(trim(license), ''), '(none)') as lic, count(*)
        from latest_snap group by 1 order by 2 desc limit 15
        """
    )
    ex.add_table("top_licenses", ["license", "skill_count"], [[l, c] for l, c in licenses])

    ex.add_table(
        "important_file_presence",
        ["file", "present", "denominator", "pct"],
        [[k, v["numerator"], v["denominator"], v["pct"]] for k, v in important_rates.items()],
    )

    return {
        "denominator_latest_result_per_latest_snapshot": denom,
        "prompt_only_vs_code_bearing": {
            "code_bearing": frac(code_bearing, denom),
            "prompt_only": frac(prompt_only, denom),
            "definition": f"code-bearing = inventory contains any of {list(CODE_EXTENSIONS)}",
        },
        "file_count_distribution": distribution(file_counts),
        "artifact_size_bytes_distribution": distribution(byte_sizes),
        "important_file_presence_rates": important_rates,
        "manifest_present": frac(manifest_present, denom),
        "top_file_extensions": [{"extension": k, "count": v} for k, v in top_ext],
        "top_licenses": [{"license": l, "skill_count": c} for l, c in licenses],
    }


def compute_analysis_coverage(ex: MetricsExporter, run_id: int, version: str) -> dict[str, Any]:
    latest_snap_total = ex.scalar(
        "select count(*) from (select distinct on (source_id) id from skills "
        "order by source_id, last_seen_at desc, id desc) z"
    )
    analyzed = ex.scalar(
        """
        with latest_snap as (
            select distinct on (source_id) id from skills
            order by source_id, last_seen_at desc, id desc
        )
        select count(distinct r.skill_id)
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id and r.status='success'
        """,
        run_id=run_id,
    )
    failures_by_status = {
        s: c for (s, c) in ex.q(
            "select status, count(*) from analysis_results "
            "where analysis_run_id=:run_id group by status order by 2 desc",
            run_id=run_id,
        )
    }
    # Failure reasons from result_json error_type for failed results.
    fail_reasons = {
        (et or "(unknown)"): c for (et, c) in ex.q(
            "select result_json->>'error_type' as et, count(*) "
            "from analysis_results where analysis_run_id=:run_id and status='failed' "
            "group by 1 order by 2 desc",
            run_id=run_id,
        )
    }
    if fail_reasons:
        ex.add_table("analysis_failure_reasons", ["error_type", "count"],
                     [[k, v] for k, v in fail_reasons.items()])

    return {
        "selected_analyzer_version": version,
        "selected_analysis_run_id": run_id,
        "coverage_latest_snapshots": {
            **frac(analyzed or 0, latest_snap_total or 0),
            "definition": "distinct latest snapshots with a successful pinned-run result.",
        },
        "results_by_status_selected_run": failures_by_status,
        "failure_reasons_selected_run": fail_reasons,
    }


def compute_capability_risk(ex: MetricsExporter, run_id: int) -> dict[str, Any]:
    rows = latest_result_rows(ex, run_id)
    denom = len(rows)
    if denom == 0:
        return {"denominator": 0, "note": "No analysis results for the pinned run."}

    def active(r: dict[str, Any], cat: str) -> bool:
        return (r.get(cat) or 0) > 0

    risk_dist = {}
    for r in rows:
        risk_dist[r["risk_level"]] = risk_dist.get(r["risk_level"], 0) + 1
    ex.add_table("risk_level_distribution", ["risk_level", "count", "denominator", "pct"],
                 [[k, v, denom, round(100.0 * v / denom, 2)] for k, v in
                  sorted(risk_dist.items(), key=lambda x: -x[1])])

    prevalence = {cat: frac(sum(1 for r in rows if active(r, cat)), denom)
                  for cat in CANONICAL_CATEGORIES}
    ex.add_table("category_prevalence", ["category", "skills_with_category", "denominator", "pct"],
                 [[cat, prevalence[cat]["numerator"], denom, prevalence[cat]["pct"]]
                  for cat in CANONICAL_CATEGORIES])

    # Requested co-occurrence pairs.
    cooccur = {}
    for a, b in COOCCURRENCE_PAIRS:
        n = sum(1 for r in rows if active(r, a) and active(r, b))
        cooccur[f"{a}+{b}"] = frac(n, denom)

    # Full 7x7 co-occurrence matrix (counts).
    matrix = {a: {} for a in CANONICAL_CATEGORIES}
    for a in CANONICAL_CATEGORIES:
        for b in CANONICAL_CATEGORIES:
            matrix[a][b] = sum(1 for r in rows if active(r, a) and active(r, b))
    ex.add_table(
        "cooccurrence_matrix",
        ["category"] + list(CANONICAL_CATEGORIES),
        [[a] + [matrix[a][b] for b in CANONICAL_CATEGORIES] for a in CANONICAL_CATEGORIES],
    )

    # Install-script prevalence: dependency_or_install_script active.
    install_prev = frac(sum(1 for r in rows if active(r, "dependency_or_install_script")), denom)

    # Env var and URL evidence caps note: counts are capped per-result by analyzer.
    env_present = frac(sum(1 for r in rows if (r["env_count"] or 0) > 0), denom)
    url_present = frac(sum(1 for r in rows if (r["url_count"] or 0) > 0), denom)

    out = {
        "denominator_latest_result_per_latest_snapshot": denom,
        "risk_level_distribution": {k: frac(v, denom) for k, v in risk_dist.items()},
        "category_prevalence": prevalence,
        "requested_cooccurrence": cooccur,
        "cooccurrence_matrix_counts": matrix,
        "install_script_prevalence": install_prev,
        "env_var_reference_present": env_present,
        "external_url_present": url_present,
        "label": "STATIC CAPABILITY/RISK SIGNALS (not maliciousness).",
    }

    # Heavier aggregations: top indicators, top domains, top env vars, top deps.
    ex.guard("capability_top_indicators", lambda: top_indicators(ex, run_id))
    ex.guard("capability_top_domains", lambda: top_domains(ex, run_id))
    ex.guard("capability_top_env_vars", lambda: top_env_vars(ex, run_id))
    ex.guard("capability_top_dependencies", lambda: top_dependencies(ex, run_id))
    return out


def _latest_res_cte(ver_param: str = ":run_id") -> str:
    return f"""
    with latest_snap as (
        select distinct on (source_id) id from skills
        order by source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id) r.skill_id, r.result_json
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = {ver_param} and r.status='success'
        order by r.skill_id, r.created_at desc, r.id desc
    )
    """


def top_indicators(ex: MetricsExporter, run_id: int) -> list[dict[str, Any]]:
    sql = _latest_res_cte(":run_id") + """
    select ev->>'indicator' as indicator, count(*) as n
    from res,
         lateral jsonb_each(res.result_json->'indicators') as cat(name, data),
         lateral jsonb_array_elements(coalesce(data->'evidence','[]')) as ev
    where ev ? 'indicator'
    group by 1 order by n desc limit 25
    """
    rows = ex.q(sql, run_id=run_id)
    ex.add_table("top_indicators", ["indicator", "evidence_count"], [[i, n] for i, n in rows])
    return [{"indicator": i, "evidence_count": n} for i, n in rows]


def top_domains(ex: MetricsExporter, run_id: int) -> list[dict[str, Any]]:
    sql = _latest_res_cte(":run_id") + """
    select d as domain, count(*) as n
    from res,
         lateral jsonb_array_elements_text(coalesce(res.result_json->'external_urls'->'domains','[]')) as d
    where d <> ''
    group by 1 order by n desc limit 25
    """
    rows = ex.q(sql, run_id=run_id)
    ex.add_table("top_external_domains", ["domain", "skills_count"], [[d, n] for d, n in rows])
    return [{"domain": d, "skills_count": n} for d, n in rows]


def top_env_vars(ex: MetricsExporter, run_id: int) -> list[dict[str, Any]]:
    sql = _latest_res_cte(":run_id") + """
    select v as env_var, count(*) as n
    from res,
         lateral jsonb_array_elements_text(coalesce(res.result_json->'env_var_references'->'unique_names','[]')) as v
    group by 1 order by n desc limit 25
    """
    rows = ex.q(sql, run_id=run_id)
    ex.add_table("top_env_vars", ["env_var", "skills_count"], [[v, n] for v, n in rows])
    return [{"env_var": v, "skills_count": n} for v, n in rows]


def top_dependencies(ex: MetricsExporter, run_id: int) -> list[dict[str, Any]]:
    sql = _latest_res_cte(":run_id") + """
    select dep, count(*) as n from (
        select d as dep from res,
             lateral jsonb_array_elements_text(
                 coalesce(res.result_json->'parsed_files'->'package_json'->'dependencies','[]')) as d
        union all
        select p as dep from res,
             lateral jsonb_array_elements_text(
                 coalesce(res.result_json->'parsed_files'->'requirements_txt'->'packages','[]')) as p
    ) z where dep <> '' group by dep order by n desc limit 25
    """
    rows = ex.q(sql, run_id=run_id)
    ex.add_table("top_dependencies", ["dependency", "skills_count"], [[d, n] for d, n in rows])
    return [{"dependency": d, "skills_count": n} for d, n in rows]


# --------------------------------------------------------------------------- #
# Output rendering
# --------------------------------------------------------------------------- #


def interesting_breakdowns() -> list[str]:
    return [
        "Capability signals split by prompt-only vs code-bearing skills.",
        "Version mutation rate by author (which authors republish the same version).",
        "Mutation rate by risk level (does risk drift across same-version hashes?).",
        "Removed/delisted skills (absent from latest crawl) by capability profile.",
        "Authorship concentration: top authors by skill count and mass-published clusters.",
        "Dependency / install-script prevalence by primary language.",
        "External service (domain) usage by skill category or tag.",
        "Same-version mutation paired with risk drift between consecutive hashes.",
    ]


def caveats(provenance: dict[str, Any]) -> list[str]:
    pre_fix = provenance.get("detail_json_fix", {}).get(
        "analysis_metrics_are_pre_detail_json_fix", True)
    notes = [
        "Capability/risk numbers are STATIC capability signals, NOT maliciousness "
        "judgments. A 'high' risk_level only means risky indicators co-occur.",
    ]
    if pre_fix:
        notes.append(
            "PRELIMINARY ANALYSIS METRICS: the selected analyzer version predates the "
            "_detail.json exclusion fix (no v3 results in the database). Crawler-added "
            "_detail.json content (marketplace descriptions, listing URLs, schema terms "
            "like 'token'/'secret') is still mixed into capability/risk signals. This "
            "inflates secret_handling, network_access, external domains, and risk_level. "
            "Re-analyze under analyzer v3 before using these for the paper."
        )
        notes.append(
            "Extension counts from the pre-fix version over-count '.json' by roughly one "
            "per skill because _detail.json is included in the inventory."
        )
    notes += [
        "URL and environment-variable evidence are capped per result by the analyzer "
        "(MAX_URL_EVIDENCE / MAX_ENV_EVIDENCE = 75). Per-skill 'present' rates are "
        "reliable; raw evidence totals are lower bounds.",
        "The database is live and being crawled. All metrics are read inside a single "
        "REPEATABLE READ snapshot, so counts are internally consistent but may differ "
        "from a later snapshot.",
        "skills.metadata.tags here encodes a version pointer (e.g. {\"latest\": \"1.0.2\"}), "
        "not topical tags; topical categorization is not yet available.",
    ]
    return notes


def render_markdown(metrics: dict[str, Any], provenance: dict[str, Any]) -> str:
    L: list[str] = []
    w = L.append

    w("# OpenClaw / ClawHub — Initial Metrics Pack")
    w("")
    w("> Generated, non-committed metrics pack for the measurement paper. "
      "All analysis/capability numbers are static signals; see Caveats.")
    w("")

    # Provenance
    w("## Provenance")
    w("")
    w(f"- Generated (UTC): `{provenance['generated_at_utc']}`")
    w(f"- Git commit: `{provenance['git_commit']}`")
    w(f"- Database: `{provenance['database_name']}`")
    w(f"- Read-only transaction: `{provenance['read_only_transaction']}`")
    w(f"- Selected analyzer version (analysis metrics): "
      f"`{provenance['selected_analyzer_version']}`")
    w("- Analyzer versions present (successful results):")
    for v in provenance["analyzer_versions_present"]:
        w(f"  - `{v['analyzer_name']} v{v['analyzer_version']}`: "
          f"{v['successful_results']} successful results")
    fix = provenance["detail_json_fix"]
    w(f"- `_detail.json` fix applied to analysis metrics: "
      f"**{'NO (pre-fix, preliminary)' if fix['analysis_metrics_are_pre_detail_json_fix'] else 'yes'}**")
    w("- Selection policy:")
    for k, v in provenance["selection_policy"].items():
        w(f"  - **{k}**: {v}")
    if provenance["failed_metrics"]:
        w(f"- Failed metrics: {len(provenance['failed_metrics'])} "
          f"(see JSON `provenance.failed_metrics`)")
    else:
        w("- Failed metrics: none")
    w("")

    # 1. Dataset Snapshot
    d = metrics.get("dataset_overview", {})
    w("## 1. Dataset Snapshot")
    w("")
    w(f"_Note: {d.get('denominators_are_distinct','')}_")
    w("")
    w("| Denominator | Value |")
    w("| --- | --- |")
    w(f"| Total rows (artifact snapshots) | {d.get('total_rows_snapshots')} |")
    w(f"| Distinct skills (`source_id`) | {d.get('distinct_skills_source_id')} |")
    w(f"| Distinct `(source_id, version)` pairs | {d.get('distinct_skill_version_pairs')} |")
    w(f"| Distinct artifact hashes | {d.get('distinct_artifact_hashes')} |")
    w(f"| Distinct authors | {d.get('distinct_authors')} |")
    w(f"| Rows with null author | {d.get('rows_with_null_author')} |")
    win = d.get("observation_window", {})
    w(f"| Observation window | {win.get('first_seen_min')} → {win.get('last_seen_max')} |")
    w(f"| Rows by source | {d.get('rows_by_source')} |")
    w("")

    # 2. Crawler and Collection Metrics
    c = metrics.get("crawler_metrics", {})
    w("## 2. Crawler and Collection Metrics")
    w("")
    w(f"- Crawl runs by status: `{c.get('runs_by_status')}`")
    ls = c.get("latest_successful_run")
    if ls:
        w(f"- Latest successful crawl run: #{ls['crawl_run_id']} "
          f"(finished `{ls['finished_at']}`)")
    w(f"- Latest run stats: `{c.get('latest_run_stats')}`")
    w(f"- Aggregate stats across successful runs: `{c.get('aggregate_stats_across_successful_runs')}`")
    if c.get("failure_taxonomy"):
        w(f"- Failure taxonomy: `{c.get('failure_taxonomy')}`")
    w("")

    # 3. Ecosystem Dynamics and Version Mutation
    e = metrics.get("ecosystem_dynamics", {})
    w("## 3. Ecosystem Dynamics and Version Mutation")
    w("")
    mut = e.get("mutation", {})
    w(f"- Mutated `(source_id, version)` pairs (>1 artifact hash): "
      f"**{mut.get('numerator')} / {mut.get('denominator')} "
      f"({mut.get('pct')}%)**")
    absent = e.get("skills_absent_from_latest_successful_crawl")
    if absent:
        w(f"- Skills absent from latest successful crawl (#{absent.get('latest_crawl_run_id')}): "
          f"**{absent.get('numerator')} / {absent.get('denominator')} "
          f"({absent.get('pct')}%)**")
    vps = e.get("versions_per_skill", {})
    w(f"- Versions per skill: {vps.get('distribution')}")
    w(f"- Versions-per-skill buckets: `{vps.get('buckets')}`")
    sps = e.get("snapshot_rows_per_skill", {})
    w(f"- Snapshot rows per skill: {sps.get('distribution')}")
    w("")
    examples = e.get("mutation_examples_top20", [])
    if examples:
        w("Top mutated versions:")
        w("")
        w("| source_id | version | hashes | first_seen | last_seen |")
        w("| --- | --- | --- | --- | --- |")
        for m in examples[:10]:
            w(f"| {m['source_id']} | {m['version']} | {m['artifact_hash_count']} "
              f"| {m['first_seen_at']} | {m['last_seen_at']} |")
        w("")

    # 4. Skill Population and Anatomy
    p = metrics.get("population_anatomy", {})
    w("## 4. Skill Population and Anatomy")
    w("")
    w(f"_Denominator: latest successful analysis result per latest snapshot = "
      f"{p.get('denominator_latest_result_per_latest_snapshot')} skills._")
    w("")
    pc = p.get("prompt_only_vs_code_bearing", {})
    if pc:
        cb, po = pc.get("code_bearing", {}), pc.get("prompt_only", {})
        w(f"- Code-bearing: **{cb.get('numerator')} / {cb.get('denominator')} "
          f"({cb.get('pct')}%)**; Prompt-only: **{po.get('numerator')} / "
          f"{po.get('denominator')} ({po.get('pct')}%)**")
    w(f"- File-count distribution: {p.get('file_count_distribution')}")
    w(f"- Artifact size (bytes) distribution: {p.get('artifact_size_bytes_distribution')}")
    man = p.get("manifest_present", {})
    if man:
        w(f"- Manifest present (package.json or requirements.txt): "
          f"{man.get('numerator')} / {man.get('denominator')} ({man.get('pct')}%)")
    w("")
    ifr = p.get("important_file_presence_rates", {})
    if ifr:
        w("Important file presence:")
        w("")
        w("| File | Present | Denominator | % |")
        w("| --- | --- | --- | --- |")
        for f in IMPORTANT_FILES:
            r = ifr.get(f, {})
            w(f"| `{f}` | {r.get('numerator')} | {r.get('denominator')} | {r.get('pct')} |")
        w("")
    te = p.get("top_file_extensions", [])
    if te:
        w("Top file extensions (selected set): " +
          ", ".join(f"`{r['extension']}`={r['count']}" for r in te[:12]))
        w("")
    tl = p.get("top_licenses", [])
    if tl:
        w("Top licenses: " + ", ".join(f"`{r['license']}`={r['skill_count']}" for r in tl[:10]))
        w("")

    # 5. Analysis Coverage
    ac = metrics.get("analysis_coverage", {})
    w("## 5. Analysis Coverage")
    w("")
    cov = ac.get("coverage_latest_snapshots", {})
    w(f"- Selected analyzer version: `{ac.get('selected_analyzer_version')}`")
    w(f"- Coverage of latest snapshots: **{cov.get('numerator')} / {cov.get('denominator')} "
      f"({cov.get('pct')}%)**")
    w(f"- Results by status (selected version): `{ac.get('results_by_status_selected_version')}`")
    if ac.get("failure_reasons_selected_version"):
        w(f"- Failure reasons: `{ac.get('failure_reasons_selected_version')}`")
    w("")

    # 6. Capability and Risk Signals
    cap = metrics.get("capability_risk", {})
    w("## 6. Capability and Risk Signals")
    w("")
    w(f"_{cap.get('label','')}_")
    w("")
    denom = cap.get("denominator_latest_result_per_latest_snapshot")
    w(f"_Denominator: {denom} skills (latest result per latest snapshot)._")
    w("")
    rl = cap.get("risk_level_distribution", {})
    if rl:
        w("Risk level distribution:")
        w("")
        w("| Risk | Count | Denominator | % |")
        w("| --- | --- | --- | --- |")
        for k, v in sorted(rl.items(), key=lambda x: -x[1]["numerator"]):
            w(f"| {k} | {v.get('numerator')} | {v.get('denominator')} | {v.get('pct')} |")
        w("")
    prev = cap.get("category_prevalence", {})
    if prev:
        w("Per-category prevalence:")
        w("")
        w("| Category | Skills | Denominator | % |")
        w("| --- | --- | --- | --- |")
        for cat in CANONICAL_CATEGORIES:
            r = prev.get(cat, {})
            w(f"| {cat} | {r.get('numerator')} | {r.get('denominator')} | {r.get('pct')} |")
        w("")
    co = cap.get("requested_cooccurrence", {})
    if co:
        w("Requested co-occurrence pairs:")
        w("")
        w("| Pair | Count | Denominator | % |")
        w("| --- | --- | --- | --- |")
        for k, v in co.items():
            w(f"| {k} | {v.get('numerator')} | {v.get('denominator')} | {v.get('pct')} |")
        w("")
    isp = cap.get("install_script_prevalence", {})
    if isp:
        w(f"- Install-script prevalence: {isp.get('numerator')} / {isp.get('denominator')} "
          f"({isp.get('pct')}%)")
    for key, label in (("capability_top_indicators", "Top indicators"),
                       ("capability_top_domains", "Top external domains"),
                       ("capability_top_env_vars", "Top env vars"),
                       ("capability_top_dependencies", "Top dependencies")):
        items = metrics.get(key)
        if items:
            head = items[:10]
            first_val = next((k for k in head[0] if k not in ("evidence_count", "skills_count")), None)
            cnt_key = "evidence_count" if "evidence_count" in head[0] else "skills_count"
            w(f"- {label}: " + ", ".join(f"`{it[first_val]}`={it[cnt_key]}" for it in head))
    w("")

    # 7. Interesting Breakdowns to Explore Next
    w("## 7. Interesting Breakdowns to Explore Next")
    w("")
    for item in metrics.get("interesting_breakdowns", []):
        w(f"- {item}")
    w("")

    # 8. Caveats and Measurement Notes
    w("## 8. Caveats and Measurement Notes")
    w("")
    for note in metrics.get("caveats", []):
        w(f"- {note}")
    w("")

    return "\n".join(L)


def write_csv_tables(tables_dir: Path, tables: dict[str, tuple[list[str], list[list[Any]]]]) -> list[Path]:
    tables_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (header, rows) in tables.items():
        path = tables_dir / f"{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(rows)
        written.append(path)
    return written


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only paper metrics exporter")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="Output directory (default: %(default)s)")
    parser.add_argument("--analyzer-name", default="static",
                        help="Analyzer name for capability metrics (default: static)")
    parser.add_argument("--analyzer-version", default=None,
                        help="Restrict analysis-run selection to this version")
    parser.add_argument("--analysis-run-id", type=int, default=None,
                        help="Pin capability metrics to this analysis_run_id "
                             "(default: latest successful run for the analyzer name). "
                             "Prevents pooling runs that share a (name, version).")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    tables_dir = out_dir / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)

    settings = get_settings()
    engine = build_engine(settings)

    with engine.connect() as conn:
        # First statement in the transaction: pin a consistent snapshot AND make
        # the transaction read-only as defense-in-depth against any accidental write.
        conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        conn.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))

        ex = MetricsExporter(conn)
        run = select_analysis_run(
            ex, args.analyzer_name, args.analyzer_version, args.analysis_run_id)
        if run is None:
            print("No successful analysis run found; capability metrics will be empty.",
                  file=sys.stderr)
            run_id, version = None, args.analyzer_version
        else:
            run_id, version = run["id"], run["analyzer_version"]
            print(f"Capability metrics from analysis run #{run_id} "
                  f"({run['analyzer_name']} v{version}).")

        ex.guard("dataset_overview", lambda: compute_dataset_overview(ex))
        ex.guard("crawler_metrics", lambda: compute_crawler_metrics(ex))
        ex.guard("ecosystem_dynamics", lambda: compute_ecosystem_dynamics(ex))
        if run_id is not None:
            ex.guard("population_anatomy", lambda: compute_population_and_anatomy(ex, run_id))
            ex.guard("analysis_coverage", lambda: compute_analysis_coverage(ex, run_id, version))
            ex.guard("capability_risk", lambda: compute_capability_risk(ex, run_id))

        provenance = ex.provenance(version)
        provenance["selected_analysis_run_id"] = run_id
        ex.metrics["interesting_breakdowns"] = interesting_breakdowns()
        ex.metrics["caveats"] = caveats(provenance)
        ex.metrics["provenance"] = provenance

        # Render outputs.
        md = render_markdown(ex.metrics, provenance)
        (out_dir / "initial_metrics.md").write_text(md, encoding="utf-8")
        (out_dir / "initial_metrics.json").write_text(
            json.dumps(ex.metrics, indent=2, default=str), encoding="utf-8"
        )
        csv_paths = write_csv_tables(tables_dir, ex.tables)

    # Roll-up to stdout.
    print(f"Output directory: {out_dir}")
    print(f"  - {out_dir / 'initial_metrics.md'}")
    print(f"  - {out_dir / 'initial_metrics.json'}")
    for p in csv_paths:
        print(f"  - {p}")
    if ex.failed_metrics:
        print(f"\nFailed metrics ({len(ex.failed_metrics)}):")
        for f in ex.failed_metrics:
            print(f"  - {f['metric']}: {f['error']}")
    else:
        print("\nFailed metrics: none")
    print(f"\nSelected analyzer version: {version} "
          f"({'PRE _detail.json fix (preliminary)' if (version is None or _lt3(version)) else 'post-fix'})")
    return 0


def _lt3(version: str) -> bool:
    try:
        return int(version) < 3
    except (TypeError, ValueError):
        return True


if __name__ == "__main__":
    raise SystemExit(main())
