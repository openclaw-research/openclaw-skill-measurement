"""
Read-only removed-skills metrics exporter for the OpenClaw/ClawHub measurement paper.

Research question: what kinds of skills get removed from ClawHub? Are removed
skills different from skills that remain available — in anatomy, authorship,
versioning, dependencies, or capability/risk signals?

Everything here is computed for the REMOVED population, with retained-skill
columns included only where the contrast helps interpretation. General
population metrics live in scripts/export_paper_metrics.py and are not
recomputed here.

Removed-skill definition (unit of removal: source_id / slug)
------------------------------------------------------------
Let R be the reference run: a successful crawl run for the source whose
catalog walk is believed complete, chosen by the coverage rule below (or
pinned with --reference-run-id). 'partial_success' and 'failed' runs are
never used as the absence reference because their listing walk may be
incomplete.

A skill (distinct source_id) is REMOVED iff:
  1. it has at least one row in `skills` for the source (ever seen), and
  2. max(last_crawl_run_id) over all of its rows is < R.id, i.e. it was not
     observed by R **or any later run** (later partial/failed runs still
     provide positive presence evidence, because per-skill touches happen
     while a run executes, before its final status is known), and
  3. it is not listed in R.stats.error_details — those skills WERE discovered
     by R's listing walk (so they were present on the registry) but their
     per-skill processing failed, which leaves last_crawl_run_id un-touched.
     They are classified as present_via_error_listing, not removed.

Presence evidence is deliberately asymmetric: ANY run seeing a skill proves
presence; only a COMPLETE successful run's silence proves absence.

Reference-run selection (coverage rule + operator confirmation)
----------------------------------------------------------------
status='success' alone does not prove a complete catalog walk: a truncated
listing (premature end-of-catalog cursor) is only logged by the crawler —
the run still finishes as 'success' and nothing lands in stats. The
reference run is therefore selected by a coverage rule over attempted
counts (skills_seen + discovery_errors):

  Among the --coverage-window most recent successful runs for the source
  that recorded an attempted count, choose the NEWEST run attempting at
  least --min-coverage-pct percent (default 80) of the window maximum.
  The window maximum itself satisfies any threshold <= 100%, so a counted
  run is always selected; the rule's job is to skip recent truncated walks,
  not to detect that ALL recent walks are truncated. For that blind spot the
  selection also reports the benchmark as a percentage of the all-time
  counted maximum — a low value means the catalog genuinely shrank OR every
  recent walk is truncated, and only the operator can tell which. (With a
  threshold above 100%, or when no counted run exists, a defensive fallback
  is proposed and is refused in non-interactive use unless --yes or
  --reference-run-id resolves it.)

The window is deliberately short (default 5 counted runs): a longer window
is stricter against truncated walks but keeps rejecting complete walks for
weeks after the registry genuinely shrinks (as in the 2026-06 purge wave,
which cut the catalog by ~25%); a shorter window adapts faster but could
normalise a persistently truncated crawler. Selection is therefore shown to
the operator before anything is computed: unless --yes is passed or the run
id was pinned, the script prints the candidate table and asks to confirm
the selection, type an alternative run id, or abort.

Two crawler behaviours bound the accuracy of absence evidence and are
measured and reported in the sanity block:
  - discovery_errors: per-slug detail-fetch failures inside discover() are
    counted in run stats but the failing slugs are NOT recorded, so up to
    that many skills classified as removed may actually have been listed by
    the reference run (unidentifiable individually).
  - the one-run-back coverage-drop check is retained for the chosen
    reference: a >10% attempted-count drop vs the previous completed run is
    flagged in the caveats.

Reappearance (disappeared then returned) is estimated from observation gaps:
a skill whose earliest activity on a newer snapshot row starts more than
--reappear-gap-days after all previous rows stopped being touched, with at
least one successful crawl run finishing inside the gap (so crawler downtime
is not mistaken for delisting). This is a LOWER BOUND: a skill that is
delisted and later relisted under the same (version, hash) touches its old
row again, which overwrites last_seen_at and erases the gap.

Analyzer identity
-----------------
Anatomy and capability/risk metrics are sourced from exactly ONE analysis run,
pinned by analysis_run_id (default: the latest successful analysis_runs row for
--analyzer-name, optionally narrowed by --analyzer-version; override with
--analysis-run-id). Pinning to a run — not just (analyzer_name, analyzer_version)
— is required because a single version string can span multiple runs: e.g.
static v4 covers both a contaminated run over the doubled corpus and the later
clean re-run over the repaired corpus. Filtering by version alone would pool
both; filtering by run_id keeps them separate and the metrics reproducible.

Safety
------
Strictly read-only: a single REPEATABLE READ, READ ONLY transaction is used
for all queries, so the export sees one consistent snapshot and cannot modify
the database. Nothing is written to S3 or to any table. Safe to rerun.

Usage:
    venv/bin/python scripts/export_removed_skill_metrics.py --help
    venv/bin/python scripts/export_removed_skill_metrics.py          # interactive confirm
    venv/bin/python scripts/export_removed_skill_metrics.py --yes    # accept selection
    venv/bin/python scripts/export_removed_skill_metrics.py --reference-run-id 49
    venv/bin/python scripts/export_removed_skill_metrics.py --analysis-run-id 71 --yes
    venv/bin/python scripts/export_removed_skill_metrics.py \
        --min-coverage-pct 80 --coverage-window 5 \
        --out-dir ../paper-openclaw-security/results/metrics/2026-07-removed-skills

Outputs (following the results/metrics convention established by the initial
metrics pack): removed_skills_metrics.md, removed_skills_metrics.json, and
tables/removed_*.csv reusable tables.

Every metric block is guarded: a single failing metric is recorded under
provenance.failed_metrics and the export continues.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timedelta, timezone
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
)
from skill_lifecycle_common import (  # noqa: E402
    DEFAULT_COVERAGE_WINDOW,
    DEFAULT_MIN_COVERAGE_PCT,
    DEFAULT_REAPPEAR_GAP_DAYS,
    DEFAULT_SOURCE,
    classify_removed,
    confirm_reference_run,
    error_listed_slugs,
    find_reappearances,
    load_crawl_runs,
    load_latest_snapshots,
    load_mutated_slugs,
    load_per_skill_rollup,
    reference_run_quality,
    select_reference_run,
)


DEFAULT_OUT_DIR = "paper_metrics/removed-skills"
DEFAULT_ANALYZER_NAME = "static"
STATEMENT_TIMEOUT_MS = 180_000

# CANONICAL_CATEGORIES (14, analyzer v4) and CODE_EXTENSIONS come from
# skill_metrics_common so all exporters cover the same capability taxonomy.
IMPORTANT_FILES = ("SKILL.md", "_meta.json", "README.md", "package.json", "requirements.txt")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def frac(numerator: int, denominator: int) -> dict[str, Any]:
    """Return an explicit numerator/denominator/pct triple."""
    pct = round(100.0 * numerator / denominator, 2) if denominator else None
    return {"numerator": numerator, "denominator": denominator, "pct": pct}


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


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def iso_week(dt: datetime) -> str:
    y, w, _ = dt.isocalendar()
    return f"{y}-W{w:02d}"


class Exporter:
    """Query helper + guarded metric registry + CSV table collector."""

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
        try:
            self.metrics[name] = fn()
        except Exception as exc:  # noqa: BLE001 - intentionally capture all
            self.failed_metrics.append(
                {"metric": name, "error": f"{type(exc).__name__}: {exc}",
                 "traceback": traceback.format_exc(limit=3)}
            )

    def add_table(self, name: str, header: list[str], rows: list[list[Any]]) -> None:
        self.tables[name] = (header, rows)


# --------------------------------------------------------------------------- #
# Analysis-result signals (removed vs retained)
# --------------------------------------------------------------------------- #


def select_analysis_run(
    ex: Exporter,
    analyzer_name: str,
    version: str | None = None,
    pinned_run_id: int | None = None,
) -> dict[str, Any] | None:
    """Resolve the single analysis_runs row that capability metrics source from.

    Capability/anatomy metrics are pinned to ONE analysis_run_id so that multiple
    runs sharing the same (analyzer_name, analyzer_version) are never mixed. This
    matters because a contaminated run and a later clean re-run can carry the same
    version string (e.g. static v4 run #70 on the doubled corpus vs run #71 on the
    repaired corpus); filtering by version alone would pool both.

    Default: the most recent successful run for analyzer_name (and version, if
    given). ``pinned_run_id`` overrides selection with an explicit run.
    """
    cols = ("id", "analyzer_name", "analyzer_version", "status", "started_at", "finished_at")
    if pinned_run_id is not None:
        row = ex.q(
            "select id, analyzer_name, analyzer_version, status, started_at, finished_at "
            "from analysis_runs where id = :rid",
            rid=pinned_run_id,
        )
        return dict(zip(cols, row[0])) if row else None

    where = "analyzer_name = :name and status = 'success'"
    params: dict[str, Any] = {"name": analyzer_name}
    if version is not None:
        where += " and analyzer_version = :ver"
        params["ver"] = version
    row = ex.q(
        "select id, analyzer_name, analyzer_version, status, started_at, finished_at "
        f"from analysis_runs where {where} "
        "order by finished_at desc nulls last, id desc limit 1",
        **params,
    )
    return dict(zip(cols, row[0])) if row else None


def load_result_signals(
    ex: Exporter, source: str, run_id: int
) -> dict[str, dict[str, Any]]:
    """Per-skill scalar signals from the latest successful result on the latest snapshot.

    Keyed by source_id. One DB pass for the whole population; the caller splits
    removed vs retained in Python.
    """
    # Indicator count columns for all 14 v4 categories, aliased by category name.
    ind_cols = ",\n            ".join(
        f"(r.result_json#>>'{{indicators,{cat},count}}')::int as \"{cat}\""
        for cat in CANONICAL_CATEGORIES
    )
    sql = f"""
    with latest_snap as (
        select distinct on (source_id) id, source_id
        from skills where source = :src
        order by source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id)
            r.skill_id,
            ls.source_id,
            r.risk_level,
            (r.result_json->>'file_count')::int                              as file_count,
            (r.result_json->'artifact'->>'downloaded_bytes')::bigint         as bytes,
            (r.result_json->'important_files'->>'SKILL.md')::bool            as has_skill_md,
            (r.result_json->'important_files'->>'_meta.json')::bool          as has_meta,
            (r.result_json->'important_files'->>'README.md')::bool           as has_readme,
            (r.result_json->'important_files'->>'package.json')::bool        as has_pkg,
            (r.result_json->'important_files'->>'requirements.txt')::bool    as has_reqs,
            (r.result_json->'extension_counts') ?| :code_exts                as code_bearing,
            (r.result_json->'env_var_references'->>'count')::int             as env_count,
            (r.result_json->'external_urls'->>'count')::int                  as url_count,
            {ind_cols}
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id
          and r.status = 'success'
        order by r.skill_id, r.created_at desc, r.id desc
    )
    select * from res
    """
    rows = ex.conn.execute(
        text(sql),
        {"src": source, "run_id": run_id, "code_exts": list(CODE_EXTENSIONS)},
    ).mappings().all()
    return {r["source_id"]: dict(r) for r in rows}


def signal_profile(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Anatomy + capability/risk profile for one group of per-skill signal rows."""
    denom = len(rows)
    if denom == 0:
        return {"denominator": 0}

    def active(r: dict[str, Any], cat: str) -> bool:
        return (r.get(cat) or 0) > 0

    risk = defaultdict(int)
    for r in rows:
        risk[r["risk_level"]] += 1

    profile = {
        "denominator": denom,
        "code_bearing": frac(sum(1 for r in rows if r["code_bearing"]), denom),
        "file_count_distribution": distribution(
            [float(r["file_count"]) for r in rows if r["file_count"] is not None]),
        "artifact_size_bytes_distribution": distribution(
            [float(r["bytes"]) for r in rows if r["bytes"] is not None]),
        "important_file_presence": {
            "SKILL.md": frac(sum(1 for r in rows if r["has_skill_md"]), denom),
            "_meta.json": frac(sum(1 for r in rows if r["has_meta"]), denom),
            "README.md": frac(sum(1 for r in rows if r["has_readme"]), denom),
            "package.json": frac(sum(1 for r in rows if r["has_pkg"]), denom),
            "requirements.txt": frac(sum(1 for r in rows if r["has_reqs"]), denom),
        },
        "manifest_present": frac(
            sum(1 for r in rows if r["has_pkg"] or r["has_reqs"]), denom),
        "env_var_reference_present": frac(
            sum(1 for r in rows if (r["env_count"] or 0) > 0), denom),
        "external_url_present": frac(
            sum(1 for r in rows if (r["url_count"] or 0) > 0), denom),
        "risk_level_distribution": {k: frac(v, denom) for k, v in sorted(risk.items())},
        "category_prevalence": {
            cat: frac(sum(1 for r in rows if active(r, cat)), denom)
            for cat in CANONICAL_CATEGORIES
        },
        "high_combination_rates": {
            "secret_handling+network_or_exec": frac(
                sum(1 for r in rows if active(r, "secret_handling")
                    and (active(r, "network_access") or active(r, "process_execution"))),
                denom),
            "suspicious_prompting+network_or_exec": frac(
                sum(1 for r in rows if active(r, "suspicious_prompting")
                    and (active(r, "network_access") or active(r, "process_execution"))),
                denom),
        },
    }
    return profile


def _removed_res_cte() -> str:
    """CTE selecting the pinned run's results for removed skills only."""
    return """
    with latest_snap as (
        select distinct on (source_id) id, source_id
        from skills where source = :src
        order by source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id) r.skill_id, r.result_json
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id
          and r.status = 'success'
          and ls.source_id = any(:removed_ids)
        order by r.skill_id, r.created_at desc, r.id desc
    )
    """


def removed_top_indicators(ex: Exporter, source: str, run_id: int,
                           removed_ids: list[str]) -> list[dict[str, Any]]:
    rows = ex.q(
        _removed_res_cte() + """
        select ev->>'indicator' as indicator, count(*) as n
        from res,
             lateral jsonb_each(res.result_json->'indicators') as cat(name, data),
             lateral jsonb_array_elements(coalesce(data->'evidence','[]')) as ev
        where ev ? 'indicator'
        group by 1 order by n desc limit 25
        """,
        src=source, run_id=run_id, removed_ids=removed_ids,
    )
    ex.add_table("removed_top_indicators", ["indicator", "evidence_count"],
                 [[i, n] for i, n in rows])
    return [{"indicator": i, "evidence_count": n} for i, n in rows]


def removed_top_domains(ex: Exporter, source: str, run_id: int,
                        removed_ids: list[str]) -> list[dict[str, Any]]:
    rows = ex.q(
        _removed_res_cte() + """
        select d as domain, count(*) as n
        from res,
             lateral jsonb_array_elements_text(
                 coalesce(res.result_json->'external_urls'->'domains','[]')) as d
        where d <> ''
        group by 1 order by n desc limit 25
        """,
        src=source, run_id=run_id, removed_ids=removed_ids,
    )
    ex.add_table("removed_top_domains", ["domain", "removed_skills_count"],
                 [[d, n] for d, n in rows])
    return [{"domain": d, "removed_skills_count": n} for d, n in rows]


def removed_top_dependencies(ex: Exporter, source: str, run_id: int,
                             removed_ids: list[str]) -> list[dict[str, Any]]:
    rows = ex.q(
        _removed_res_cte() + """
        select dep, count(*) as n from (
            select d as dep from res,
                 lateral jsonb_array_elements_text(
                     coalesce(res.result_json->'parsed_files'->'package_json'->'dependencies','[]')) as d
            union all
            select p as dep from res,
                 lateral jsonb_array_elements_text(
                     coalesce(res.result_json->'parsed_files'->'requirements_txt'->'packages','[]')) as p
        ) z where dep <> '' group by dep order by n desc limit 25
        """,
        src=source, run_id=run_id, removed_ids=removed_ids,
    )
    ex.add_table("removed_top_dependencies", ["dependency", "removed_skills_count"],
                 [[d, n] for d, n in rows])
    return [{"dependency": d, "removed_skills_count": n} for d, n in rows]


# --------------------------------------------------------------------------- #
# Author metrics
# --------------------------------------------------------------------------- #


def author_metrics(
    ex: Exporter,
    latest: dict[str, dict[str, Any]],
    removed: set[str],
    min_skills_for_rate: int = 3,
) -> dict[str, Any]:
    per_author: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "removed": 0})
    for sid, snap in latest.items():
        author = snap["author"] or "(none)"
        per_author[author]["total"] += 1
        if sid in removed:
            per_author[author]["removed"] += 1

    authors_with_removals = {a: v for a, v in per_author.items() if v["removed"] > 0}
    total_removed = sum(v["removed"] for v in authors_with_removals.values())

    ranked = sorted(authors_with_removals.items(), key=lambda kv: -kv[1]["removed"])
    ranked_rows = [
        {"author": a, "removed_skills": v["removed"], "ever_seen_skills": v["total"],
         "removal_rate_pct": round(100.0 * v["removed"] / v["total"], 2)}
        for a, v in ranked
    ]
    top20 = ranked_rows[:20]
    ex.add_table(
        "removed_by_author",
        ["author", "removed_skills", "ever_seen_skills", "removal_rate_pct"],
        [[r["author"], r["removed_skills"], r["ever_seen_skills"], r["removal_rate_pct"]]
         for r in ranked_rows],
    )

    def top_share(k: int) -> dict[str, Any]:
        n = sum(v["removed"] for _, v in ranked[:k])
        return frac(n, total_removed)

    n_authors = len(ranked)
    concentration = {
        "authors_with_removals": n_authors,
        "top_1_author_share": top_share(1) if n_authors else None,
        "top_10_authors_share": top_share(10) if n_authors else None,
        "top_1pct_authors_share": top_share(max(1, n_authors // 100)) if n_authors else None,
        "top_10pct_authors_share": top_share(max(1, n_authors // 10)) if n_authors else None,
    }

    # Full-removal authors: every observed skill of theirs is removed (>=2 skills).
    fully_removed_authors = [
        a for a, v in authors_with_removals.items()
        if v["removed"] == v["total"] and v["total"] >= 2
    ]
    # Clustering: removed skills whose author has >=2 removed skills.
    clustered = sum(v["removed"] for v in authors_with_removals.values() if v["removed"] >= 2)

    high_rate_authors = [
        {"author": a, "removed_skills": v["removed"], "ever_seen_skills": v["total"],
         "removal_rate_pct": round(100.0 * v["removed"] / v["total"], 2)}
        for a, v in ranked
        if v["total"] >= min_skills_for_rate and v["removed"] / v["total"] >= 0.5
    ]

    return {
        "authors_with_at_least_one_removal": n_authors,
        "removed_skills_total": total_removed,
        "top_authors_by_removed_count": top20,
        "concentration": concentration,
        "removed_skills_with_author_having_2plus_removals": frac(clustered, total_removed),
        "authors_with_all_skills_removed_2plus": len(fully_removed_authors),
        "authors_with_ge50pct_removal_rate_min3_skills": high_rate_authors[:20],
        "note": (
            "Author taken from each skill's latest snapshot row. Rates use the "
            "author's ever-seen skill count as denominator."
        ),
    }


# --------------------------------------------------------------------------- #
# Metric blocks
# --------------------------------------------------------------------------- #


def removal_overview(
    ex: Exporter,
    rollup: dict[str, dict[str, Any]],
    latest: dict[str, dict[str, Any]],
    classes: dict[str, Any],
    runs: list[dict[str, Any]],
    ref: dict[str, Any],
) -> dict[str, Any]:
    removed = classes["removed"]
    ever_seen = len(rollup)

    run_finished = {r["id"]: r["finished_at"] for r in runs}
    success_after: list[tuple[datetime, int]] = sorted(
        (r["finished_at"], r["id"]) for r in runs
        if r["status"] == "success" and r["finished_at"]
    )

    def removal_window_end(last_seen: datetime) -> datetime | None:
        for t, _rid in success_after:
            if t > last_seen:
                return t
        return None

    # Removals over time: bucket by ISO week of last observation.
    by_week: dict[str, int] = defaultdict(int)
    by_last_run: dict[int, int] = defaultdict(int)
    lifespans: list[float] = []
    for sid in removed:
        rec = rollup[sid]
        if rec["last_seen"]:
            by_week[iso_week(rec["last_seen"])] += 1
            if rec["first_seen"]:
                lifespans.append(
                    (rec["last_seen"] - rec["first_seen"]).total_seconds() / 86400)
        if rec["max_last_run"] is not None:
            by_last_run[rec["max_last_run"]] += 1

    ex.add_table(
        "removed_by_week",
        ["iso_week_of_last_observation", "removed_skills"],
        [[w, c] for w, c in sorted(by_week.items())],
    )
    ex.add_table(
        "removed_by_last_confirming_run",
        ["crawl_run_id", "run_finished_at", "removed_skills_last_seen_in_run"],
        [[rid, iso(run_finished.get(rid)), c] for rid, c in sorted(by_last_run.items())],
    )

    # Full removed-skill list.
    rows = []
    for sid in sorted(removed):
        rec = rollup[sid]
        snap = latest.get(sid, {})
        rows.append([
            sid, snap.get("name"), snap.get("author"), snap.get("version"),
            iso(rec["first_seen"]), iso(rec["last_seen"]),
            iso(removal_window_end(rec["last_seen"])) if rec["last_seen"] else None,
            rec["versions"], rec["snapshot_rows"], rec["hashes"],
        ])
    ex.add_table(
        "removed_skills",
        ["source_id", "name", "author", "last_seen_version", "first_seen_at",
         "last_seen_at", "removal_detected_by", "versions_observed",
         "snapshot_rows", "distinct_hashes"],
        rows,
    )

    return {
        "unit_of_removal": "source_id (slug)",
        "ever_seen_skills": ever_seen,
        "present_skills": len(classes["present"]),
        "present_via_error_listing": len(classes["present_via_error_listing"]),
        "removed_skills": frac(len(removed), ever_seen),
        "reference_run": {
            "id": ref["id"], "status": ref["status"],
            "finished_at": iso(ref["finished_at"]),
        },
        "removed_lifespan_days_first_to_last_seen": distribution(lifespans),
        "removals_by_iso_week_of_last_observation": dict(sorted(by_week.items())),
    }


def version_artifact_metrics(
    rollup: dict[str, dict[str, Any]],
    removed: set[str],
    mutated_slugs: set[str],
) -> dict[str, Any]:
    def group(sids: set[str]) -> dict[str, Any]:
        recs = [rollup[s] for s in sids]
        denom = len(recs)
        if denom == 0:
            return {"denominator": 0}
        return {
            "denominator": denom,
            "versions_per_skill": distribution([float(r["versions"]) for r in recs]),
            "snapshot_rows_per_skill": distribution(
                [float(r["snapshot_rows"]) for r in recs]),
            "distinct_hashes_per_skill": distribution(
                [float(r["hashes"]) for r in recs]),
            "multi_version_skills": frac(
                sum(1 for r in recs if r["versions"] > 1), denom),
            "same_version_mutated_skills": frac(
                sum(1 for r in recs if r["source_id"] in mutated_slugs), denom),
        }

    retained = set(rollup) - removed
    return {
        "removed": group(removed),
        "retained_for_contrast": group(retained),
        "note": (
            "same_version_mutated = skill has >=1 (version -> multiple artifact "
            "hashes) observation. Retained shown only for contrast."
        ),
    }


def comparison_table(ex: Exporter, removed_profile: dict[str, Any],
                     retained_profile: dict[str, Any],
                     va: dict[str, Any]) -> None:
    """Flat removed-vs-retained CSV for the headline contrasts."""
    def pct(profile: dict[str, Any], *path: str) -> Any:
        node: Any = profile
        for p in path:
            if not isinstance(node, dict) or p not in node:
                return None
            node = node[p]
        return node.get("pct") if isinstance(node, dict) else node

    rows: list[list[Any]] = [
        ["analyzed_denominator", removed_profile.get("denominator"),
         retained_profile.get("denominator")],
        ["code_bearing_pct", pct(removed_profile, "code_bearing"),
         pct(retained_profile, "code_bearing")],
        ["file_count_median",
         (removed_profile.get("file_count_distribution") or {}).get("median"),
         (retained_profile.get("file_count_distribution") or {}).get("median")],
        ["manifest_present_pct", pct(removed_profile, "manifest_present"),
         pct(retained_profile, "manifest_present")],
        ["env_var_reference_present_pct",
         pct(removed_profile, "env_var_reference_present"),
         pct(retained_profile, "env_var_reference_present")],
        ["external_url_present_pct", pct(removed_profile, "external_url_present"),
         pct(retained_profile, "external_url_present")],
    ]
    for f in IMPORTANT_FILES:
        rows.append([f"has_{f}_pct",
                     pct(removed_profile, "important_file_presence", f),
                     pct(retained_profile, "important_file_presence", f)])
    for cat in CANONICAL_CATEGORIES:
        rows.append([f"{cat}_pct",
                     pct(removed_profile, "category_prevalence", cat),
                     pct(retained_profile, "category_prevalence", cat)])
    # Risk tiers, ordered; union across both groups so v4's 'critical'/'none'
    # (and any 'unknown') are always represented, not just a hardcoded subset.
    _RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 5}
    risk_tiers = set(removed_profile.get("risk_level_distribution") or {}) | set(
        retained_profile.get("risk_level_distribution") or {})
    for risk in sorted(risk_tiers, key=lambda r: _RISK_ORDER.get(r, 99)):
        rows.append([f"risk_{risk}_pct",
                     pct(removed_profile, "risk_level_distribution", risk),
                     pct(retained_profile, "risk_level_distribution", risk)])
    for combo in ("secret_handling+network_or_exec", "suspicious_prompting+network_or_exec"):
        rows.append([f"{combo}_pct",
                     pct(removed_profile, "high_combination_rates", combo),
                     pct(retained_profile, "high_combination_rates", combo)])
    rows.append(["multi_version_skills_pct",
                 (va["removed"].get("multi_version_skills") or {}).get("pct"),
                 (va["retained_for_contrast"].get("multi_version_skills") or {}).get("pct")])
    rows.append(["same_version_mutated_pct",
                 (va["removed"].get("same_version_mutated_skills") or {}).get("pct"),
                 (va["retained_for_contrast"].get("same_version_mutated_skills") or {}).get("pct")])

    ex.add_table("removed_vs_retained_comparison",
                 ["metric", "removed", "retained"], rows)


def sanity_checks(
    ex: Exporter,
    runs: list[dict[str, Any]],
    ref: dict[str, Any],
    rollup: dict[str, dict[str, Any]],
    classes: dict[str, Any],
    gaps: list[dict[str, Any]],
    removed_signals: int,
    version: str | None,
    analyzer_name: str,
    analysis_run_id: int | None = None,
) -> dict[str, Any]:
    by_status = defaultdict(int)
    for r in runs:
        by_status[r["status"]] += 1
    removed = classes["removed"]
    present = classes["present"]
    via_error = classes["present_via_error_listing"]
    accounting_ok = len(removed) + len(present) + len(via_error) == len(rollup)
    newer_nonsuccess = [
        {"id": r["id"], "status": r["status"], "finished_at": iso(r["finished_at"])}
        for r in runs if r["id"] > ref["id"]
    ]
    reappeared_ids = {g["source_id"] for g in gaps}
    stub_only_skills = sum(1 for rec in rollup.values() if not rec["has_artifact"])
    stub_only_removed = sum(
        1 for sid in removed if not rollup[sid]["has_artifact"])
    return {
        "reference_run_quality": reference_run_quality(runs, ref),
        "skills_with_no_stored_artifact_stub_only": stub_only_skills,
        "removed_skills_with_no_stored_artifact": stub_only_removed,
        "crawl_runs_by_status": dict(by_status),
        "successful_runs_used_as_presence_timeline": by_status.get("success", 0),
        "reference_run_id": ref["id"],
        "reference_run_finished_at": iso(ref["finished_at"]),
        "runs_after_reference_run": newer_nonsuccess,
        "ever_seen_skills": len(rollup),
        "present_skills": len(present),
        "present_via_error_listing_in_reference_run": len(via_error),
        "removed_skills": len(removed),
        "accounting_removed_plus_present_equals_ever_seen": accounting_ok,
        "removed_with_null_last_crawl_run_id": len(classes["removed_with_null_last_run"]),
        "failed_and_partial_runs_excluded_from_absence_reference": True,
        "skills_with_detected_disappear_reappear_gap": len(reappeared_ids),
        "currently_removed_skills_with_prior_reappearance": len(
            reappeared_ids & removed),
        "analyzer_identity_for_capability_metrics": {
            "analyzer_name": analyzer_name, "analyzer_version": version,
            "analysis_run_id": analysis_run_id},
        "removed_skills_with_selected_version_analysis": frac(
            removed_signals, len(removed)),
    }


# --------------------------------------------------------------------------- #
# Provenance / caveats / rendering
# --------------------------------------------------------------------------- #


def build_provenance(ex: Exporter, args: argparse.Namespace,
                     version: str | None,
                     selection: dict[str, Any] | None = None,
                     analysis_run_id: int | None = None) -> dict[str, Any]:
    try:
        db_name = ex.scalar("select current_database()")
    except Exception:
        db_name = None
    try:
        versions = [
            {"analyzer_name": n, "analyzer_version": v, "successful_results": c}
            for (n, v, c) in ex.q(
                "select analyzer_name, analyzer_version, count(*) "
                "from analysis_results where status='success' "
                "group by 1,2 order by 1,2"
            )
        ]
    except Exception:
        versions = []
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit_hash(),
        "database_name": db_name,
        "source_filter": args.source,
        "analyzer_versions_present": versions,
        "selected_analyzer_name": args.analyzer_name,
        "selected_analyzer_version": version,
        "selected_analysis_run_id": analysis_run_id,
        "analysis_run_selection_note": (
            "Capability/anatomy metrics are sourced from exactly this "
            "analysis_run_id. Runs sharing a (name, version) are never pooled; "
            "e.g. static v4 spans a contaminated run and a clean re-run."
        ),
        "reappear_gap_days_threshold": args.reappear_gap_days,
        "pinned_reference_run_id": args.reference_run_id,
        "reference_run_selection": selection,
        "read_only_transaction": "REPEATABLE READ, READ ONLY",
        "removed_definition": (
            "Distinct source_id ever seen for the source whose "
            "max(last_crawl_run_id) predates the coverage-qualified reference "
            "crawl run (see reference_run_selection) and which is not listed "
            "in that run's error_details. Presence evidence is accepted from "
            "any run (including partial/failed); absence evidence only from a "
            "complete successful run."
        ),
        "failed_metrics": ex.failed_metrics,
    }


def build_caveats(version: str | None, cov: dict[str, Any] | None,
                  ref_quality: dict[str, Any] | None = None,
                  selection: dict[str, Any] | None = None) -> list[str]:
    notes = []
    rq = ref_quality or {}
    sel = selection or {}
    if sel.get("method") == "fallback_benchmark_run":
        notes.append(
            "NO RUN MET THE COVERAGE THRESHOLD: the reference is the fullest "
            f"recent run, attempting {sel.get('chosen_attempted')} "
            f"({sel.get('chosen_pct_of_benchmark')}% of benchmark). Every recent "
            "walk may be truncated; treat removal counts as unreliable until a "
            "full walk completes."
        )
    elif sel.get("method") == "interactive_override":
        notes.append(
            f"The reference run (#{sel.get('chosen_run_id')}) was chosen manually "
            "at the confirmation prompt, overriding the coverage rule "
            f"(attempted {sel.get('chosen_attempted')}, "
            f"{sel.get('chosen_pct_of_benchmark')}% of benchmark)."
        )
    bpa = sel.get("benchmark_pct_of_alltime_max")
    if bpa is not None and bpa < (sel.get("min_coverage_pct") or 0):
        notes.append(
            f"Recent walks are markedly smaller than historical ones: the "
            f"coverage benchmark ({sel.get('benchmark_attempted')}) is only "
            f"{bpa}% of the all-time counted maximum "
            f"({sel.get('alltime_max_attempted')}). This is consistent with "
            "genuine registry shrinkage (e.g. a purge wave) but also with "
            "persistently truncated catalog walks; removal counts inherit "
            "this ambiguity."
        )
    if rq.get("coverage_drop_exceeds_10pct"):
        notes.append(
            f"CATALOG COVERAGE DROP: the reference run attempted "
            f"{rq.get('reference_run_skills_attempted')} skills vs "
            f"{rq.get('previous_completed_run_skills_attempted')} in the previous "
            f"completed run ({rq.get('coverage_drop_vs_previous_pct')}% drop). The "
            "listing API may have ended pagination prematurely; the crawler does "
            "not fail the run for this. Removal counts are likely INFLATED — "
            "rerun with --reference-run-id pinned to an earlier full run."
        )
    if (rq.get("reference_run_discovery_errors") or 0) > 0:
        notes.append(
            f"The reference run had {rq['reference_run_discovery_errors']} "
            "discovery (detail-fetch) errors whose slugs are not recorded; up to "
            "that many skills classified as removed may actually have been listed. "
            "Treat the removed count as having this additive error bound."
        )
    notes += [
        "Removal means 'no longer listed by the ClawHub catalog walk'. It does not "
        "distinguish moderator takedown, author unpublish, renamed slugs, or "
        "registry-side listing faults. Do not describe removed skills as 'banned' "
        "or 'malicious'.",
        "A skill absent from the reference run but relisted later is counted as "
        "present (positive evidence from any run wins). Removal status is therefore "
        "as of the reference run, not forever.",
        "Reappearance detection is a lower bound: a skill relisted under the same "
        "(version, artifact hash) re-touches its existing row and erases the "
        "observation gap. Only reappearances that produced a new snapshot row and "
        "spanned a successful run are visible.",
        "Removed skills' anatomy/capability metrics cover only removed skills that "
        "have a successful analysis result under the selected analyzer version; "
        "coverage is reported in the sanity block and may be lower than for "
        "retained skills (removed artifacts can predate an analyzer re-run).",
        "Capability/risk numbers are STATIC capability signals, not maliciousness "
        "judgments; substring rules over-trigger (see analyzer planning notes).",
        "URL and env-var evidence are capped per result by the analyzer (75); "
        "'present' rates are reliable, totals are lower bounds.",
        "The database is live; all numbers come from one REPEATABLE READ snapshot "
        "and will drift between runs of this script.",
    ]
    try:
        if version is not None and int(version) < 3:
            notes.insert(0, (
                "SELECTED ANALYZER VERSION PREDATES the _detail.json exclusion fix "
                "(v3): capability/risk signals include crawler-added marketplace "
                "metadata and are PRELIMINARY."
            ))
    except ValueError:
        pass
    if cov and cov.get("pct") is not None and cov["pct"] < 80:
        notes.insert(0, (
            f"LOW ANALYSIS COVERAGE for removed skills under the selected analyzer "
            f"version ({cov['numerator']}/{cov['denominator']} = {cov['pct']}%). "
            "Anatomy/capability contrasts may not represent all removed skills; "
            "consider re-running the analyzer before relying on them."
        ))
    return notes


def render_markdown(m: dict[str, Any], prov: dict[str, Any]) -> str:
    L: list[str] = []
    w = L.append

    def wfrac(label: str, f: dict[str, Any] | None) -> None:
        if f:
            w(f"- {label}: **{f.get('numerator')} / {f.get('denominator')} "
              f"({f.get('pct')}%)**")

    w("# OpenClaw / ClawHub — Removed-Skill Metrics")
    w("")
    w("> Metrics for skills removed from ClawHub (absent from the latest complete "
      "successful crawl), with retained-skill columns for contrast only. "
      "Generated by a read-only export; see Caveats.")
    w("")

    w("## Provenance")
    w("")
    w(f"- Generated (UTC): `{prov['generated_at_utc']}`")
    w(f"- Git commit: `{prov['git_commit']}`")
    w(f"- Database: `{prov['database_name']}`; source filter: `{prov['source_filter']}`")
    w(f"- Read-only transaction: `{prov['read_only_transaction']}`")
    w(f"- Analyzer identity for capability metrics: "
      f"`{prov['selected_analyzer_name']} v{prov['selected_analyzer_version']}`")
    w("- Analyzer versions present (successful results):")
    for v in prov["analyzer_versions_present"]:
        w(f"  - `{v['analyzer_name']} v{v['analyzer_version']}`: "
          f"{v['successful_results']} successful results")
    w(f"- Removed definition: {prov['removed_definition']}")
    w(f"- Failed metrics: {len(prov['failed_metrics']) or 'none'}")
    w("")

    s = m.get("sanity_checks", {})
    w("## Data Quality / Sanity Checks")
    w("")
    w(f"- Crawl runs by status: `{s.get('crawl_runs_by_status')}`")
    w(f"- Reference run: #{s.get('reference_run_id')} "
      f"finished `{s.get('reference_run_finished_at')}`")
    sel = prov.get("reference_run_selection") or {}
    if sel:
        w(f"- Reference selection: method `{sel.get('method')}` — attempted "
          f"{sel.get('chosen_attempted')} = {sel.get('chosen_pct_of_benchmark')}% "
          f"of benchmark run #{sel.get('benchmark_run_id')} "
          f"({sel.get('benchmark_attempted')}); rule: newest of the last "
          f"{sel.get('coverage_window')} counted successful runs attempting "
          f">= {sel.get('min_coverage_pct')}% of the window maximum")
    rq = s.get("reference_run_quality", {})
    if rq:
        w(f"- Reference run attempted {rq.get('reference_run_skills_attempted')} skills "
          f"(discovery errors: {rq.get('reference_run_discovery_errors')}, pipeline "
          f"failures: {rq.get('reference_run_pipeline_failures')}); previous completed "
          f"run #{rq.get('previous_completed_run_id')} attempted "
          f"{rq.get('previous_completed_run_skills_attempted')}; coverage drop: "
          f"{rq.get('coverage_drop_vs_previous_pct')}% "
          f"(**exceeds 10%: {rq.get('coverage_drop_exceeds_10pct')}**)")
    w(f"- Skills with no stored artifact (metadata-only / capture-limited stubs): "
      f"{s.get('skills_with_no_stored_artifact_stub_only')} "
      f"(removed among them: {s.get('removed_skills_with_no_stored_artifact')})")
    if s.get("runs_after_reference_run"):
        w(f"- Runs after the reference run (presence evidence only): "
          f"`{s.get('runs_after_reference_run')}`")
    w(f"- Ever-seen skills: {s.get('ever_seen_skills')}; present: "
      f"{s.get('present_skills')}; present via error-listing: "
      f"{s.get('present_via_error_listing_in_reference_run')}; removed: "
      f"{s.get('removed_skills')}")
    w(f"- Accounting (removed + present + error-listed == ever-seen): "
      f"**{s.get('accounting_removed_plus_present_equals_ever_seen')}**")
    w(f"- Removed with NULL last_crawl_run_id: "
      f"{s.get('removed_with_null_last_crawl_run_id')}")
    w(f"- Failed/partial runs excluded from absence reference: "
      f"{s.get('failed_and_partial_runs_excluded_from_absence_reference')}")
    w(f"- Skills with a detected disappear→reappear gap: "
      f"{s.get('skills_with_detected_disappear_reappear_gap')} "
      f"(currently-removed among them: "
      f"{s.get('currently_removed_skills_with_prior_reappearance')})")
    cov = s.get("removed_skills_with_selected_version_analysis", {})
    w(f"- Removed skills with selected-version analysis: "
      f"**{cov.get('numerator')} / {cov.get('denominator')} ({cov.get('pct')}%)**")
    w("")

    o = m.get("removal_overview", {})
    w("## 1. Removal Overview")
    w("")
    w(f"- Unit of removal: `{o.get('unit_of_removal')}`")
    wfrac("Removed skills (of ever-seen)", o.get("removed_skills"))
    w(f"- Removed-skill lifespan (days, first→last observation): "
      f"{o.get('removed_lifespan_days_first_to_last_seen')}")
    w(f"- Removals by ISO week of last observation: "
      f"`{o.get('removals_by_iso_week_of_last_observation')}`")
    w("")

    g = m.get("reappearance", {})
    w("## 2. Disappear → Reappear")
    w("")
    w(f"- Detected gaps (validated against successful-run coverage): "
      f"{g.get('gap_episodes')} episodes across {g.get('skills_with_gaps')} skills")
    w(f"- Gap length days: {g.get('gap_days_distribution')}")
    w("- Lower bound: same-(version,hash) relistings are undetectable (see Caveats).")
    w("")

    va = m.get("version_artifact_behavior", {})
    w("## 3. Version / Artifact Behavior (removed vs retained)")
    w("")
    for grp_key, label in (("removed", "Removed"), ("retained_for_contrast", "Retained")):
        grp = va.get(grp_key, {})
        if not grp or grp.get("denominator", 0) == 0:
            continue
        w(f"**{label}** (n={grp['denominator']}):")
        w(f"- Versions per skill: {grp.get('versions_per_skill')}")
        wfrac("Multi-version skills", grp.get("multi_version_skills"))
        wfrac("Same-version mutated skills", grp.get("same_version_mutated_skills"))
        w("")

    a = m.get("author_patterns", {})
    w("## 4. Author Patterns")
    w("")
    w(f"- Authors with ≥1 removal: {a.get('authors_with_at_least_one_removal')}")
    wfrac("Removed skills whose author has ≥2 removals",
          a.get("removed_skills_with_author_having_2plus_removals"))
    w(f"- Authors with ALL skills removed (≥2 skills): "
      f"{a.get('authors_with_all_skills_removed_2plus')}")
    conc = a.get("concentration", {})
    for key in ("top_1_author_share", "top_10_authors_share",
                "top_1pct_authors_share", "top_10pct_authors_share"):
        wfrac(f"Concentration {key}", conc.get(key))
    top = a.get("top_authors_by_removed_count", [])
    if top:
        w("")
        w("Top authors by removed-skill count:")
        w("")
        w("| Author | Removed | Ever seen | Removal rate % |")
        w("| --- | --- | --- | --- |")
        for r in top[:10]:
            w(f"| {r['author']} | {r['removed_skills']} | {r['ever_seen_skills']} "
              f"| {r['removal_rate_pct']} |")
    w("")

    w("## 5. Anatomy — Removed vs Retained")
    w("")
    rp = m.get("removed_profile", {})
    tp = m.get("retained_profile", {})
    w(f"_Analyzed denominators: removed={rp.get('denominator')}, "
      f"retained={tp.get('denominator')} (selected-version successful results on "
      f"latest snapshots)._")
    w("")
    w("| Metric | Removed % | Retained % |")
    w("| --- | --- | --- |")

    def row(label: str, r: dict | None, t: dict | None) -> None:
        w(f"| {label} | {(r or {}).get('pct')} | {(t or {}).get('pct')} |")

    row("Code-bearing", rp.get("code_bearing"), tp.get("code_bearing"))
    row("Manifest present", rp.get("manifest_present"), tp.get("manifest_present"))
    for f in IMPORTANT_FILES:
        row(f"Has `{f}`", (rp.get("important_file_presence") or {}).get(f),
            (tp.get("important_file_presence") or {}).get(f))
    row("Env-var reference present", rp.get("env_var_reference_present"),
        tp.get("env_var_reference_present"))
    row("External URL present", rp.get("external_url_present"),
        tp.get("external_url_present"))
    w("")
    w(f"- File-count distribution (removed): {rp.get('file_count_distribution')}")
    w(f"- File-count distribution (retained): {tp.get('file_count_distribution')}")
    w("")

    w("## 6. Capability / Risk Signals — Removed vs Retained")
    w("")
    w("_STATIC CAPABILITY/RISK SIGNALS (not maliciousness)._")
    w("")
    w("| Category | Removed % | Retained % |")
    w("| --- | --- | --- |")
    for cat in CANONICAL_CATEGORIES:
        row(cat, (rp.get("category_prevalence") or {}).get(cat),
            (tp.get("category_prevalence") or {}).get(cat))
    for combo in ("secret_handling+network_or_exec", "suspicious_prompting+network_or_exec"):
        row(combo, (rp.get("high_combination_rates") or {}).get(combo),
            (tp.get("high_combination_rates") or {}).get(combo))
    w("")
    w("Risk level distribution:")
    w("")
    w("| Risk | Removed % | Retained % |")
    w("| --- | --- | --- |")
    risks = set((rp.get("risk_level_distribution") or {})) | set(
        (tp.get("risk_level_distribution") or {}))
    for k in sorted(risks):
        row(k, (rp.get("risk_level_distribution") or {}).get(k),
            (tp.get("risk_level_distribution") or {}).get(k))
    w("")
    for key, label in (("removed_top_indicators", "Top indicators among removed"),
                       ("removed_top_domains", "Top external domains among removed"),
                       ("removed_top_dependencies", "Top dependencies among removed")):
        items = m.get(key) or []
        if items:
            first_key = next(k for k in items[0] if not k.endswith("_count"))
            cnt_key = next(k for k in items[0] if k.endswith("_count"))
            w(f"- {label}: " + ", ".join(
                f"`{it[first_key]}`={it[cnt_key]}" for it in items[:10]))
    w("")

    w("## Caveats and Limitations")
    w("")
    for note in m.get("caveats", []):
        w(f"- {note}")
    w("")
    return "\n".join(L)


def write_csv_tables(tables_dir: Path,
                     tables: dict[str, tuple[list[str], list[list[Any]]]]) -> list[Path]:
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
    parser = argparse.ArgumentParser(
        description="Read-only removed-skills metrics exporter (see module docstring)."
    )
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                        help="Output directory (default: %(default)s)")
    parser.add_argument("--source", default=DEFAULT_SOURCE,
                        help="skills.source to measure (default: %(default)s)")
    parser.add_argument("--analyzer-name", default=DEFAULT_ANALYZER_NAME,
                        help="analysis_results.analyzer_name filter (default: %(default)s)")
    parser.add_argument("--analyzer-version", default=None,
                        help="Restrict analysis-run selection to this analyzer_version "
                             "(default: latest successful run for the analyzer name)")
    parser.add_argument("--analysis-run-id", type=int, default=None,
                        help="Pin capability/anatomy metrics to this analysis_run_id "
                             "(default: latest successful run for the analyzer name / "
                             "version). Prevents pooling multiple runs that share a "
                             "(name, version), e.g. a contaminated run and a clean re-run.")
    parser.add_argument("--reappear-gap-days", type=float,
                        default=DEFAULT_REAPPEAR_GAP_DAYS,
                        help="Minimum observation gap (days) to count as a "
                             "disappear/reappear episode (default: %(default)s)")
    parser.add_argument("--reference-run-id", type=int, default=None,
                        help="Pin the absence-reference crawl run, bypassing the "
                             "coverage rule and the confirmation prompt")
    parser.add_argument("--min-coverage-pct", type=float,
                        default=DEFAULT_MIN_COVERAGE_PCT,
                        help="Reference run must attempt at least this percent of "
                             "the window-maximum attempted count (default: "
                             "%(default)s)")
    parser.add_argument("--coverage-window", type=int,
                        default=DEFAULT_COVERAGE_WINDOW,
                        help="How many recent counted successful runs form the "
                             "coverage benchmark window (default: %(default)s)")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Accept the selected reference run without prompting")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    tables_dir = out_dir / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)

    settings = get_settings()
    engine = build_engine(settings)

    with engine.connect() as conn:
        # First statements in the transaction: pin a consistent snapshot AND make
        # the transaction read-only as defense-in-depth against accidental writes.
        conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        conn.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))

        ex = Exporter(conn)

        runs = load_crawl_runs(ex, args.source)
        ref, selection = select_reference_run(
            runs,
            pinned_id=args.reference_run_id,
            min_coverage_pct=args.min_coverage_pct,
            coverage_window=args.coverage_window,
        )
        if ref is None:
            print("No usable reference crawl run found for source "
                  f"'{args.source}' (pinned id: {args.reference_run_id}); "
                  "cannot define removal.", file=sys.stderr)
            return 1
        ref = confirm_reference_run(ref, selection, runs, assume_yes=args.yes)
        if ref is None:
            print("Reference run not confirmed; no metrics computed.",
                  file=sys.stderr)
            return 1
        if ref["status"] != "success":
            print(f"WARNING: reference run #{ref['id']} has status "
                  f"'{ref['status']}' — absence evidence from a non-success run "
                  "is unreliable.", file=sys.stderr)

        rollup = load_per_skill_rollup(ex, args.source)
        latest = load_latest_snapshots(ex, args.source)
        classes = classify_removed(rollup, ref, error_listed_slugs(ref))
        removed = classes["removed"]
        retained = set(rollup) - removed

        analysis_run = select_analysis_run(
            ex, args.analyzer_name, args.analyzer_version, args.analysis_run_id)
        if analysis_run is None:
            print("No successful analysis run found for analyzer "
                  f"'{args.analyzer_name}'"
                  + (f" version {args.analyzer_version}" if args.analyzer_version else "")
                  + (f" run id {args.analysis_run_id}" if args.analysis_run_id else "")
                  + "; capability/anatomy metrics will be empty.", file=sys.stderr)
            run_id = None
            version = args.analyzer_version
        else:
            run_id = analysis_run["id"]
            version = analysis_run["analyzer_version"]
            if analysis_run["status"] != "success":
                print(f"WARNING: pinned analysis run #{run_id} has status "
                      f"'{analysis_run['status']}'.", file=sys.stderr)
            print(f"Capability metrics sourced from analysis run #{run_id} "
                  f"({analysis_run['analyzer_name']} v{version}, "
                  f"finished {iso(analysis_run['finished_at'])}).")

        ex.guard("removal_overview",
                 lambda: removal_overview(ex, rollup, latest, classes, runs, ref))

        gaps: list[dict[str, Any]] = []

        def compute_reappearance() -> dict[str, Any]:
            nonlocal gaps
            gaps = find_reappearances(ex, args.source, runs, args.reappear_gap_days)
            ex.add_table(
                "removed_reappearance_gaps",
                ["source_id", "gap_start", "gap_end", "gap_days", "currently_removed"],
                [[g["source_id"], iso(g["gap_start"]), iso(g["gap_end"]),
                  g["gap_days"], g["source_id"] in removed] for g in gaps],
            )
            return {
                "gap_episodes": len(gaps),
                "skills_with_gaps": len({g["source_id"] for g in gaps}),
                "gap_days_distribution": distribution(
                    [g["gap_days"] for g in gaps]),
                "currently_removed_with_prior_gap": len(
                    {g["source_id"] for g in gaps} & removed),
            }

        ex.guard("reappearance", compute_reappearance)

        mutated = load_mutated_slugs(ex, args.source)
        ex.guard("version_artifact_behavior",
                 lambda: version_artifact_metrics(rollup, removed, mutated))

        ex.guard("author_patterns", lambda: author_metrics(ex, latest, removed))

        signals: dict[str, dict[str, Any]] = {}
        if run_id is not None:
            def load_signals() -> str:
                signals.update(
                    load_result_signals(ex, args.source, run_id))
                return f"loaded {len(signals)} per-skill signal rows"
            ex.guard("_load_signals", load_signals)
        removed_rows = [signals[s] for s in removed if s in signals]
        retained_rows = [signals[s] for s in retained if s in signals]

        ex.guard("removed_profile", lambda: signal_profile(removed_rows))
        ex.guard("retained_profile", lambda: signal_profile(retained_rows))

        def comparison() -> str:
            comparison_table(ex, ex.metrics.get("removed_profile", {}),
                             ex.metrics.get("retained_profile", {}),
                             ex.metrics.get("version_artifact_behavior",
                                            {"removed": {}, "retained_for_contrast": {}}))
            return "ok"
        ex.guard("_comparison_table", comparison)

        # Category prevalence side-by-side CSVs.
        def prevalence_csvs() -> str:
            rp = ex.metrics.get("removed_profile", {})
            tp = ex.metrics.get("retained_profile", {})
            ex.add_table(
                "removed_category_prevalence",
                ["category", "removed_n", "removed_denominator", "removed_pct",
                 "retained_pct"],
                [[cat,
                  ((rp.get("category_prevalence") or {}).get(cat) or {}).get("numerator"),
                  ((rp.get("category_prevalence") or {}).get(cat) or {}).get("denominator"),
                  ((rp.get("category_prevalence") or {}).get(cat) or {}).get("pct"),
                  ((tp.get("category_prevalence") or {}).get(cat) or {}).get("pct")]
                 for cat in CANONICAL_CATEGORIES],
            )
            ex.add_table(
                "removed_risk_distribution",
                ["risk_level", "removed_n", "removed_denominator", "removed_pct",
                 "retained_pct"],
                [[k,
                  v.get("numerator"), v.get("denominator"), v.get("pct"),
                  ((tp.get("risk_level_distribution") or {}).get(k) or {}).get("pct")]
                 for k, v in sorted(
                    (rp.get("risk_level_distribution") or {}).items())],
            )
            return "ok"
        ex.guard("_prevalence_csvs", prevalence_csvs)

        if run_id is not None and removed_rows:
            removed_ids = sorted(removed)
            ex.guard("removed_top_indicators",
                     lambda: removed_top_indicators(
                         ex, args.source, run_id, removed_ids))
            ex.guard("removed_top_domains",
                     lambda: removed_top_domains(
                         ex, args.source, run_id, removed_ids))
            ex.guard("removed_top_dependencies",
                     lambda: removed_top_dependencies(
                         ex, args.source, run_id, removed_ids))

        ex.guard("sanity_checks", lambda: sanity_checks(
            ex, runs, ref, rollup, classes, gaps, len(removed_rows),
            version, args.analyzer_name, run_id))

        prov = build_provenance(ex, args, version, selection, run_id)
        sc = ex.metrics.get("sanity_checks") or {}
        ex.metrics["caveats"] = build_caveats(
            version,
            sc.get("removed_skills_with_selected_version_analysis"),
            sc.get("reference_run_quality"),
            selection,
        )
        ex.metrics["provenance"] = prov

        # Internal bookkeeping guards are not part of the exported metrics.
        for internal in ("_load_signals", "_comparison_table", "_prevalence_csvs"):
            ex.metrics.pop(internal, None)

        md = render_markdown(ex.metrics, prov)
        (out_dir / "removed_skills_metrics.md").write_text(md, encoding="utf-8")
        (out_dir / "removed_skills_metrics.json").write_text(
            json.dumps(ex.metrics, indent=2, default=str), encoding="utf-8")
        csv_paths = write_csv_tables(tables_dir, ex.tables)

    print(f"Output directory: {out_dir}")
    print(f"  - {out_dir / 'removed_skills_metrics.md'}")
    print(f"  - {out_dir / 'removed_skills_metrics.json'}")
    for p in csv_paths:
        print(f"  - {p}")
    if ex.failed_metrics:
        print(f"\nFailed metrics ({len(ex.failed_metrics)}):")
        for f in ex.failed_metrics:
            print(f"  - {f['metric']}: {f['error']}")
    else:
        print("\nFailed metrics: none")
    ov = ex.metrics.get("removal_overview", {})
    rem = ov.get("removed_skills") or {}
    print(f"\nRemoved skills: {rem.get('numerator')} / {rem.get('denominator')} "
          f"({rem.get('pct')}%) of ever-seen '{args.source}' skills "
          f"(reference run #{(ov.get('reference_run') or {}).get('id')}, "
          f"selected via {selection.get('method')})")
    print(f"Analyzer identity for capability metrics: "
          f"{args.analyzer_name} v{version} (analysis_run_id={run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
