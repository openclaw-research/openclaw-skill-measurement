"""
Shared engine for the OpenClaw/ClawHub measurement metric exporters.

Three exporters build on this module:
  - export_paper_metrics.py            population / anatomy / churn / capability
  - export_removed_skill_metrics.py    removed-vs-retained
  - export_party_comparison_metrics.py first-party vs third-party

It centralises the pieces that MUST stay identical across them so numbers are
comparable and reproducible:

  - A read-only Exporter (query helper + guarded-metric registry + CSV tables).
  - Run pinning: capability/anatomy metrics are sourced from exactly one
    analysis_run_id, never pooled across runs that happen to share a
    (analyzer_name, analyzer_version). A single version can span a contaminated
    run and a clean re-run (e.g. static v4).
  - The analyzer v4 capability taxonomy (14 categories) and the per-skill
    signal extraction + profile used everywhere.

Everything here is read-only. Callers wrap queries in a single
REPEATABLE READ, READ ONLY transaction.
"""
from __future__ import annotations

import csv
import statistics
import subprocess
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import text
from sqlalchemy.engine import Connection

# --------------------------------------------------------------------------- #
# Analyzer v4 taxonomy
# --------------------------------------------------------------------------- #

# All 14 indicator categories emitted by static analyzer v4, grouped by the
# analyzer's own base severity. Order is severity-descending for display.
CANONICAL_CATEGORIES = (
    # critical
    "reverse_shell_patterns",
    # high
    "credential_theft_targets",
    "exfiltration_channels",
    "obfuscation_techniques",
    "download_and_execute",
    "suspicious_prompting",
    # medium
    "persistence_mechanisms",
    "network_access",
    "filesystem_access",
    "secret_handling",
    "hidden_content",
    "dependency_or_install_script",
    "process_execution",
    # low
    "hook_or_tool_exposure",
)

# Capability-family groupings used for higher-level reporting.
CAPABILITY_FAMILIES = {
    "remote_access": ("reverse_shell_patterns", "download_and_execute"),
    "credential_exposure": ("credential_theft_targets", "secret_handling"),
    "exfiltration": ("exfiltration_channels",),
    "evasion": ("obfuscation_techniques", "hidden_content"),
    "persistence": ("persistence_mechanisms",),
    "prompt_manipulation": ("suspicious_prompting",),
    "system_interaction": ("process_execution", "filesystem_access", "network_access"),
    "packaging": ("dependency_or_install_script",),
    "tooling_surface": ("hook_or_tool_exposure",),
}

# Co-occurrence pairs of paper interest (dangerous combinations).
COOCCURRENCE_PAIRS = (
    ("secret_handling", "network_access"),
    ("secret_handling", "process_execution"),
    ("credential_theft_targets", "exfiltration_channels"),
    ("credential_theft_targets", "network_access"),
    ("download_and_execute", "network_access"),
    ("obfuscation_techniques", "process_execution"),
    ("reverse_shell_patterns", "network_access"),
    ("suspicious_prompting", "network_access"),
)

# Risk tiers in ascending order (v4 adds 'critical' and 'none'; 'unknown' is a
# failed/degraded result marker).
RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 5}

CODE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".java",
    ".php", ".pl", ".lua", ".ps1",
)

IMPORTANT_FILES = ("SKILL.md", "_meta.json", "README.md", "package.json", "requirements.txt")

STATEMENT_TIMEOUT_MS = 300_000


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def frac(numerator: int, denominator: int) -> dict[str, Any]:
    """Explicit numerator/denominator/pct triple."""
    pct = round(100.0 * numerator / denominator, 2) if denominator else None
    return {"numerator": numerator, "denominator": denominator, "pct": pct}


def distribution(values: list[float]) -> dict[str, Any]:
    """Min / median / mean / p90 / max plus count for a numeric list."""
    if not values:
        return {"count": 0, "min": None, "median": None, "mean": None,
                "p90": None, "max": None}
    ordered = sorted(values)
    p90_idx = max(0, min(len(ordered) - 1, int(round(0.90 * (len(ordered) - 1)))))
    return {
        "count": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "mean": round(statistics.fmean(values), 3),
        "p90": ordered[p90_idx],
        "max": max(values),
    }


def git_commit_hash() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except Exception:
        return None


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


# --------------------------------------------------------------------------- #
# Exporter
# --------------------------------------------------------------------------- #


class Exporter:
    """Read-only query helper + guarded metric registry + CSV table collector."""

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
        """Run a metric block; record but never propagate a failure."""
        try:
            self.metrics[name] = fn()
        except Exception as exc:  # noqa: BLE001 - intentional catch-all
            self.failed_metrics.append(
                {"metric": name, "error": f"{type(exc).__name__}: {exc}",
                 "traceback": traceback.format_exc(limit=3)}
            )

    def add_table(self, name: str, header: list[str], rows: list[list[Any]]) -> None:
        self.tables[name] = (header, rows)


def begin_readonly(conn: Connection) -> None:
    """Pin a consistent snapshot and make the transaction read-only."""
    conn.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
    conn.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


def write_csv_tables(tables_dir: Path,
                     tables: dict[str, tuple[list[str], list[list[Any]]]]) -> list[Path]:
    tables_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, (header, rows) in tables.items():
        path = tables_dir / f"{name}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
        written.append(path)
    return written


# --------------------------------------------------------------------------- #
# Run pinning
# --------------------------------------------------------------------------- #


def select_analysis_run(
    ex: Exporter,
    analyzer_name: str,
    version: str | None = None,
    pinned_run_id: int | None = None,
) -> dict[str, Any] | None:
    """Resolve the single analysis_runs row capability metrics source from.

    Pinning to a run_id (not just name+version) guarantees a contaminated run
    and a later clean re-run sharing a version are never pooled. Default: latest
    successful run for analyzer_name (optionally narrowed by version).
    """
    cols = ("id", "analyzer_name", "analyzer_version", "status", "started_at", "finished_at")
    if pinned_run_id is not None:
        row = ex.q("select id, analyzer_name, analyzer_version, status, started_at, "
                   "finished_at from analysis_runs where id = :rid", rid=pinned_run_id)
        return dict(zip(cols, row[0])) if row else None
    where = "analyzer_name = :name and status = 'success'"
    params: dict[str, Any] = {"name": analyzer_name}
    if version is not None:
        where += " and analyzer_version = :ver"
        params["ver"] = version
    row = ex.q("select id, analyzer_name, analyzer_version, status, started_at, finished_at "
               f"from analysis_runs where {where} "
               "order by finished_at desc nulls last, id desc limit 1", **params)
    return dict(zip(cols, row[0])) if row else None


# --------------------------------------------------------------------------- #
# Per-skill signal extraction (latest snapshot per skill, one pinned run)
# --------------------------------------------------------------------------- #


def _indicator_count_columns() -> str:
    return ",\n            ".join(
        f"(r.result_json#>>'{{indicators,{cat},count}}')::int as \"{cat}\""
        for cat in CANONICAL_CATEGORIES
    )


def load_signal_rows(ex: Exporter, run_id: int, source: str | None = None) -> list[dict[str, Any]]:
    """Per-skill scalar signals from the pinned run, one row per latest snapshot.

    Latest snapshot is chosen per (source, source_id). Each returned dict carries
    ``source`` and ``source_id`` so callers can split by party. ``source`` filter
    restricts to a single source when given.
    """
    src_clause = "where source = :src" if source else ""
    sql = f"""
    with latest_snap as (
        select distinct on (source, source_id) id, source, source_id
        from skills {src_clause}
        order by source, source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id)
            r.skill_id,
            ls.source,
            ls.source_id,
            r.risk_level,
            (r.result_json->>'file_count')::int                            as file_count,
            (r.result_json->'artifact'->>'downloaded_bytes')::bigint       as bytes,
            (r.result_json->'important_files'->>'SKILL.md')::bool          as has_skill_md,
            (r.result_json->'important_files'->>'_meta.json')::bool        as has_meta,
            (r.result_json->'important_files'->>'README.md')::bool         as has_readme,
            (r.result_json->'important_files'->>'package.json')::bool      as has_pkg,
            (r.result_json->'important_files'->>'requirements.txt')::bool  as has_reqs,
            (r.result_json->'extension_counts') ?| :code_exts              as code_bearing,
            (r.result_json->'env_var_references'->>'count')::int           as env_count,
            (r.result_json->'external_urls'->>'count')::int                as url_count,
            {_indicator_count_columns()}
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id and r.status = 'success'
        order by r.skill_id, r.created_at desc, r.id desc
    )
    select * from res
    """
    params: dict[str, Any] = {"run_id": run_id, "code_exts": list(CODE_EXTENSIONS)}
    if source:
        params["src"] = source
    return [dict(row) for row in ex.conn.execute(text(sql), params).mappings().all()]


def _active(row: dict[str, Any], cat: str) -> bool:
    return (row.get(cat) or 0) > 0


def signal_profile(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Anatomy + capability/risk profile for one group of per-skill signal rows.

    Capability numbers are STATIC signals, not maliciousness judgments.
    """
    denom = len(rows)
    if denom == 0:
        return {"denominator": 0}

    risk: dict[str, int] = {}
    for r in rows:
        risk[r["risk_level"]] = risk.get(r["risk_level"], 0) + 1

    prevalence = {cat: frac(sum(1 for r in rows if _active(r, cat)), denom)
                  for cat in CANONICAL_CATEGORIES}

    families = {
        fam: frac(sum(1 for r in rows if any(_active(r, c) for c in cats)), denom)
        for fam, cats in CAPABILITY_FAMILIES.items()
    }

    cooccur = {
        f"{a}+{b}": frac(sum(1 for r in rows if _active(r, a) and _active(r, b)), denom)
        for a, b in COOCCURRENCE_PAIRS
    }

    return {
        "denominator": denom,
        "prompt_only_vs_code_bearing": {
            "code_bearing": frac(sum(1 for r in rows if r["code_bearing"]), denom),
            "prompt_only": frac(sum(1 for r in rows if not r["code_bearing"]), denom),
        },
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
        "manifest_present": frac(sum(1 for r in rows if r["has_pkg"] or r["has_reqs"]), denom),
        "env_var_reference_present": frac(
            sum(1 for r in rows if (r["env_count"] or 0) > 0), denom),
        "external_url_present": frac(
            sum(1 for r in rows if (r["url_count"] or 0) > 0), denom),
        "risk_level_distribution": {
            k: frac(v, denom) for k, v in sorted(
                risk.items(), key=lambda kv: RISK_ORDER.get(kv[0], 99))},
        "category_prevalence": prevalence,
        "capability_family_prevalence": families,
        "cooccurrence": cooccur,
    }


def risk_tiers_sorted(*profiles: dict[str, Any]) -> list[str]:
    """Union of risk tiers across profiles, in canonical order."""
    tiers: set[str] = set()
    for p in profiles:
        tiers |= set((p or {}).get("risk_level_distribution") or {})
    return sorted(tiers, key=lambda r: RISK_ORDER.get(r, 99))


# --------------------------------------------------------------------------- #
# Top-N aggregations over a pinned run (domains / dependencies / indicators)
# --------------------------------------------------------------------------- #


def _run_res_cte(source: str | None, source_ids: list[str] | None = None) -> str:
    conds = []
    if source:
        conds.append("source = :src")
    if source_ids is not None:
        conds.append("source_id = any(:source_ids)")
    src_clause = ("where " + " and ".join(conds)) if conds else ""
    return f"""
    with latest_snap as (
        select distinct on (source, source_id) id from skills {src_clause}
        order by source, source_id, last_seen_at desc, id desc
    ),
    res as (
        select distinct on (r.skill_id) r.skill_id, r.result_json
        from analysis_results r
        join latest_snap ls on ls.id = r.skill_id
        where r.analysis_run_id = :run_id and r.status = 'success'
        order by r.skill_id, r.created_at desc, r.id desc
    )
    """


def _top_params(run_id: int, source: str | None,
                source_ids: list[str] | None) -> dict[str, Any]:
    params: dict[str, Any] = {"run_id": run_id}
    if source:
        params["src"] = source
    if source_ids is not None:
        params["source_ids"] = list(source_ids)
    return params


def top_domains(ex: Exporter, run_id: int, source: str | None = None,
                limit: int = 25, source_ids: list[str] | None = None):
    return ex.q(_run_res_cte(source, source_ids) + """
        select d as domain, count(*) as n
        from res, lateral jsonb_array_elements_text(
            coalesce(res.result_json->'external_urls'->'domains','[]')) as d
        where d <> '' group by 1 order by n desc limit :lim
    """, lim=limit, **_top_params(run_id, source, source_ids))


def top_dependencies(ex: Exporter, run_id: int, source: str | None = None,
                     limit: int = 25, source_ids: list[str] | None = None):
    return ex.q(_run_res_cte(source, source_ids) + """
        select dep, count(*) as n from (
            select d as dep from res, lateral jsonb_array_elements_text(
                coalesce(res.result_json->'parsed_files'->'package_json'->'dependencies','[]')) as d
            union all
            select p as dep from res, lateral jsonb_array_elements_text(
                coalesce(res.result_json->'parsed_files'->'requirements_txt'->'packages','[]')) as p
        ) z where dep <> '' group by dep order by n desc limit :lim
    """, lim=limit, **_top_params(run_id, source, source_ids))


def top_indicators(ex: Exporter, run_id: int, source: str | None = None,
                   limit: int = 25, source_ids: list[str] | None = None):
    return ex.q(_run_res_cte(source, source_ids) + """
        select ev->>'indicator' as indicator, count(*) as n
        from res,
             lateral jsonb_each(res.result_json->'indicators') as cat(name, data),
             lateral jsonb_array_elements(coalesce(data->'evidence','[]')) as ev
        where ev ? 'indicator' group by 1 order by n desc limit :lim
    """, lim=limit, **_top_params(run_id, source, source_ids))
