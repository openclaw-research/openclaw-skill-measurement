"""
First-party vs third-party skill metrics for the OpenClaw/ClawHub paper.

Party definition
----------------
  first_party  = skills crawled from ClawHub itself      (skills.source = 'clawhub')
  third_party  = every other source                      (skills.source <> 'clawhub')

This exporter contrasts the two populations on size, anatomy, version churn, and
static capability/risk signals. It is read-only and sources all capability
metrics from a single pinned analysis run (see skill_metrics_common); runs that
share a (name, version) are never pooled.

Usage:
    venv/bin/python scripts/export_party_comparison_metrics.py --help
    venv/bin/python scripts/export_party_comparison_metrics.py
    venv/bin/python scripts/export_party_comparison_metrics.py --analysis-run-id 71

Outputs (git-ignored) under --out-dir (default paper_metrics/party-comparison/):
  party_comparison_metrics.md, party_comparison_metrics.json, tables/*.csv

Every metric block is guarded: a single failure is recorded under
provenance.failed_metrics and the export continues.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db.session import build_engine  # noqa: E402
from config import get_settings  # noqa: E402
import skill_metrics_common as C  # noqa: E402

DEFAULT_OUT_DIR = "paper_metrics/party-comparison"
FIRST_PARTY_SOURCE = "clawhub"
DEFAULT_ANALYZER_NAME = "static"

PARTIES = ("first_party", "third_party")


def party_source_clause(party: str) -> tuple[str, dict[str, Any]]:
    """SQL predicate + params selecting a party from the skills table."""
    if party == "first_party":
        return "source = :src", {"src": FIRST_PARTY_SOURCE}
    return "source <> :src", {"src": FIRST_PARTY_SOURCE}


# --------------------------------------------------------------------------- #
# Population (no analysis needed)
# --------------------------------------------------------------------------- #


def population(ex: C.Exporter, party: str) -> dict[str, Any]:
    clause, params = party_source_clause(party)
    scalar = lambda sql: ex.scalar(sql, **params)  # noqa: E731
    rows = scalar(f"select count(*) from skills where {clause}")
    distinct_skills = scalar(
        f"select count(*) from (select distinct source, source_id from skills where {clause}) z")
    pairs = scalar(
        f"select count(*) from (select distinct source, source_id, version "
        f"from skills where {clause}) z")
    hashes = scalar(f"select count(distinct artifact_hash) from skills where {clause}")
    authors = scalar(f"select count(distinct author) from skills where {clause}")
    sources = dict(ex.q(
        f"select source, count(distinct source_id) from skills where {clause} group by 1 order by 2 desc",
        **params))
    window = ex.q(f"select min(first_seen_at), max(last_seen_at) from skills where {clause}", **params)[0]
    return {
        "snapshot_rows": rows,
        "distinct_skills": distinct_skills,
        "distinct_skill_version_pairs": pairs,
        "distinct_artifact_hashes": hashes,
        "distinct_authors": authors,
        "sources": sources,
        "observation_window": {"first_seen_min": C.iso(window[0]),
                               "last_seen_max": C.iso(window[1])},
    }


def churn(ex: C.Exporter, party: str) -> dict[str, Any]:
    clause, params = party_source_clause(party)
    pairs = ex.scalar(
        f"select count(*) from (select distinct source, source_id, version "
        f"from skills where {clause}) z", **params)
    mutated = ex.scalar(
        f"select count(*) from (select source, source_id, version from skills where {clause} "
        f"group by source, source_id, version having count(distinct artifact_hash) > 1) z",
        **params)
    versions_per_skill = [r[0] for r in ex.q(
        f"select count(distinct version) from skills where {clause} group by source, source_id",
        **params)]
    rows_per_skill = [r[0] for r in ex.q(
        f"select count(*) from skills where {clause} group by source, source_id", **params)]
    return {
        "same_version_mutation": {
            **C.frac(mutated, pairs),
            "definition": "(source_id, version) pairs mapping to >1 artifact hash.",
        },
        "versions_per_skill": distribution_int(versions_per_skill),
        "snapshot_rows_per_skill": distribution_int(rows_per_skill),
        "multi_version_skills": C.frac(
            sum(1 for v in versions_per_skill if v > 1), len(versions_per_skill)),
    }


def distribution_int(values: list[int]) -> dict[str, Any]:
    return C.distribution([float(v) for v in values])


# --------------------------------------------------------------------------- #
# Analysis coverage per party
# --------------------------------------------------------------------------- #


def coverage(ex: C.Exporter, party: str, run_id: int) -> dict[str, Any]:
    clause, params = party_source_clause(party)
    latest = ex.scalar(
        f"select count(*) from (select distinct on (source, source_id) id from skills "
        f"where {clause} order by source, source_id, last_seen_at desc, id desc) z", **params)
    analyzed = ex.scalar(
        f"""with latest_snap as (
                select distinct on (source, source_id) id from skills where {clause}
                order by source, source_id, last_seen_at desc, id desc)
            select count(distinct r.skill_id) from analysis_results r
            join latest_snap ls on ls.id = r.skill_id
            where r.analysis_run_id = :run_id and r.status = 'success'""",
        run_id=run_id, **params)
    return {**C.frac(analyzed or 0, latest or 0),
            "definition": "distinct latest snapshots with a successful pinned-run result."}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def build_provenance(ex: C.Exporter, args, run: dict[str, Any] | None) -> dict[str, Any]:
    try:
        db_name = ex.scalar("select current_database()")
    except Exception:
        db_name = None
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": C.git_commit_hash(),
        "database_name": db_name,
        "party_definition": {
            "first_party": "skills.source = 'clawhub' (crawled from ClawHub)",
            "third_party": "skills.source <> 'clawhub' (all other sources)",
        },
        "selected_analyzer_name": args.analyzer_name,
        "selected_analysis_run_id": run["id"] if run else None,
        "selected_analyzer_version": run["analyzer_version"] if run else None,
        "analysis_run_finished_at": C.iso(run["finished_at"]) if run else None,
        "read_only_transaction": "REPEATABLE READ, READ ONLY",
        "capability_note": (
            "Capability/risk numbers are STATIC signals (analyzer v4 substring / "
            "regex / weighted matching), NOT maliciousness judgments. All sourced "
            "from one analysis_run_id; runs are never pooled."
        ),
        "failed_metrics": ex.failed_metrics,
    }


def caveats() -> list[str]:
    return [
        "Capability/risk numbers are STATIC capability signals, not maliciousness; "
        "high/critical means risky indicators co-occur, nothing more.",
        "Third-party is dominated by one source (github-skills); openclaw contributes "
        "a handful of rows. Read 'third-party' as 'non-ClawHub', not a uniform group.",
        "The two parties differ ~14x in size; compare rates (pct), not raw counts.",
        "URL and env-var evidence are capped per result by the analyzer (75); 'present' "
        "rates are reliable, raw totals are lower bounds.",
        "Capability metrics cover only skills with a successful pinned-run result; "
        "per-party coverage is reported and may differ between parties.",
        "The database is live; all numbers come from one REPEATABLE READ snapshot.",
    ]


def add_comparison_tables(ex: C.Exporter, prof: dict[str, dict[str, Any]]) -> None:
    fp, tp = prof["first_party"], prof["third_party"]

    def p(profile, *path):
        node = profile
        for key in path:
            if not isinstance(node, dict) or key not in node:
                return None
            node = node[key]
        return node.get("pct") if isinstance(node, dict) else node

    # Anatomy + capability comparison.
    rows = [
        ["analyzed_denominator", fp.get("denominator"), tp.get("denominator")],
        ["code_bearing_pct", p(fp, "prompt_only_vs_code_bearing", "code_bearing"),
         p(tp, "prompt_only_vs_code_bearing", "code_bearing")],
        ["file_count_median", (fp.get("file_count_distribution") or {}).get("median"),
         (tp.get("file_count_distribution") or {}).get("median")],
        ["manifest_present_pct", p(fp, "manifest_present"), p(tp, "manifest_present")],
        ["env_var_present_pct", p(fp, "env_var_reference_present"),
         p(tp, "env_var_reference_present")],
        ["external_url_present_pct", p(fp, "external_url_present"),
         p(tp, "external_url_present")],
    ]
    for f in C.IMPORTANT_FILES:
        rows.append([f"has_{f}_pct", p(fp, "important_file_presence", f),
                     p(tp, "important_file_presence", f)])
    for cat in C.CANONICAL_CATEGORIES:
        rows.append([f"cat_{cat}_pct", p(fp, "category_prevalence", cat),
                     p(tp, "category_prevalence", cat)])
    for fam in C.CAPABILITY_FAMILIES:
        rows.append([f"family_{fam}_pct", p(fp, "capability_family_prevalence", fam),
                     p(tp, "capability_family_prevalence", fam)])
    for a, b in C.COOCCURRENCE_PAIRS:
        rows.append([f"cooccur_{a}+{b}_pct", p(fp, "cooccurrence", f"{a}+{b}"),
                     p(tp, "cooccurrence", f"{a}+{b}")])
    for tier in C.risk_tiers_sorted(fp, tp):
        rows.append([f"risk_{tier}_pct", p(fp, "risk_level_distribution", tier),
                     p(tp, "risk_level_distribution", tier)])
    ex.add_table("party_comparison", ["metric", "first_party", "third_party"], rows)


def render_markdown(m: dict[str, Any], prov: dict[str, Any]) -> str:
    L: list[str] = []
    w = L.append
    fp_pop = m["population"]["first_party"]
    tp_pop = m["population"]["third_party"]
    fp = m["profile"]["first_party"]
    tp = m["profile"]["third_party"]

    w("# OpenClaw / ClawHub — First-Party vs Third-Party Skills")
    w("")
    w("> first_party = crawled from ClawHub (`source = 'clawhub'`); "
      "third_party = all other sources. Static capability signals only — see Caveats.")
    w("")
    w("## Provenance")
    w("")
    w(f"- Generated (UTC): `{prov['generated_at_utc']}`")
    w(f"- Git commit: `{prov['git_commit']}`")
    w(f"- Database: `{prov['database_name']}`")
    w(f"- Capability metrics from analysis run `#{prov['selected_analysis_run_id']}` "
      f"(`{prov['selected_analyzer_name']} v{prov['selected_analyzer_version']}`, "
      f"finished `{prov['analysis_run_finished_at']}`)")
    w(f"- Failed metrics: {len(prov['failed_metrics']) or 'none'}")
    w("")

    w("## 1. Population")
    w("")
    w("| Denominator | First-party | Third-party |")
    w("| --- | --- | --- |")
    w(f"| Distinct skills | {fp_pop['distinct_skills']} | {tp_pop['distinct_skills']} |")
    w(f"| Snapshot rows | {fp_pop['snapshot_rows']} | {tp_pop['snapshot_rows']} |")
    w(f"| (source_id, version) pairs | {fp_pop['distinct_skill_version_pairs']} "
      f"| {tp_pop['distinct_skill_version_pairs']} |")
    w(f"| Distinct artifact hashes | {fp_pop['distinct_artifact_hashes']} "
      f"| {tp_pop['distinct_artifact_hashes']} |")
    w(f"| Distinct authors | {fp_pop['distinct_authors']} | {tp_pop['distinct_authors']} |")
    w(f"| Sources | {fp_pop['sources']} | {tp_pop['sources']} |")
    w("")
    cov = m["coverage"]
    w(f"- Analysis coverage (latest snapshots with pinned-run result): "
      f"first-party **{cov['first_party'].get('pct')}%** "
      f"({cov['first_party'].get('numerator')}/{cov['first_party'].get('denominator')}), "
      f"third-party **{cov['third_party'].get('pct')}%** "
      f"({cov['third_party'].get('numerator')}/{cov['third_party'].get('denominator')})")
    w("")

    w("## 2. Version Churn")
    w("")
    for label, key in (("First-party", "first_party"), ("Third-party", "third_party")):
        ch = m["churn"][key]
        w(f"**{label}:**")
        w(f"- Same-version mutation (>1 hash per version): "
          f"{ch['same_version_mutation']['numerator']}/"
          f"{ch['same_version_mutation']['denominator']} "
          f"({ch['same_version_mutation']['pct']}%)")
        w(f"- Multi-version skills: {ch['multi_version_skills']['pct']}%; "
          f"versions/skill median={ch['versions_per_skill']['median']}, "
          f"max={ch['versions_per_skill']['max']}")
        w("")

    w("## 3. Anatomy (analyzed skills)")
    w("")
    w(f"_Denominators: first-party={fp.get('denominator')}, third-party={tp.get('denominator')}._")
    w("")
    w("| Metric | First-party % | Third-party % |")
    w("| --- | --- | --- |")

    def rowpct(label, node_fp, node_tp):
        w(f"| {label} | {(node_fp or {}).get('pct')} | {(node_tp or {}).get('pct')} |")

    rowpct("Code-bearing",
           fp.get("prompt_only_vs_code_bearing", {}).get("code_bearing"),
           tp.get("prompt_only_vs_code_bearing", {}).get("code_bearing"))
    rowpct("Manifest present", fp.get("manifest_present"), tp.get("manifest_present"))
    for f in C.IMPORTANT_FILES:
        rowpct(f"Has `{f}`", (fp.get("important_file_presence") or {}).get(f),
               (tp.get("important_file_presence") or {}).get(f))
    rowpct("Env-var reference present", fp.get("env_var_reference_present"),
           tp.get("env_var_reference_present"))
    rowpct("External URL present", fp.get("external_url_present"),
           tp.get("external_url_present"))
    w("")
    w(f"- File-count distribution — first-party: {fp.get('file_count_distribution')}")
    w(f"- File-count distribution — third-party: {tp.get('file_count_distribution')}")
    w("")

    w("## 4. Capability Families & Risk")
    w("")
    w("_STATIC CAPABILITY SIGNALS — not maliciousness._")
    w("")
    w("| Capability family | First-party % | Third-party % |")
    w("| --- | --- | --- |")
    for fam in C.CAPABILITY_FAMILIES:
        rowpct(fam, (fp.get("capability_family_prevalence") or {}).get(fam),
               (tp.get("capability_family_prevalence") or {}).get(fam))
    w("")
    w("Per-category prevalence:")
    w("")
    w("| Category | First-party % | Third-party % |")
    w("| --- | --- | --- |")
    for cat in C.CANONICAL_CATEGORIES:
        rowpct(cat, (fp.get("category_prevalence") or {}).get(cat),
               (tp.get("category_prevalence") or {}).get(cat))
    w("")
    w("Risk level distribution:")
    w("")
    w("| Risk | First-party % | Third-party % |")
    w("| --- | --- | --- |")
    for tier in C.risk_tiers_sorted(fp, tp):
        rowpct(tier, (fp.get("risk_level_distribution") or {}).get(tier),
               (tp.get("risk_level_distribution") or {}).get(tier))
    w("")
    for key, label in (("top_domains", "Top external domains"),
                       ("top_dependencies", "Top dependencies"),
                       ("top_indicators", "Top indicators")):
        w(f"**{label}:**")
        for party in ("first_party", "third_party"):
            items = m[key][party][:8]
            w(f"- {party}: " + ", ".join(f"`{k}`={n}" for k, n in items))
        w("")

    w("## Caveats")
    w("")
    for note in m["caveats"]:
        w(f"- {note}")
    w("")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="First-party vs third-party skill metrics (read-only).")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--analyzer-name", default=DEFAULT_ANALYZER_NAME)
    parser.add_argument("--analyzer-version", default=None)
    parser.add_argument("--analysis-run-id", type=int, default=None,
                        help="Pin capability metrics to this run (default: latest "
                             "successful run for the analyzer name).")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    (out_dir / "tables").mkdir(parents=True, exist_ok=True)

    engine = build_engine(get_settings())
    with engine.connect() as conn:
        C.begin_readonly(conn)
        ex = C.Exporter(conn)

        run = C.select_analysis_run(
            ex, args.analyzer_name, args.analyzer_version, args.analysis_run_id)
        run_id = run["id"] if run else None
        if run is None:
            print("WARNING: no successful analysis run found; capability metrics empty.",
                  file=sys.stderr)
        else:
            print(f"Capability metrics from analysis run #{run_id} "
                  f"({run['analyzer_name']} v{run['analyzer_version']}).")

        # Population + churn (no analysis needed).
        ex.guard("population", lambda: {p: population(ex, p) for p in PARTIES})
        ex.guard("churn", lambda: {p: churn(ex, p) for p in PARTIES})

        # Capability/anatomy profiles from the pinned run.
        profiles: dict[str, Any] = {"first_party": {}, "third_party": {}}
        cov: dict[str, Any] = {"first_party": {}, "third_party": {}}
        if run_id is not None:
            all_rows = C.load_signal_rows(ex, run_id)
            first = [r for r in all_rows if r["source"] == FIRST_PARTY_SOURCE]
            third = [r for r in all_rows if r["source"] != FIRST_PARTY_SOURCE]
            profiles["first_party"] = C.signal_profile(first)
            profiles["third_party"] = C.signal_profile(third)
            ex.guard("coverage", lambda: {p: coverage(ex, p, run_id) for p in PARTIES})
            cov = ex.metrics.get("coverage", cov)

            for key, fn in (("top_domains", C.top_domains),
                            ("top_dependencies", C.top_dependencies),
                            ("top_indicators", C.top_indicators)):
                fp_rows = [[k, n] for k, n in fn(ex, run_id, source=FIRST_PARTY_SOURCE)]
                # third-party = non-clawhub; query per non-clawhub source and merge
                tp_map: dict[str, int] = {}
                for src in [s for s in ("github-skills", "openclaw") ]:
                    for k, n in fn(ex, run_id, source=src):
                        tp_map[k] = tp_map.get(k, 0) + n
                tp_rows = sorted(([k, n] for k, n in tp_map.items()),
                                 key=lambda r: -r[1])[:25]
                ex.metrics[key] = {"first_party": fp_rows, "third_party": tp_rows}
                ex.add_table(f"{key}_first_party", ["value", "count"], fp_rows)
                ex.add_table(f"{key}_third_party", ["value", "count"], tp_rows)

        ex.metrics["profile"] = profiles
        ex.metrics["coverage"] = cov
        ex.metrics["caveats"] = caveats()
        ex.guard("_comparison", lambda: add_comparison_tables(ex, profiles) or "ok")

        prov = build_provenance(ex, args, run)
        ex.metrics["provenance"] = prov
        ex.metrics.pop("_comparison", None)

        md = render_markdown(ex.metrics, prov)
        (out_dir / "party_comparison_metrics.md").write_text(md, encoding="utf-8")
        (out_dir / "party_comparison_metrics.json").write_text(
            json.dumps(ex.metrics, indent=2, default=str), encoding="utf-8")
        csv_paths = C.write_csv_tables(out_dir / "tables", ex.tables)

    print(f"Output directory: {out_dir}")
    print(f"  - {out_dir / 'party_comparison_metrics.md'}")
    print(f"  - {out_dir / 'party_comparison_metrics.json'}")
    for p in csv_paths:
        print(f"  - {p}")
    print(f"\nFailed metrics: {len(ex.failed_metrics) or 'none'}")
    for f in ex.failed_metrics:
        print(f"  - {f['metric']}: {f['error']}")
    pop = ex.metrics.get("population", {})
    if pop:
        print(f"\nFirst-party: {pop['first_party']['distinct_skills']} skills; "
              f"Third-party: {pop['third_party']['distinct_skills']} skills "
              f"(analysis run #{run_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
