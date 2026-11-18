"""
Disappearance/reappearance skill metrics for the OpenClaw/ClawHub paper.

Focus population: skills that DISAPPEARED from ClawHub across successful crawls
and later REAPPEARED. This is a lifecycle behavior of security interest — a skill
can be unpublished/taken down and then return, sometimes with changed content.

Definitions
-----------
Reference run R: the coverage-qualified status='success' crawl chosen by the
shared rule (skill_lifecycle_common.select_reference_run). Failed/partial crawls
are never the absence reference.

Reappeared skill (unit = source_id/slug): a skill with >= 1 VALIDATED observation
gap — a later snapshot row whose first_seen_at is more than --reappear-gap-days
(default 5) after all prior rows stopped being touched, AND with at least one
success crawl finishing inside the gap. The success-run check is what stops
crawler downtime / failed / partial crawls from fabricating a disappearance.
Detection is via skill_lifecycle_common.find_reappearances.

Cohorts (source=clawhub):
  reappeared               — has >= 1 validated gap (the focus population)
  reappeared_still_present — reappeared AND present at R
  reappeared_now_removed   — reappeared AND removed at R (came back, gone again)
  permanently_removed      — removed at R AND never reappeared  (contrast)
  stable_retained          — present at R AND never had a gap    (contrast)

Capability/risk signals come from ONE pinned analysis run (default: latest
successful static run, expected v4 run #71); runs are never pooled by version.

Safety: read-only, single REPEATABLE READ, READ ONLY transaction; nothing is
written to S3 or any table.

Usage:
    venv/bin/python scripts/export_reappearance_metrics.py --help
    venv/bin/python scripts/export_reappearance_metrics.py --analysis-run-id 71 --yes
    venv/bin/python scripts/export_reappearance_metrics.py \
        --out-dir ../paper-openclaw-security/results/metrics/2026-07-reappeared-skills

Outputs (git-ignored local staging under --out-dir, copied to the paper repo's
results/metrics/ by hand): reappearance_metrics.md, reappearance_metrics.json,
tables/*.csv.

Limitations
-----------
- LOWER BOUND: a skill relisted under the same (version, artifact_hash) re-touches
  its existing row and erases the gap, so reappearances are undercounted.
- Requires >= 2 snapshot rows; single-row skills are invisible.
- NO capability drift across the gap: only the latest snapshot is analyzed under
  the pinned run, so pre-gap vs post-gap capability cannot be compared.
  content_changed (artifact-hash difference across the gap) is a content-change
  proxy only. Future work: analyze historical snapshots.
- Default source is clawhub; other sources lack multi-crawl history.

Every metric block is guarded: a single failure is recorded under
provenance.failed_metrics and the export continues.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from db.session import build_engine  # noqa: E402
from config import get_settings  # noqa: E402
import skill_metrics_common as C  # noqa: E402
import skill_lifecycle_common as L  # noqa: E402

DEFAULT_OUT_DIR = "paper_metrics/reappeared-skills"
DEFAULT_ANALYZER_NAME = "static"


def iso_week(dt: datetime) -> str:
    y, w, _ = dt.isocalendar()
    return f"{y}-W{w:02d}"


# --------------------------------------------------------------------------- #
# Cohort profiling helpers
# --------------------------------------------------------------------------- #


def cohort_profile(sig_by_sid: dict[str, dict[str, Any]], ids: set[str]) -> dict[str, Any]:
    """Anatomy + capability profile over the analyzed skills in a cohort."""
    return C.signal_profile([sig_by_sid[s] for s in ids if s in sig_by_sid])


def cohort_coverage(sig_by_sid: dict[str, dict[str, Any]], ids: set[str]) -> dict[str, Any]:
    analyzed = sum(1 for s in ids if s in sig_by_sid)
    return {**C.frac(analyzed, len(ids)),
            "definition": "cohort skills with a successful pinned-run result."}


def version_artifact_group(rollup: dict[str, dict[str, Any]],
                           mutated: set[str], ids: set[str]) -> dict[str, Any]:
    recs = [rollup[s] for s in ids if s in rollup]
    denom = len(recs)
    if denom == 0:
        return {"denominator": 0}
    return {
        "denominator": denom,
        "versions_per_skill": C.distribution([float(r["versions"]) for r in recs]),
        "snapshot_rows_per_skill": C.distribution([float(r["snapshot_rows"]) for r in recs]),
        "distinct_hashes_per_skill": C.distribution([float(r["hashes"]) for r in recs]),
        "multi_version_skills": C.frac(sum(1 for r in recs if r["versions"] > 1), denom),
        "same_version_mutated_skills": C.frac(
            sum(1 for r in recs if r["source_id"] in mutated), denom),
    }


def author_concentration(ex: C.Exporter, latest: dict[str, dict[str, Any]],
                         reappeared: set[str]) -> dict[str, Any]:
    per_author: dict[str, int] = defaultdict(int)
    for sid in reappeared:
        author = (latest.get(sid, {}) or {}).get("author") or "(none)"
        per_author[author] += 1
    ranked = sorted(per_author.items(), key=lambda kv: -kv[1])
    total = sum(per_author.values())
    n_auth = len(ranked)

    def share(k: int) -> dict[str, Any]:
        return C.frac(sum(n for _, n in ranked[:k]), total)

    ex.add_table(
        "reappeared_by_author",
        ["author", "reappeared_skills"],
        [[a, n] for a, n in ranked],
    )
    return {
        "authors_with_reappearance": n_auth,
        "reappeared_skills_total": total,
        "top_authors_by_reappeared_count": [
            {"author": a, "reappeared_skills": n} for a, n in ranked[:20]],
        "concentration": {
            "top_1_author_share": share(1) if n_auth else None,
            "top_10_authors_share": share(10) if n_auth else None,
            "top_1pct_authors_share": share(max(1, n_auth // 100)) if n_auth else None,
            "top_10pct_authors_share": share(max(1, n_auth // 10)) if n_auth else None,
        },
        "authors_with_2plus_reappeared": sum(1 for _, n in ranked if n >= 2),
        "note": "Author taken from each skill's latest snapshot row.",
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def build_provenance(ex: C.Exporter, args, run: dict[str, Any] | None,
                     selection: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any]:
    try:
        db_name = ex.scalar("select current_database()")
    except Exception:
        db_name = None
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": C.git_commit_hash(),
        "database_name": db_name,
        "source_filter": args.source,
        "selected_analyzer_name": args.analyzer_name,
        "selected_analysis_run_id": run["id"] if run else None,
        "selected_analyzer_version": run["analyzer_version"] if run else None,
        "analysis_run_finished_at": C.iso(run["finished_at"]) if run else None,
        "reference_run_id": ref["id"],
        "reference_run_finished_at": C.iso(ref["finished_at"]),
        "reference_run_selection": selection,
        "reappear_gap_days_threshold": args.reappear_gap_days,
        "read_only_transaction": "REPEATABLE READ, READ ONLY",
        "reappeared_definition": (
            "Distinct source_id with >=1 validated observation gap: a later "
            "snapshot begins > reappear_gap_days after prior rows stopped being "
            "touched, with >=1 success crawl finishing inside the gap. Failed/"
            "partial crawls never validate a gap. Lower bound: same-(version,hash) "
            "relisting erases the gap."
        ),
        "failed_metrics": ex.failed_metrics,
    }


def caveats(selection: dict[str, Any], ref_quality: dict[str, Any]) -> list[str]:
    notes = []
    if ref_quality.get("coverage_drop_exceeds_10pct"):
        notes.append(
            f"CATALOG COVERAGE DROP at the reference run "
            f"({ref_quality.get('coverage_drop_vs_previous_pct')}% vs previous "
            "completed run): presence/absence at R is less reliable; consider "
            "--reference-run-id.")
    if selection.get("method") == "fallback_benchmark_run":
        notes.append(
            "No crawl met the coverage threshold; reference is the fullest recent "
            "run. Cohort membership (removed vs present) is unreliable.")
    notes += [
        "REAPPEARANCE IS A LOWER BOUND: a skill relisted under the same "
        "(version, artifact_hash) re-touches its existing row and leaves no gap, "
        "so it is not counted. Only reappearances that produced a new snapshot "
        "row and spanned a successful crawl are visible.",
        "Gaps are validated only against SUCCESS crawl finish times, so crawler "
        "downtime and failed/partial crawls cannot fabricate a disappearance.",
        "content_changed compares the artifact hash before vs after the gap; it is "
        "a content-change proxy, NOT capability drift (only the latest snapshot is "
        "analyzed under the pinned run). It is ~100% by construction (identical "
        "relistings create no gap); use overlap_same_version_mutated for signal.",
        "Reappeared skills tend to have a NEW latest snapshot that post-dates the "
        "pinned analysis run, so their analysis coverage is low and their "
        "capability/anatomy numbers are computed on a minority of the cohort — "
        "treat them as preliminary until a fresh analyzer run covers them.",
        "Capability/risk numbers are STATIC signals, not maliciousness judgments.",
        "Cohorts differ greatly in size; compare rates (pct), not raw counts. "
        "URL/env-var evidence is capped per result (75); 'present' rates are "
        "reliable, totals are lower bounds.",
        "The database is live; all numbers come from one REPEATABLE READ snapshot.",
    ]
    return notes


def _row_pct(w, label, *nodes):
    w(f"| {label} | " + " | ".join(str((n or {}).get('pct')) for n in nodes) + " |")


def render_markdown(m: dict[str, Any], prov: dict[str, Any]) -> str:
    L_: list[str] = []
    w = L_.append
    ov = m.get("reappearance_overview", {})
    prof = m.get("profiles", {})
    rp = prof.get("reappeared", {})
    pr = prof.get("permanently_removed", {})
    st = prof.get("stable_retained", {})

    w("# OpenClaw / ClawHub — Disappearance/Reappearance Skills")
    w("")
    w("> Skills that disappeared from ClawHub across successful crawls and later "
      "reappeared. Static capability signals only — see Caveats.")
    w("")
    w("## Provenance")
    w("")
    w(f"- Generated (UTC): `{prov['generated_at_utc']}`")
    w(f"- Git commit: `{prov['git_commit']}`")
    w(f"- Database: `{prov['database_name']}`; source: `{prov['source_filter']}`")
    w(f"- Reference crawl run: #{prov['reference_run_id']} "
      f"(finished `{prov['reference_run_finished_at']}`)")
    w(f"- Capability metrics from analysis run `#{prov['selected_analysis_run_id']}` "
      f"(`{prov['selected_analyzer_name']} v{prov['selected_analyzer_version']}`)")
    w(f"- Reappearance gap threshold: {prov['reappear_gap_days_threshold']} days")
    w(f"- Failed metrics: {len(prov['failed_metrics']) or 'none'}")
    w("")

    w("## 1. Reappearance Overview & Lifecycle")
    w("")
    w(f"- Reappeared skills: **{ov.get('reappeared_skills')}** of "
      f"{ov.get('ever_seen_skills')} ever-seen "
      f"({ov.get('reappeared_share_pct')}%)")
    w(f"- Gap episodes: {ov.get('gap_episodes')} across "
      f"{ov.get('reappeared_skills')} skills; gaps/skill: "
      f"{ov.get('gaps_per_skill_distribution')}")
    w(f"- Gap length (days): {ov.get('gap_days_distribution')}")
    w(f"- Reappeared & still present: {ov.get('reappeared_still_present')}; "
      f"reappeared & now removed again: {ov.get('reappeared_now_removed')}")
    cov = ov.get("analysis_coverage", {})
    w(f"- Analysis coverage of reappeared: {cov.get('numerator')}/"
      f"{cov.get('denominator')} ({cov.get('pct')}%)")
    w(f"- Reappearances by ISO week of return: `{ov.get('reappeared_by_iso_week')}`")
    w("")

    cc = m.get("content_behavior", {})
    w("## 2. Content Behavior Across the Gap")
    w("")
    w("_Hash before vs after the gap (content-change proxy, not capability drift). "
      "**content_changed is ~100% by construction** — an identical relisting re-touches "
      "the old row and leaves no gap, so only content-changed returns are detectable; "
      "identical relistings are the invisible lower bound._")
    w("")
    sk = cc.get("skills_returned_changed", {})
    gp = cc.get("gaps_with_content_change", {})
    w(f"- Skills returned with changed content (structural ~100%): "
      f"{sk.get('numerator')}/{sk.get('denominator')} ({sk.get('pct')}%)")
    w(f"- Gap episodes with content change (structural ~100%): {gp.get('numerator')}/"
      f"{gp.get('denominator')} ({gp.get('pct')}%)")
    w(f"- **Returned under the SAME version with new content (re-publish, not a "
      f"version bump): {cc.get('overlap_same_version_mutated', {}).get('pct')}%** "
      "— the more informative cut.")
    w("")

    va = m.get("version_artifact_behavior", {})
    w("## 3. Version / Artifact Behavior (by cohort)")
    w("")
    w("| Metric | Reappeared | Perm. removed | Stable retained |")
    w("| --- | --- | --- | --- |")
    for key, label in (("versions_per_skill", "Versions/skill (median)"),
                       ("snapshot_rows_per_skill", "Snapshot rows/skill (median)"),
                       ("distinct_hashes_per_skill", "Distinct hashes/skill (median)")):
        w(f"| {label} | "
          f"{(va.get('reappeared', {}).get(key) or {}).get('median')} | "
          f"{(va.get('permanently_removed', {}).get(key) or {}).get('median')} | "
          f"{(va.get('stable_retained', {}).get(key) or {}).get('median')} |")
    _row_pct(w, "Multi-version skills %",
             va.get("reappeared", {}).get("multi_version_skills"),
             va.get("permanently_removed", {}).get("multi_version_skills"),
             va.get("stable_retained", {}).get("multi_version_skills"))
    _row_pct(w, "Same-version mutated %",
             va.get("reappeared", {}).get("same_version_mutated_skills"),
             va.get("permanently_removed", {}).get("same_version_mutated_skills"),
             va.get("stable_retained", {}).get("same_version_mutated_skills"))
    w("")

    w("## 4. Anatomy (by cohort)")
    w("")
    w(f"_Analyzed denominators: reappeared={rp.get('denominator')}, "
      f"permanently_removed={pr.get('denominator')}, "
      f"stable_retained={st.get('denominator')}._")
    w("")
    w("| Metric | Reappeared % | Perm. removed % | Stable retained % |")
    w("| --- | --- | --- | --- |")
    _row_pct(w, "Code-bearing",
             rp.get("prompt_only_vs_code_bearing", {}).get("code_bearing"),
             pr.get("prompt_only_vs_code_bearing", {}).get("code_bearing"),
             st.get("prompt_only_vs_code_bearing", {}).get("code_bearing"))
    _row_pct(w, "Manifest present", rp.get("manifest_present"),
             pr.get("manifest_present"), st.get("manifest_present"))
    for f in C.IMPORTANT_FILES:
        _row_pct(w, f"Has `{f}`",
                 (rp.get("important_file_presence") or {}).get(f),
                 (pr.get("important_file_presence") or {}).get(f),
                 (st.get("important_file_presence") or {}).get(f))
    _row_pct(w, "Env-var present", rp.get("env_var_reference_present"),
             pr.get("env_var_reference_present"), st.get("env_var_reference_present"))
    _row_pct(w, "External URL present", rp.get("external_url_present"),
             pr.get("external_url_present"), st.get("external_url_present"))
    w("")

    w("## 5. Capability & Risk (by cohort)")
    w("")
    w("_STATIC CAPABILITY SIGNALS — not maliciousness._")
    w("")
    w("| Category | Reappeared % | Perm. removed % | Stable retained % |")
    w("| --- | --- | --- | --- |")
    for cat in C.CANONICAL_CATEGORIES:
        _row_pct(w, cat,
                 (rp.get("category_prevalence") or {}).get(cat),
                 (pr.get("category_prevalence") or {}).get(cat),
                 (st.get("category_prevalence") or {}).get(cat))
    w("")
    w("Capability families:")
    w("")
    w("| Family | Reappeared % | Perm. removed % | Stable retained % |")
    w("| --- | --- | --- | --- |")
    for fam in C.CAPABILITY_FAMILIES:
        _row_pct(w, fam,
                 (rp.get("capability_family_prevalence") or {}).get(fam),
                 (pr.get("capability_family_prevalence") or {}).get(fam),
                 (st.get("capability_family_prevalence") or {}).get(fam))
    w("")
    w("Risk level distribution:")
    w("")
    w("| Risk | Reappeared % | Perm. removed % | Stable retained % |")
    w("| --- | --- | --- | --- |")
    for tier in C.risk_tiers_sorted(rp, pr, st):
        _row_pct(w, tier,
                 (rp.get("risk_level_distribution") or {}).get(tier),
                 (pr.get("risk_level_distribution") or {}).get(tier),
                 (st.get("risk_level_distribution") or {}).get(tier))
    w("")

    au = m.get("author_concentration", {})
    w("## 6. Author Concentration (reappeared)")
    w("")
    w(f"- Authors with >=1 reappeared skill: {au.get('authors_with_reappearance')}")
    w(f"- Authors with >=2 reappeared skills: {au.get('authors_with_2plus_reappeared')}")
    conc = au.get("concentration", {})
    for k in ("top_1_author_share", "top_10_authors_share",
              "top_1pct_authors_share", "top_10pct_authors_share"):
        v = conc.get(k) or {}
        w(f"- {k}: {v.get('numerator')}/{v.get('denominator')} ({v.get('pct')}%)")
    top = au.get("top_authors_by_reappeared_count", [])
    if top:
        w("")
        w("| Author | Reappeared skills |")
        w("| --- | --- |")
        for r in top[:10]:
            w(f"| {r['author']} | {r['reappeared_skills']} |")
    w("")

    w("## 7. Top Domains / Dependencies / Indicators (reappeared)")
    w("")
    for key, label in (("top_domains", "Top external domains"),
                       ("top_dependencies", "Top dependencies"),
                       ("top_indicators", "Top indicators")):
        items = m.get(key) or []
        if items:
            w(f"- {label}: " + ", ".join(f"`{k}`={n}" for k, n in items[:10]))
    w("")

    s = m.get("sanity", {})
    w("## Data Quality / Sanity")
    w("")
    w(f"- Crawl runs by status: `{s.get('crawl_runs_by_status')}`")
    rq = s.get("reference_run_quality", {})
    w(f"- Reference run attempted {rq.get('reference_run_skills_attempted')} "
      f"(discovery errors {rq.get('reference_run_discovery_errors')}); coverage "
      f"drop vs previous completed: {rq.get('coverage_drop_vs_previous_pct')}% "
      f"(exceeds 10%: {rq.get('coverage_drop_exceeds_10pct')})")
    w(f"- Ever-seen skills: {s.get('ever_seen_skills')}; present: "
      f"{s.get('present_skills')}; removed: {s.get('removed_skills')}")
    w("")

    w("## Caveats")
    w("")
    for note in m.get("caveats", []):
        w(f"- {note}")
    w("")
    return "\n".join(L_)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only disappearance/reappearance skill metrics exporter.")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--source", default=L.DEFAULT_SOURCE)
    parser.add_argument("--analyzer-name", default=DEFAULT_ANALYZER_NAME)
    parser.add_argument("--analyzer-version", default=None)
    parser.add_argument("--analysis-run-id", type=int, default=None,
                        help="Pin capability metrics to this analysis_run_id "
                             "(default: latest successful run for the analyzer name).")
    parser.add_argument("--reappear-gap-days", type=float,
                        default=L.DEFAULT_REAPPEAR_GAP_DAYS)
    parser.add_argument("--reference-run-id", type=int, default=None,
                        help="Pin the absence-reference crawl run (bypasses the "
                             "coverage rule and confirmation prompt).")
    parser.add_argument("--min-coverage-pct", type=float, default=L.DEFAULT_MIN_COVERAGE_PCT)
    parser.add_argument("--coverage-window", type=int, default=L.DEFAULT_COVERAGE_WINDOW)
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Accept the selected reference run without prompting.")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    (out_dir / "tables").mkdir(parents=True, exist_ok=True)

    engine = build_engine(get_settings())
    with engine.connect() as conn:
        C.begin_readonly(conn)
        ex = C.Exporter(conn)

        # Reference run (absence basis).
        runs = L.load_crawl_runs(ex, args.source)
        ref, selection = L.select_reference_run(
            runs, pinned_id=args.reference_run_id,
            min_coverage_pct=args.min_coverage_pct,
            coverage_window=args.coverage_window)
        if ref is None:
            print(f"No usable reference crawl run for source '{args.source}'.",
                  file=sys.stderr)
            return 1
        ref = L.confirm_reference_run(ref, selection, runs, assume_yes=args.yes)
        if ref is None:
            print("Reference run not confirmed; no metrics computed.", file=sys.stderr)
            return 1

        # Cohorts.
        rollup = L.load_per_skill_rollup(ex, args.source)
        latest = L.load_latest_snapshots(ex, args.source)
        mutated = L.load_mutated_slugs(ex, args.source)
        classes = L.classify_removed(rollup, ref, L.error_listed_slugs(ref))
        removed, present = classes["removed"], classes["present"]

        gaps = L.find_reappearances(ex, args.source, runs, args.reappear_gap_days)
        reappeared = {g["source_id"] for g in gaps}
        reappeared_still_present = reappeared & present
        reappeared_now_removed = reappeared & removed
        permanently_removed = removed - reappeared
        stable_retained = present - reappeared

        # Pinned analysis run + per-skill signals.
        run = C.select_analysis_run(
            ex, args.analyzer_name, args.analyzer_version, args.analysis_run_id)
        run_id = run["id"] if run else None
        sig_by_sid: dict[str, dict[str, Any]] = {}
        if run_id is not None:
            print(f"Capability metrics from analysis run #{run_id} "
                  f"({run['analyzer_name']} v{run['analyzer_version']}).")
            sig_by_sid = {r["source_id"]: r
                          for r in C.load_signal_rows(ex, run_id, source=args.source)}
        else:
            print("No successful analysis run found; capability metrics empty.",
                  file=sys.stderr)

        # --- Metric blocks (guarded) ---

        def overview() -> dict[str, Any]:
            per_skill_gaps: dict[str, int] = defaultdict(int)
            by_week: dict[str, int] = defaultdict(int)
            for g in gaps:
                per_skill_gaps[g["source_id"]] += 1
                if g["gap_end"]:
                    by_week[iso_week(g["gap_end"])] += 1
            ex.add_table(
                "reappearance_gaps",
                ["source_id", "gap_start", "gap_end", "gap_days",
                 "hash_before", "hash_after", "content_changed", "currently_removed"],
                [[g["source_id"], C.iso(g["gap_start"]), C.iso(g["gap_end"]),
                  g["gap_days"], g["hash_before"], g["hash_after"],
                  g["content_changed"], g["source_id"] in removed] for g in gaps],
            )
            ex.add_table(
                "reappeared_skills",
                ["source_id", "name", "author", "gap_count", "versions", "hashes",
                 "first_seen", "last_seen", "currently_removed"],
                [[sid, (latest.get(sid, {}) or {}).get("name"),
                  (latest.get(sid, {}) or {}).get("author"),
                  per_skill_gaps[sid], rollup.get(sid, {}).get("versions"),
                  rollup.get(sid, {}).get("hashes"),
                  C.iso(rollup.get(sid, {}).get("first_seen")),
                  C.iso(rollup.get(sid, {}).get("last_seen")),
                  sid in removed] for sid in sorted(reappeared)],
            )
            ex.add_table(
                "reappeared_by_week",
                ["iso_week_of_return", "reappeared_gap_episodes"],
                [[wk, c] for wk, c in sorted(by_week.items())],
            )
            ever = len(rollup)
            return {
                "ever_seen_skills": ever,
                "reappeared_skills": len(reappeared),
                "reappeared_share_pct": (round(100.0 * len(reappeared) / ever, 2)
                                         if ever else None),
                "gap_episodes": len(gaps),
                "gaps_per_skill_distribution": C.distribution(
                    [float(v) for v in per_skill_gaps.values()]),
                "gap_days_distribution": C.distribution([g["gap_days"] for g in gaps]),
                "reappeared_still_present": len(reappeared_still_present),
                "reappeared_now_removed": len(reappeared_now_removed),
                "analysis_coverage": cohort_coverage(sig_by_sid, reappeared),
                "reappeared_by_iso_week": dict(sorted(by_week.items())),
            }

        ex.guard("reappearance_overview", overview)

        def content_behavior() -> dict[str, Any]:
            known = [g for g in gaps if g["content_changed"] is not None]
            changed = [g for g in known if g["content_changed"]]
            skill_changed: dict[str, bool | None] = {}
            for g in gaps:
                sid, c = g["source_id"], g["content_changed"]
                if c is True:
                    skill_changed[sid] = True
                elif sid not in skill_changed:
                    skill_changed[sid] = False if c is False else None
            skills_known = [s for s, v in skill_changed.items() if v is not None]
            skills_changed = [s for s in skills_known if skill_changed[s]]
            return {
                "skills_returned_changed": C.frac(len(skills_changed), len(skills_known)),
                "gaps_with_content_change": C.frac(len(changed), len(known)),
                "overlap_same_version_mutated": C.frac(
                    len(reappeared & mutated), len(reappeared)),
                "note": (
                    "content_changed = artifact hash differs before vs after the gap. "
                    "This is ~100% BY CONSTRUCTION: a same-(version,hash) relisting "
                    "re-touches the existing row (updating last_seen_at) and creates no "
                    "new row, so it produces no detectable gap. The detectable "
                    "reappearances are therefore exactly the content-changed returns; "
                    "identical-content relistings are the invisible lower-bound "
                    "population. overlap_same_version_mutated is the more informative "
                    "cut: reappeared skills that returned under the SAME version with "
                    "different content (a re-publish, not a version bump)."
                ),
            }

        ex.guard("content_behavior", content_behavior)

        ex.guard("version_artifact_behavior", lambda: {
            "reappeared": version_artifact_group(rollup, mutated, reappeared),
            "permanently_removed": version_artifact_group(rollup, mutated, permanently_removed),
            "stable_retained": version_artifact_group(rollup, mutated, stable_retained),
            "note": "Cohorts by source_id; contrast columns for interpretation.",
        })

        ex.guard("profiles", lambda: {
            "reappeared": cohort_profile(sig_by_sid, reappeared),
            "permanently_removed": cohort_profile(sig_by_sid, permanently_removed),
            "stable_retained": cohort_profile(sig_by_sid, stable_retained),
        })

        ex.guard("author_concentration",
                 lambda: author_concentration(ex, latest, reappeared))

        if run_id is not None and reappeared:
            ids = sorted(reappeared)
            ex.guard("top_domains", lambda: [
                [d, n] for d, n in C.top_domains(ex, run_id, source=args.source, source_ids=ids)])
            ex.guard("top_dependencies", lambda: [
                [d, n] for d, n in C.top_dependencies(ex, run_id, source=args.source, source_ids=ids)])
            ex.guard("top_indicators", lambda: [
                [d, n] for d, n in C.top_indicators(ex, run_id, source=args.source, source_ids=ids)])
            for key in ("top_domains", "top_dependencies", "top_indicators"):
                ex.add_table(f"reappeared_{key}", ["value", "count"], ex.metrics.get(key, []))

        # Cohort comparison + per-cohort CSVs.
        def comparison_tables() -> str:
            prof = ex.metrics.get("profiles", {})
            rp2, pr2, st2 = (prof.get("reappeared", {}), prof.get("permanently_removed", {}),
                             prof.get("stable_retained", {}))
            ex.add_table(
                "reappeared_category_prevalence",
                ["category", "reappeared_pct", "permanently_removed_pct", "stable_retained_pct"],
                [[cat,
                  ((rp2.get("category_prevalence") or {}).get(cat) or {}).get("pct"),
                  ((pr2.get("category_prevalence") or {}).get(cat) or {}).get("pct"),
                  ((st2.get("category_prevalence") or {}).get(cat) or {}).get("pct")]
                 for cat in C.CANONICAL_CATEGORIES])
            ex.add_table(
                "reappeared_risk_distribution",
                ["risk_level", "reappeared_pct", "permanently_removed_pct", "stable_retained_pct"],
                [[tier,
                  ((rp2.get("risk_level_distribution") or {}).get(tier) or {}).get("pct"),
                  ((pr2.get("risk_level_distribution") or {}).get(tier) or {}).get("pct"),
                  ((st2.get("risk_level_distribution") or {}).get(tier) or {}).get("pct")]
                 for tier in C.risk_tiers_sorted(rp2, pr2, st2)])
            return "ok"

        ex.guard("_comparison", comparison_tables)

        # Sanity block.
        by_status: dict[str, int] = defaultdict(int)
        for r in runs:
            by_status[r["status"]] += 1
        ex.metrics["sanity"] = {
            "crawl_runs_by_status": dict(by_status),
            "reference_run_quality": L.reference_run_quality(runs, ref),
            "ever_seen_skills": len(rollup),
            "present_skills": len(present),
            "removed_skills": len(removed),
            "reappeared_skills": len(reappeared),
        }

        prov = build_provenance(ex, args, run, selection, ref)
        ex.metrics["caveats"] = caveats(selection, ex.metrics["sanity"]["reference_run_quality"])
        ex.metrics["provenance"] = prov
        ex.metrics.pop("_comparison", None)

        md = render_markdown(ex.metrics, prov)
        (out_dir / "reappearance_metrics.md").write_text(md, encoding="utf-8")
        (out_dir / "reappearance_metrics.json").write_text(
            json.dumps(ex.metrics, indent=2, default=str), encoding="utf-8")
        csv_paths = C.write_csv_tables(out_dir / "tables", ex.tables)

    print(f"Output directory: {out_dir}")
    print(f"  - {out_dir / 'reappearance_metrics.md'}")
    print(f"  - {out_dir / 'reappearance_metrics.json'}")
    for p in csv_paths:
        print(f"  - {p}")
    print(f"\nFailed metrics: {len(ex.failed_metrics) or 'none'}")
    for f in ex.failed_metrics:
        print(f"  - {f['metric']}: {f['error']}")
    ov = ex.metrics.get("reappearance_overview", {})
    print(f"\nReappeared skills: {ov.get('reappeared_skills')} / "
          f"{ov.get('ever_seen_skills')} ever-seen '{args.source}' "
          f"({ov.get('reappeared_share_pct')}%); "
          f"reference run #{ref['id']}, analysis run #{run_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
