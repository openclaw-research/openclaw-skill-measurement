"""
Shared crawl-lifecycle helpers for the OpenClaw/ClawHub metric exporters.

This module owns the crawl-run / presence-absence / reappearance logic that is
common to the removed-skills and reappearance exporters (one source of truth):

  - Loading crawl runs and measuring their catalog coverage.
  - Choosing a trustworthy absence-reference run (coverage rule + confirmation),
    so a truncated-but-'success' walk is not mistaken for a complete catalog.
  - Classifying ever-seen skills into removed / present / present-via-error.
  - Per-skill lifecycle rollups (versions, hashes, first/last seen).
  - Detecting disappear->reappear observation gaps, validated against successful
    crawls so crawler downtime / failed / partial crawls cannot fake a gap.

Presence evidence is asymmetric: ANY run seeing a skill proves presence; only a
COMPLETE successful run's silence proves absence. Failed and partial crawls are
never used as the absence reference, and only 'success' run finish times validate
a reappearance gap.

Read-only: every query runs inside the caller's REPEATABLE READ, READ ONLY
transaction. Imports only leaf helpers from skill_metrics_common (one-way; that
module never imports this one, so there is no cycle).
"""
from __future__ import annotations

import sys
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from skill_metrics_common import Exporter, iso

# Defaults shared by the lifecycle-aware exporters.
DEFAULT_SOURCE = "clawhub"
DEFAULT_REAPPEAR_GAP_DAYS = 5.0
DEFAULT_MIN_COVERAGE_PCT = 80.0
DEFAULT_COVERAGE_WINDOW = 5


# --------------------------------------------------------------------------- #
# Crawl runs and coverage
# --------------------------------------------------------------------------- #


def load_crawl_runs(ex: Exporter, source: str) -> list[dict[str, Any]]:
    rows = ex.q(
        "select id, status, started_at, finished_at, stats from crawl_runs "
        "where source = :src order by id",
        src=source,
    )
    return [
        {"id": rid, "status": status, "started_at": started,
         "finished_at": finished, "stats": stats}
        for (rid, status, started, finished, stats) in rows
    ]


def attempted_count(run: dict[str, Any]) -> int | None:
    """Skills the run tried to process: skills_seen + discovery_errors.

    None when the run predates these stats keys and cannot be coverage-assessed.
    """
    stats = run.get("stats") or {}
    seen = stats.get("skills_seen")
    if not isinstance(seen, int):
        return None
    return seen + (stats.get("discovery_errors") or 0)


def select_reference_run(
    runs: list[dict[str, Any]],
    pinned_id: int | None = None,
    min_coverage_pct: float = DEFAULT_MIN_COVERAGE_PCT,
    coverage_window: int = DEFAULT_COVERAGE_WINDOW,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Choose the absence-reference run by coverage, and explain the choice.

    Rule: among the `coverage_window` most recent successful runs that recorded
    an attempted count, pick the newest attempting >= min_coverage_pct% of the
    window maximum (the benchmark).

    Returns (run, selection); `selection` documents the rule inputs and the
    candidate table for the confirmation prompt and provenance. Outcomes:
    method='pinned' (pinned_id given; rule not applied), 'coverage_rule',
    'latest_success_no_counts' (no counted runs; old-style stats),
    'fallback_benchmark_run' (nothing qualified — must be explicitly
    confirmed), or run=None when nothing is selectable.
    """
    successes = sorted(
        (r for r in runs if r["status"] == "success"),
        key=lambda r: (r["finished_at"] or r["started_at"], r["id"]),
        reverse=True,
    )

    window: list[dict[str, Any]] = []
    for r in successes:
        if attempted_count(r) is not None:
            window.append(r)
        if len(window) >= coverage_window:
            break

    benchmark_run = max(window, key=attempted_count) if window else None
    benchmark = attempted_count(benchmark_run) if benchmark_run else None
    threshold = benchmark * min_coverage_pct / 100.0 if benchmark else None
    # Context for the all-recent-walks-truncated blind spot: how does the
    # window benchmark compare with the largest walk ever recorded?
    alltime_counts = [attempted_count(r) for r in successes]
    alltime_max = max((a for a in alltime_counts if a is not None), default=None)
    benchmark_pct_of_alltime = (
        round(100.0 * benchmark / alltime_max, 1)
        if benchmark is not None and alltime_max else None)

    def pct_of_benchmark(a: int | None) -> float | None:
        if a is None or not benchmark:
            return None
        return round(100.0 * a / benchmark, 1)

    selection: dict[str, Any] = {
        "method": None,
        "min_coverage_pct": min_coverage_pct,
        "coverage_window": coverage_window,
        "benchmark_run_id": benchmark_run["id"] if benchmark_run else None,
        "benchmark_attempted": benchmark,
        "alltime_max_attempted": alltime_max,
        "benchmark_pct_of_alltime_max": benchmark_pct_of_alltime,
        "threshold_attempted": int(threshold) if threshold is not None else None,
        "window_runs": [
            {
                "run_id": r["id"],
                "finished_at": iso(r["finished_at"]),
                "attempted": attempted_count(r),
                "pct_of_benchmark": pct_of_benchmark(attempted_count(r)),
                "qualifies": bool(threshold is not None
                                  and attempted_count(r) >= threshold),
            }
            for r in window
        ],
        "interactive_override": False,
    }

    def choose(run: dict[str, Any] | None, method: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        selection["method"] = method
        if run is not None:
            a = attempted_count(run)
            selection["chosen_run_id"] = run["id"]
            selection["chosen_attempted"] = a
            selection["chosen_pct_of_benchmark"] = pct_of_benchmark(a)
        return run, selection

    if pinned_id is not None:
        pinned = next((r for r in runs if r["id"] == pinned_id), None)
        return choose(pinned, "pinned")
    if not successes:
        return choose(None, "no_successful_runs")
    if not window:
        return choose(successes[0], "latest_success_no_counts")
    for r in window:  # newest first
        if attempted_count(r) >= threshold:
            return choose(r, "coverage_rule")
    return choose(benchmark_run, "fallback_benchmark_run")


def print_selection(ref: dict[str, Any], selection: dict[str, Any]) -> None:
    """Print the candidate table and the chosen reference run."""
    if selection["benchmark_attempted"] is None:
        print("Reference-run selection: no successful run records an attempted "
              "count; the coverage rule cannot be applied.")
    else:
        print(f"Reference-run selection (rule: attempted >= "
              f"{selection['min_coverage_pct']:g}% of benchmark "
              f"{selection['benchmark_attempted']} from run "
              f"#{selection['benchmark_run_id']}, window of "
              f"{selection['coverage_window']} counted successful runs):")
    print(f"  {'run':>6}  {'finished (UTC)':<26}  {'attempted':>9}  "
          f"{'% of bench':>10}  qualifies")
    for row in selection["window_runs"]:
        marker = " <- selected" if row["run_id"] == ref["id"] else ""
        print(f"  #{row['run_id']:>5}  {str(row['finished_at']):<26}  "
              f"{str(row['attempted']):>9}  {str(row['pct_of_benchmark']):>10}  "
              f"{'yes' if row['qualifies'] else 'no'}{marker}")
    if all(row["run_id"] != ref["id"] for row in selection["window_runs"]):
        print(f"  #{ref['id']:>5}  {str(iso(ref['finished_at'])):<26}  "
              f"{str(attempted_count(ref)):>9}  "
              f"{str(selection.get('chosen_pct_of_benchmark')):>10}  -   <- selected"
              f" ({selection['method']})")
    if selection.get("benchmark_pct_of_alltime_max") is not None:
        print(f"  (window benchmark = {selection['benchmark_pct_of_alltime_max']}% "
              f"of the all-time counted maximum, "
              f"{selection['alltime_max_attempted']}; a low value means real "
              "catalog shrinkage OR persistently truncated walks)")
    print(f"Selected: run #{ref['id']} via {selection['method']} "
          f"(status={ref['status']}, attempted={selection.get('chosen_attempted')}, "
          f"{selection.get('chosen_pct_of_benchmark')}% of benchmark)")


def confirm_reference_run(
    ref: dict[str, Any],
    selection: dict[str, Any],
    runs: list[dict[str, Any]],
    assume_yes: bool,
) -> dict[str, Any] | None:
    """Show the selection; let the operator confirm, override, or abort.

    Returns the confirmed run (possibly a different one if the operator typed
    another run id) or None to abort. The prompt is skipped when the run id was
    pinned on the command line (that IS the confirmation), when --yes was
    passed, or when stdin is not a TTY — except that the fallback selection
    (no run met the coverage threshold) is never accepted silently: without a
    TTY it requires --yes or --reference-run-id.
    """
    print_selection(ref, selection)
    if selection["method"] == "pinned" or assume_yes:
        return ref
    fallback = selection["method"] == "fallback_benchmark_run"
    if not sys.stdin.isatty():
        if fallback:
            print("No run met the coverage threshold and stdin is not a TTY: "
                  "refusing to guess. Re-run with --yes to accept run "
                  f"#{ref['id']}, or pin one with --reference-run-id.",
                  file=sys.stderr)
            return None
        print("(stdin is not a TTY; proceeding with the selection above. "
              "Pass --yes to silence this notice.)")
        return ref

    if fallback:
        print("WARNING: no run met the coverage threshold; the fullest recent "
              "run is proposed instead. Confirm carefully.")
    threshold = selection.get("threshold_attempted")
    for _ in range(5):
        answer = input(f"Use crawl run #{ref['id']} as the absence reference? "
                       "[Y/n/<run id>] ").strip().lower()
        if answer in ("", "y", "yes"):
            return ref
        if answer in ("n", "no"):
            return None
        if answer.isdigit():
            chosen = next((r for r in runs if r["id"] == int(answer)), None)
            if chosen is None:
                print(f"Run #{answer} not found for this source.")
                continue
            if chosen["status"] != "success":
                print(f"NOTE: run #{chosen['id']} has status "
                      f"'{chosen['status']}' — absence evidence from a "
                      "non-success run is unreliable.")
            a = attempted_count(chosen)
            if threshold is not None and (a is None or a < threshold):
                print(f"NOTE: run #{chosen['id']} attempted {a}, below the "
                      f"coverage threshold ({threshold}).")
            selection["method"] = "interactive_override"
            selection["interactive_override"] = True
            selection["chosen_run_id"] = chosen["id"]
            selection["chosen_attempted"] = a
            benchmark = selection.get("benchmark_attempted")
            selection["chosen_pct_of_benchmark"] = (
                round(100.0 * a / benchmark, 1) if (a is not None and benchmark) else None)
            return chosen
        print("Answer 'y' to accept, 'n' to abort, or type a crawl run id.")
    print("No valid answer after 5 attempts; aborting.", file=sys.stderr)
    return None


def reference_run_quality(runs: list[dict[str, Any]],
                          ref: dict[str, Any]) -> dict[str, Any]:
    """Absence-evidence quality bounds for the reference run.

    - discovery_errors: listed-but-never-touched slugs are unidentifiable and
      each may be a false removal.
    - coverage drop vs the previous completed (success/partial_success) run:
      the crawler only LOGS this condition; it never fails the run or lands in
      stats, so it is recomputed here from persisted attempted counts.
    """
    stats = ref.get("stats") or {}
    attempted = (stats.get("skills_seen") or 0) + (stats.get("discovery_errors") or 0)

    prev_attempted = None
    prev_id = None
    for r in runs:
        if r["id"] < ref["id"] and r["status"] in ("success", "partial_success"):
            pstats = r.get("stats") or {}
            pa = (pstats.get("skills_seen") or 0) + (pstats.get("discovery_errors") or 0)
            if pa > 0 and (prev_id is None or r["id"] > prev_id):
                prev_id, prev_attempted = r["id"], pa

    drop_pct = None
    if prev_attempted:
        drop_pct = round(100.0 * (prev_attempted - attempted) / prev_attempted, 2)

    return {
        "reference_run_skills_attempted": attempted,
        "reference_run_discovery_errors": stats.get("discovery_errors") or 0,
        "reference_run_pipeline_failures": stats.get("failures") or 0,
        "previous_completed_run_id": prev_id,
        "previous_completed_run_skills_attempted": prev_attempted,
        "coverage_drop_vs_previous_pct": drop_pct,
        "coverage_drop_exceeds_10pct": bool(drop_pct is not None and drop_pct > 10.0),
    }


def error_listed_slugs(run: dict[str, Any]) -> set[str]:
    """source_ids listed in the run's per-skill error_details (discovered but failed)."""
    stats = run.get("stats") or {}
    details = stats.get("error_details") or []
    return {d.get("skill_id") for d in details if isinstance(d, dict) and d.get("skill_id")}


# --------------------------------------------------------------------------- #
# Per-skill lifecycle rollups and classification
# --------------------------------------------------------------------------- #


def load_per_skill_rollup(ex: Exporter, source: str) -> dict[str, dict[str, Any]]:
    """One record per distinct source_id with presence/version/hash rollups."""
    rows = ex.q(
        """
        select source_id,
               min(first_seen_at)          as first_seen,
               max(last_seen_at)           as last_seen,
               max(last_crawl_run_id)      as max_last_run,
               count(*)                    as snapshot_rows,
               count(distinct version)     as versions,
               count(distinct artifact_hash) as hashes,
               bool_or(artifact_hash is not null) as has_artifact
        from skills where source = :src
        group by source_id
        """,
        src=source,
    )
    return {
        sid: {
            "source_id": sid, "first_seen": fs, "last_seen": ls,
            "max_last_run": mlr, "snapshot_rows": sr,
            "versions": nv, "hashes": nh, "has_artifact": ha,
        }
        for (sid, fs, ls, mlr, sr, nv, nh, ha) in rows
    }


def load_mutated_slugs(ex: Exporter, source: str) -> set[str]:
    """source_ids with >=1 (version -> multiple artifact hashes) mutation.

    artifact_hash excludes collector provenance (_detail.json) since the
    2026-07 hash repair, so this reflects genuine content re-publishes.
    Runs against a pre-repair database overcount mutations massively (volatile
    API counters flipped the hash on every verify crawl).
    """
    rows = ex.q(
        "select distinct source_id from skills where source = :src "
        "group by source_id, version having count(distinct artifact_hash) > 1",
        src=source,
    )
    return {r[0] for r in rows}


def load_latest_snapshots(ex: Exporter, source: str) -> dict[str, dict[str, Any]]:
    """Latest snapshot row per source_id (metadata for lists/author metrics)."""
    rows = ex.q(
        """
        select distinct on (source_id)
               source_id, id, name, version, author, license, first_seen_at, last_seen_at
        from skills where source = :src
        order by source_id, last_seen_at desc, id desc
        """,
        src=source,
    )
    return {
        sid: {"source_id": sid, "skill_row_id": rid, "name": name, "version": ver,
              "author": author, "license": lic, "first_seen_at": fs, "last_seen_at": ls}
        for (sid, rid, name, ver, author, lic, fs, ls) in rows
    }


def classify_removed(
    rollup: dict[str, dict[str, Any]],
    ref_run: dict[str, Any],
    error_slugs: set[str],
) -> dict[str, Any]:
    """Split ever-seen skills into removed / present / present_via_error_listing."""
    removed, present, via_error, null_last_run = set(), set(), set(), set()
    for sid, rec in rollup.items():
        mlr = rec["max_last_run"]
        if mlr is not None and mlr >= ref_run["id"]:
            present.add(sid)
        elif sid in error_slugs:
            via_error.add(sid)
        else:
            removed.add(sid)
            if mlr is None:
                null_last_run.add(sid)
    return {
        "removed": removed,
        "present": present,
        "present_via_error_listing": via_error,
        "removed_with_null_last_run": null_last_run,
    }


# --------------------------------------------------------------------------- #
# Reappearance (gap) analysis
# --------------------------------------------------------------------------- #


def find_reappearances(
    ex: Exporter,
    source: str,
    runs: list[dict[str, Any]],
    gap_days: float,
) -> list[dict[str, Any]]:
    """Observation gaps per skill, validated against successful-run times.

    A gap counts only if at least one successful run finished inside it —
    otherwise the silence is crawler downtime (or a failed/partial crawl), not
    registry absence. Lower bound: same-(version,hash) relistings re-touch the
    old row and leave no gap.

    Each gap dict carries: source_id, gap_start, gap_end, gap_days, plus
    hash_before / hash_after (artifact hashes of the last snapshot before the
    gap and the first snapshot after it) and content_changed (bool, or None
    when either hash is missing) so callers can tell whether the skill returned
    with different content.
    """
    success_times = sorted(
        r["finished_at"] for r in runs if r["status"] == "success" and r["finished_at"]
    )
    # (first_seen, last_seen, artifact_hash) per skill.
    intervals: dict[str, list[tuple[datetime, datetime, str | None]]] = defaultdict(list)
    for (sid, fs, ls, h) in ex.q(
        "select source_id, first_seen_at, last_seen_at, artifact_hash "
        "from skills where source = :src",
        src=source,
    ):
        intervals[sid].append((fs, ls, h))

    threshold = timedelta(days=gap_days)
    gaps: list[dict[str, Any]] = []
    for sid, ivs in intervals.items():
        if len(ivs) < 2:
            continue  # single row -> no detectable gap (see docstring)
        ivs.sort(key=lambda t: t[0])
        running_end = ivs[0][1]
        running_end_hash = ivs[0][2]
        for fs, ls, h in ivs[1:]:
            if fs - running_end > threshold:
                covered = any(running_end < t < fs for t in success_times)
                if covered:
                    changed: bool | None = None
                    if running_end_hash and h:
                        changed = running_end_hash != h
                    gaps.append({
                        "source_id": sid,
                        "gap_start": running_end,
                        "gap_end": fs,
                        "gap_days": round((fs - running_end).total_seconds() / 86400, 2),
                        "hash_before": running_end_hash,
                        "hash_after": h,
                        "content_changed": changed,
                    })
            if ls > running_end:
                running_end = ls
                running_end_hash = h
    return gaps
