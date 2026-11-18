"""
removal_reappearance_analysis.py

Computes removal and reappearance metrics for ClawHub skills.

Usage:
    python scripts/removal_reappearance_analysis.py [--source clawhub] [--output-dir reports/]

Output:
    - Console report with all metrics
    - CSV files for paper tables (if --output-dir specified)
"""

import argparse
import csv
import os
import statistics
from collections import Counter, defaultdict
from datetime import timezone

import psycopg2

# Config

DEFAULT_DSN = "dbname=skill_collector user=collector_user password=CHANGE_ME host=localhost port=5432"
EXCLUDE_MONTH = "2026-05"  # Initial crawl month — excluded from monthly tables
COVERAGE_STATUSES = ("success", "partial_success")  # Exclude 'running', 'failed'


# DB helpers

def get_connection(dsn: str):
    return psycopg2.connect(dsn)


def load_crawl_runs(conn, source: str) -> list[tuple]:
    """Return coverage-qualified crawl runs ordered by id."""
    cur = conn.cursor()
    cur.execute("""
        SELECT id, started_at, status, stats
        FROM crawl_runs
        WHERE source = %s
        AND status IN %s
        ORDER BY id
    """, (source, COVERAGE_STATUSES))
    return cur.fetchall()


def load_skill_rows(conn, source: str) -> list[tuple]:
    """Return all skill snapshots ordered by source_id, first_seen_at."""
    cur = conn.cursor()
    cur.execute("""
        SELECT source_id, author, name, version,
               first_crawl_run_id, last_crawl_run_id,
               first_seen_at, last_seen_at,
               artifact_hash
        FROM skills
        WHERE source = %s
        ORDER BY source_id, first_seen_at
    """, (source,))
    return cur.fetchall()

# Core analysis

def build_next_crawl(crawl_run_ids: list[int]) -> dict[int, int]:
    return {crawl_run_ids[i]: crawl_run_ids[i+1]
            for i in range(len(crawl_run_ids) - 1)}


def analyze(conn, source: str) -> dict:
    # Load data
    crawl_runs = load_crawl_runs(conn, source)
    crawl_run_ids = [r[0] for r in crawl_runs]
    crawl_run_dates = {r[0]: r[1] for r in crawl_runs}
    crawl_run_set = set(crawl_run_ids)
    latest_run_id = crawl_run_ids[-1]
    next_crawl = build_next_crawl(crawl_run_ids)

    rows = load_skill_rows(conn, source)

    # Group by source_id
    skill_rows = defaultdict(list)
    for row in rows:
        skill_rows[row[0]].append(row)

    total_ever = len(skill_rows)

    # Reference date = most recent last_seen_at across all skills
    # Reference date = latest crawl run date
    reference_date = crawl_run_dates[latest_run_id]

    # Removal threshold: 14 days
    # P(false positive) = 0.16^7 = 0.0000003 (essentially zero)
    # 14 days = 7 crawl cycles at 48h cadence
    REMOVAL_THRESHOLD_DAYS = 14

    # REMOVALS
    # A skill is removed if MAX(last_seen_at) < reference_date - 14 days
    # This approach is independent of last_crawl_run_id and crawl coverage gaps
    from datetime import timedelta
    removal_cutoff = reference_date - timedelta(days=REMOVAL_THRESHOLD_DAYS)

    removed_distinct = set()
    monthly_removed_distinct = defaultdict(set)
    lifespan_days = []

    for source_id, versions in skill_rows.items():
        max_last_seen = max(v[7] for v in versions)
        if max_last_seen < removal_cutoff:
            removed_distinct.add(source_id)
            # Month of removal = month of max_last_seen
            month = max_last_seen.strftime('%Y-%m')
            if month != EXCLUDE_MONTH:
                monthly_removed_distinct[month].add(source_id)
            # Lifespan
            first_seen = min(v[6] for v in versions)
            lifespan_days.append((max_last_seen - first_seen).days)

    removal_events = len(removed_distinct)  # each distinct skill = one removal

    # REAPPEARANCES
    # A reappearance: skill absent from >=1 crawl, then seen again
    # Still uses crawl run sequence for detection
    reapp_distinct = set()
    reapp_events = 0
    monthly_reapp_events = Counter()
    reapp_gap_days = []
    name_changed = 0
    content_changed = 0
    version_downgraded = 0

    for source_id, versions in skill_rows.items():
        if len(versions) <= 1:
            continue
        versions_sorted = sorted(versions, key=lambda x: x[6])  # first_seen_at

        for i in range(len(versions_sorted) - 1):
            last_seen_prev = versions_sorted[i][7]   # last_seen_at of row i
            first_seen_next = versions_sorted[i+1][6] # first_seen_at of row i+1
            gap = (first_seen_next - last_seen_prev).days
            if gap < 0:
                continue
            if gap <= REMOVAL_THRESHOLD_DAYS:
                continue  # gap too small — likely crawler artifact, not true reappearance

            # True reappearance — absent for >14 days
            reapp_distinct.add(source_id)
            reapp_events += 1
            reapp_gap_days.append(gap)

            # Return month
            month = first_seen_next.strftime('%Y-%m')
            if month != EXCLUDE_MONTH:
                monthly_reapp_events[month] += 1

            # Content/name/version changes
            prev = versions_sorted[i]
            nxt = versions_sorted[i+1]
            if prev[2] != nxt[2]:  # name
                name_changed += 1
            if prev[8] != nxt[8]:  # artifact_hash
                content_changed += 1
            try:
                prev_ver = tuple(int(x) for x in prev[3].split('.') if x.isdigit()) if prev[3] else ()
                nxt_ver = tuple(int(x) for x in nxt[3].split('.') if x.isdigit()) if nxt[3] else ()
                if nxt_ver < prev_ver:
                    version_downgraded += 1
            except Exception:
                pass

    # AUTHOR CONCENTRATION IN REMOVALS
    author_removal_counts = Counter()
    for source_id in removed_distinct:
        versions = skill_rows[source_id]
        author = versions[0][1]
        if author:
            author_removal_counts[author] += 1

    total_authors_removed = len(author_removal_counts)
    sorted_author_counts = sorted(author_removal_counts.values(), reverse=True)
    top1_n = max(1, int(total_authors_removed * 0.01))
    top10_n = max(1, int(total_authors_removed * 0.10))
    top1_skills = sum(sorted_author_counts[:top1_n])
    top10_skills = sum(sorted_author_counts[:top10_n])
    top10_authors_skills = sum(sorted_author_counts[:10])
    total_with_author = sum(author_removal_counts.values())

    author_total_counts = Counter()
    for source_id, versions in skill_rows.items():
        author = versions[0][1]
        if author:
            author_total_counts[author] += 1

    authors_all_removed = sum(
        1 for author, removed_count in author_removal_counts.items()
        if removed_count == author_total_counts.get(author, 0)
    )

    return {
        "total_ever": total_ever,
        "crawl_runs": crawl_runs,
        "latest_run_id": latest_run_id,
        "latest_run_date": crawl_run_dates[latest_run_id].date(),
        "reference_date": reference_date.date(),
        "removal_threshold_days": REMOVAL_THRESHOLD_DAYS,
        "removal_cutoff": removal_cutoff.date(),

        # Removals
        "removed_distinct": len(removed_distinct),
        "removal_events": len(removed_distinct) + reapp_events,
        "monthly_removed_distinct": {k: len(v) for k, v in monthly_removed_distinct.items()},
        "lifespan_days": lifespan_days,

        # Reappearances
        "reapp_distinct": len(reapp_distinct),
        "reapp_events": reapp_events,
        "monthly_reapp_events": monthly_reapp_events,
        "reapp_gap_days": reapp_gap_days,
        "name_changed": name_changed,
        "content_changed": content_changed,
        "version_downgraded": version_downgraded,

        # Author concentration
        "total_authors_removed": total_authors_removed,
        "top1_n": top1_n,
        "top1_skills": top1_skills,
        "top10_n": top10_n,
        "top10_skills": top10_skills,
        "top10_authors_skills": top10_authors_skills,
        "total_with_author": total_with_author,
        "top10_authors": author_removal_counts.most_common(10),
        "authors_all_removed": authors_all_removed,
    }

# Report

def print_report(r: dict):
    total = r["total_ever"]
    removed = r["removed_distinct"]
    active = total - removed

    print("=" * 65)
    print("REMOVAL AND REAPPEARANCE ANALYSIS")
    print("=" * 65)
    print()
    print("Latest crawl:      run #%d  (%s)" % (r["latest_run_id"], r["latest_run_date"]))
    print("Reference date:    %s" % r["reference_date"])
    print("Removal threshold: >%d days absent (FP probability ~0.0003%%)" % r["removal_threshold_days"])
    print("Removal cutoff:    %s" % r["removal_cutoff"])
    print("Crawl runs used:   %d (success + partial_success)" % len(r["crawl_runs"]))
    print()

    print("=== REMOVALS ===")
    print()
    print("Definition: skill whose MAX(last_seen_at) is more than")
    print("%d days before the reference date. Independent of" % r["removal_threshold_days"])
    print("last_crawl_run_id — uses last_seen_at timestamps only.")
    print("Threshold chosen so P(false positive) < 0.001%%.")
    print()
    print("Total ever seen:          %8d" % total)
    print("Distinct removed skills:  %8d  (%.1f%%)" % (removed, removed*100/total))
    print("Total removal events:     %8d" % r["removal_events"])
    print("Currently active:         %8d  (%.1f%%)" % (active, active*100/total))
    print()

    if r["lifespan_days"]:
        ls = r["lifespan_days"]
        print("Lifespan of removed skills:")
        print("  Median: %d days" % statistics.median(ls))
        print("  Mean:   %.1f days" % (sum(ls)/len(ls)))
        print("  Min:    %d days" % min(ls))
        print("  Max:    %d days" % max(ls))
        print()

    print("Monthly removals (month = last seen month):")
    print("%-10s  %10s" % ("Month", "Distinct"))
    print("-" * 25)
    for month in sorted(r["monthly_removed_distinct"].keys()):
        if month == EXCLUDE_MONTH:
            continue
        print("%s    %8d" % (month, r["monthly_removed_distinct"][month]))
    print("-" * 25)
    print("%-10s  %10d" % ("Total", removed))
    print()

    print("=== AUTHOR CONCENTRATION IN REMOVALS ===")
    print()
    total_with_author = r["total_with_author"]
    print("Distinct authors with removals:  %d" % r["total_authors_removed"])
    print("Top 1%% authors (%d):             %d skills (%.1f%%)" % (
        r["top1_n"], r["top1_skills"],
        r["top1_skills"]*100/total_with_author if total_with_author else 0))
    print("Top 10%% authors (%d):            %d skills (%.1f%%)" % (
        r["top10_n"], r["top10_skills"],
        r["top10_skills"]*100/total_with_author if total_with_author else 0))
    print("Top 10 authors:                  %d skills (%.1f%%)" % (
        r["top10_authors_skills"],
        r["top10_authors_skills"]*100/total_with_author if total_with_author else 0))
    print()
    print("Top 10 authors by removals:")
    for author, count in r["top10_authors"]:
        print("  %-30s: %d (%.1f%%)" % (
            author, count,
            count*100/total_with_author if total_with_author else 0))
    print()

    print("=== REAPPEARANCES ===")
    print()
    print("Definition: skill absent from >=1 coverage-qualified")
    print("crawl, then observed again in a subsequent crawl.")
    print()
    reapp = r["reapp_distinct"]
    print("Distinct reappeared skills:  %d (%.1f%% of removed)" % (
        reapp, reapp*100/removed if removed else 0))
    print("Total reappearance events:   %d" % r["reapp_events"])
    print()

    if r["reapp_gap_days"]:
        gd = r["reapp_gap_days"]
        print("Gap when absent:")
        print("  Median: %.0f days" % statistics.median(gd))
        print("  Mean:   %.1f days" % (sum(gd)/len(gd)))
        print("  Max:    %d days" % max(gd))
        print()

    n = r["reapp_events"]
    if n > 0:
        print("On reappearance:")
        print("  Name changed:       %d (%.1f%%)" % (r["name_changed"], r["name_changed"]*100/n))
        print("  Content changed:    %d (%.1f%%)" % (r["content_changed"], r["content_changed"]*100/n))
        print("  Version downgraded: %d (%.1f%%)" % (r["version_downgraded"], r["version_downgraded"]*100/n))
        print()

    print("Monthly reappearances:")
    print("%-10s  %10s" % ("Month", "Events"))
    print("-" * 25)
    for month in sorted(r["monthly_reapp_events"].keys()):
        if month == EXCLUDE_MONTH:
            continue
        print("%s    %8d" % (month, r["monthly_reapp_events"][month]))
    print("-" * 25)
    print("%-10s  %10d" % ("Total", sum(r["monthly_reapp_events"].values())))
    print()


# CSV output

def write_csvs(r: dict, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    # Monthly table
    months = sorted(set(
        list(r["monthly_removal_events"].keys()) +
        list(r["monthly_removed_distinct"].keys()) +
        list(r["monthly_reapp_events"].keys())
    ))
    with open(os.path.join(output_dir, "monthly_activity.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Month", "Removed (distinct)", "Reappearance Events"])
        for month in months:
            if month == EXCLUDE_MONTH:
                continue
            w.writerow([
                month,
                r["monthly_removed_distinct"].get(month, 0),
                r["monthly_reapp_events"].get(month, 0),
            ])

    # Author concentration
    with open(os.path.join(output_dir, "author_removals.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Author", "Removed Skills", "Pct"])
        total = r["total_with_author"]
        for author, count in r["top10_authors"]:
            w.writerow([author, count, round(count*100/total, 1) if total else 0])

    print("CSVs written to %s" % output_dir)


# Main

def main():
    parser = argparse.ArgumentParser(description="Removal and reappearance analysis")
    parser.add_argument("--source", default="clawhub", help="Skill source to analyze")
    parser.add_argument("--dsn", default=DEFAULT_DSN, help="PostgreSQL DSN")
    parser.add_argument("--output-dir", default=None, help="Directory for CSV output")
    args = parser.parse_args()

    conn = get_connection(args.dsn)
    try:
        results = analyze(conn, args.source)
        print_report(results)
        if args.output_dir:
            write_csvs(results, args.output_dir)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
