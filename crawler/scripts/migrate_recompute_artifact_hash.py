"""Repair migration: recompute artifact_hash without volatile provenance and
collapse the spurious duplicate snapshot rows it created.

Background (see docs/misc/artifact-duplication-investigation.md):
ClawHub's _detail.json (collector-injected provenance) embeds volatile API
counters, and it used to be part of compute_artifact_hash(). The 2026-07-02
verify crawl (crawl_run 52) therefore saw a "new" artifact for ~65k unchanged
skills and inserted a near-total duplicate row set, each with a full S3 copy
under .../{version}/{hash12}/. The hash definition now excludes each source's
hash_excluded_files; this script brings the stored rows in line with it.

What it does, per (source, source_id, version) group of rows that have both
artifact_uri and artifact_hash:
  1. Downloads each row's artifact from S3 (listing scoped to the row's own
     layout: a legacy flat URI skips sibling {12-hex}/ snapshot subtrees; a
     hash-segmented URI takes everything under it) and recomputes the hash
     with the source's hash_excluded_files applied.
  2. Rows whose recomputed hash is unchanged are no-ops (this makes re-runs
     idempotent).
  3. When several rows in a group recompute to the SAME hash, their content
     (excluding volatile provenance) is identical: the oldest row (earliest
     first_seen_at, then lowest id) survives with the new hash and merged
     last_seen_at / last_crawl_run_id; the others are copied into the
     skills_hash_migration_audit table and deleted. Rows that recompute to
     DIFFERENT hashes all survive — genuine mutation evidence is preserved.
  4. Rows whose artifacts cannot be read (non-s3 URI, missing objects) are
     skipped and reported; nothing is written for that group.

Safety:
  - DRY-RUN BY DEFAULT. Pass --execute to write. Both modes produce a TSV
    report (logs/hash_migration_report_<timestamp>.tsv) with one line per row.
  - REQUIRED BEFORE --execute: a fresh DB backup, e.g.
        pg_dump "$DATABASE_URL" -Fc -f skill_collector_pre_hash_migration.dump
  - Every deleted row is preserved in skills_hash_migration_audit first
    (superseded id, survivor id, old hash/uri, seen timestamps, crawl-run
    references, name, metadata).
  - Each group is applied in its own transaction: a crash mid-run leaves
    every group either fully migrated or untouched; re-running resumes.
  - Takes the same per-source lock the systemd crawl units use
    (/tmp/openclaw-crawler-<source>.lock, non-blocking) so it never races a
    running crawl. NEVER writes to S3; orphaned {hash12}/ objects are handled
    separately by scripts/report_orphaned_hash_dirs.py.

Usage:
    python3 scripts/migrate_recompute_artifact_hash.py                    # dry-run, all sources
    python3 scripts/migrate_recompute_artifact_hash.py --source clawhub
    python3 scripts/migrate_recompute_artifact_hash.py --source-id traefik-mantrae-diagnostics
    python3 scripts/migrate_recompute_artifact_hash.py --limit 50         # first N groups
    python3 scripts/migrate_recompute_artifact_hash.py --since-run 55     # delta: groups with rows
                                                                          # first seen in run >= 55
    python3 scripts/migrate_recompute_artifact_hash.py --summarize logs/a.tsv logs/b.tsv
                                                                          # merged review report
                                                                          # (later files win per group)
    python3 scripts/migrate_recompute_artifact_hash.py --execute --source clawhub
    python3 scripts/migrate_recompute_artifact_hash.py --validate-only    # post-migration checks

Note on coverage: dry-run reports are point-in-time predictions for review.
--execute does NOT replay a report — it re-plans every group live at execution
time, so rows inserted after a dry-run are always covered by the execute pass
itself. Use --since-run for a delta report over newly crawled rows and
--summarize to merge reports and cross-check them against the live table
(uncovered rows are listed explicitly).
"""

import argparse
import fcntl
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

import boto3
from sqlalchemy import text

from db.session import engine
from pipeline import compute_artifact_hash
from sources.clawhub import ClawHubSource
from sources.github import GitHubSkillsSource
from storage.base import ARTIFACT_HASH_SEGMENT_LEN

# Per-source hash exclusions come from the source classes (single source of
# truth with the crawl/backfill paths). Unknown legacy sources exclude nothing.
HASH_EXCLUSIONS = {
    ClawHubSource.source_name: ClawHubSource.hash_excluded_files,
    GitHubSkillsSource.source_name: GitHubSkillsSource.hash_excluded_files,
}

HASH_SEGMENT_RE = re.compile(r"^[0-9a-f]{%d}$" % ARTIFACT_HASH_SEGMENT_LEN)

AUDIT_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS skills_hash_migration_audit (
    id                  BIGSERIAL PRIMARY KEY,
    superseded_skill_id BIGINT NOT NULL,
    survivor_skill_id   BIGINT NOT NULL,
    source              TEXT NOT NULL,
    source_id           TEXT NOT NULL,
    version             TEXT NOT NULL,
    name                TEXT,
    old_artifact_hash   TEXT NOT NULL,
    old_artifact_uri    TEXT NOT NULL,
    new_artifact_hash   TEXT NOT NULL,
    first_seen_at       TIMESTAMPTZ,
    last_seen_at        TIMESTAMPTZ,
    first_crawl_run_id  BIGINT,
    last_crawl_run_id   BIGINT,
    metadata            JSONB,
    migrated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


def parse_s3_uri(uri: str):
    """Split s3://bucket/prefix into (bucket, prefix); None for non-s3 URIs."""
    if not uri.startswith("s3://"):
        return None
    without_scheme = uri[len("s3://"):]
    bucket, _, prefix = without_scheme.partition("/")
    return bucket, prefix


def is_hash_segmented_prefix(prefix: str) -> bool:
    last = prefix.rstrip("/").rsplit("/", 1)[-1]
    return bool(HASH_SEGMENT_RE.match(last))


def load_artifact_files(s3_client, uri: str) -> dict | None:
    """Download an artifact's {relative_path: bytes} from its artifact_uri.

    The listing is scoped exactly like the artifact was written: a legacy flat
    prefix must skip sibling {12-hex}/ snapshot subtrees (they belong to other
    rows), while a hash-segmented prefix is already scoped to one snapshot.
    Returns None when the URI is not s3:// or no objects exist.
    """
    parsed = parse_s3_uri(uri)
    if parsed is None:
        return None
    bucket, prefix = parsed

    # Earliest-era rows (single-file artifacts stored via store.save()) carry a
    # FILE URI (e.g. .../1.0.0/skill.json), not a directory prefix. Fetch that
    # one object directly; its basename is the artifact's only relative path.
    if not prefix.endswith("/"):
        try:
            body = s3_client.get_object(Bucket=bucket, Key=prefix)["Body"].read()
        except s3_client.exceptions.NoSuchKey:
            return None
        return {prefix.rsplit("/", 1)[-1]: body}

    exclude_hash_subdirs = not is_hash_segmented_prefix(prefix)

    files = {}
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            relative = key[len(prefix):]
            if not relative:
                continue
            first_segment = relative.split("/", 1)[0]
            if exclude_hash_subdirs and "/" in relative and HASH_SEGMENT_RE.match(first_segment):
                continue
            body = s3_client.get_object(Bucket=bucket, Key=key)["Body"].read()
            files[relative] = body
    return files or None


def acquire_source_lock(source: str, execute: bool):
    """Take the same lock the systemd crawl units use.

    --execute must never race a crawl (it deletes/updates rows the crawl may
    touch), so a busy lock aborts. A dry-run is read-only: a concurrent crawl
    can only make the report slightly stale, so it warns and proceeds.
    """
    lock_path = f"/tmp/openclaw-crawler-{source}.lock"
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if execute:
            print(f"ABORT: {lock_path} is held — a crawl for '{source}' is running. Retry later.")
            sys.exit(1)
        print(f"WARNING: a crawl for '{source}' is running; dry-run report may be slightly stale.")
    return handle  # held until process exit


def fetch_groups(conn, source: str | None, source_id: str | None, since_run: int | None = None):
    """Return {(source, source_id, version): [row dicts]} for all hashable rows.

    since_run scopes to groups containing at least one row FIRST seen in crawl
    run >= since_run (delta mode: re-plan only groups touched by newer crawls).
    The whole group is always loaded — collapse decisions need every sibling.
    """
    query = """
        SELECT id, source, source_id, version, name, artifact_uri, artifact_hash,
               first_seen_at, last_seen_at, first_crawl_run_id, last_crawl_run_id
        FROM skills
        WHERE artifact_uri IS NOT NULL AND artifact_hash IS NOT NULL
    """
    params = {}
    if source:
        query += " AND source = :source"
        params["source"] = source
    if source_id:
        query += " AND source_id = :source_id"
        params["source_id"] = source_id
    if since_run is not None:
        query += """ AND (source, source_id, version) IN (
            SELECT source, source_id, version FROM skills
            WHERE first_crawl_run_id >= :since_run)"""
        params["since_run"] = since_run
    query += " ORDER BY source, source_id, version, first_seen_at, id"

    groups = {}
    for row in conn.execute(text(query), params).mappings():
        groups.setdefault((row["source"], row["source_id"], row["version"]), []).append(dict(row))
    return groups


def plan_group(s3_client, rows: list[dict]) -> list[dict]:
    """Compute per-row actions for one (source, source_id, version) group.

    Returns rows annotated with new_hash and action:
      noop | rehash | collapse_survivor | collapse_delete | skip_unreadable
    """
    exclusions = HASH_EXCLUSIONS.get(rows[0]["source"], frozenset())

    uri_cache = {}  # rows can share a URI (pre-cutover overwrites) — download once
    for row in rows:
        uri = row["artifact_uri"]
        if uri not in uri_cache:
            uri_cache[uri] = load_artifact_files(s3_client, uri)
        files = uri_cache[uri]
        row["new_hash"] = compute_artifact_hash(files, exclude=exclusions) if files else None

    # Any unreadable artifact poisons collision detection for the whole group,
    # so the group is reported and left untouched.
    if any(row["new_hash"] is None for row in rows):
        for row in rows:
            row["action"] = "skip_unreadable"
        return rows

    by_new_hash = {}
    for row in rows:  # rows arrive ordered oldest-first (first_seen_at, id)
        by_new_hash.setdefault(row["new_hash"], []).append(row)

    for cohort in by_new_hash.values():
        survivor = cohort[0]
        if len(cohort) == 1:
            survivor["action"] = "noop" if survivor["new_hash"] == survivor["artifact_hash"] else "rehash"
        else:
            survivor["action"] = "collapse_survivor"
            survivor["merged_last_seen_at"] = max(r["last_seen_at"] for r in cohort)
            newest = max(cohort, key=lambda r: (r["last_seen_at"], r["id"]))
            survivor["merged_last_crawl_run_id"] = newest["last_crawl_run_id"]
            for row in cohort[1:]:
                row["action"] = "collapse_delete"
                row["survivor_id"] = survivor["id"]
    return rows


def apply_group(conn, rows: list[dict]) -> None:
    """Write one planned group inside the caller's transaction.

    Deletes come first: a superseded row's old hash could equal a survivor's
    new hash, and the (source, source_id, version, artifact_hash) unique
    constraint must never trip mid-flight.
    """
    for row in rows:
        if row["action"] == "collapse_delete":
            # Analyzer results reference skills via RESTRICT FKs. Results on a
            # superseded row describe content identical (minus volatile
            # provenance) to its survivor, which the same runs also analyzed —
            # no unique signal is lost, and the pre-migration pg_dump retains
            # them. Findings cascade from results in both tables.
            conn.execute(text("DELETE FROM analysis_results WHERE skill_id = :id"),
                         {"id": row["id"]})
            conn.execute(text("DELETE FROM llm_analysis_results WHERE skill_id = :id"),
                         {"id": row["id"]})
            conn.execute(text("""
                INSERT INTO skills_hash_migration_audit (
                    superseded_skill_id, survivor_skill_id, source, source_id, version,
                    name, old_artifact_hash, old_artifact_uri, new_artifact_hash,
                    first_seen_at, last_seen_at, first_crawl_run_id, last_crawl_run_id, metadata)
                SELECT id, :survivor_id, source, source_id, version,
                       name, artifact_hash, artifact_uri, :new_hash,
                       first_seen_at, last_seen_at, first_crawl_run_id, last_crawl_run_id, metadata
                FROM skills WHERE id = :id
            """), {"id": row["id"], "survivor_id": row["survivor_id"], "new_hash": row["new_hash"]})
            conn.execute(text("DELETE FROM skills WHERE id = :id"), {"id": row["id"]})

    for row in rows:
        if row["action"] == "rehash":
            conn.execute(text(
                "UPDATE skills SET artifact_hash = :new_hash WHERE id = :id"
            ), {"id": row["id"], "new_hash": row["new_hash"]})
        elif row["action"] == "collapse_survivor":
            conn.execute(text("""
                UPDATE skills
                SET artifact_hash = :new_hash,
                    last_seen_at = :last_seen_at,
                    last_crawl_run_id = :last_crawl_run_id
                WHERE id = :id
            """), {
                "id": row["id"],
                "new_hash": row["new_hash"],
                "last_seen_at": row["merged_last_seen_at"],
                "last_crawl_run_id": row["merged_last_crawl_run_id"],
            })


EXAMPLE_SOURCE_IDS = ("traefik-mantrae-diagnostics", "1password-old", "0codekit")


def load_processed_groups(report_paths: list[str]) -> set:
    """Group keys already covered by earlier dry-run reports (resume support).

    A killed run may have written its final group only partially, so the last
    group of each report is discarded and gets re-planned. Malformed trailing
    lines are ignored for the same reason.
    """
    processed = set()
    for path in report_paths:
        ordered = []
        with open(path) as report:
            header = report.readline().rstrip("\n").split("\t")
            for line in report:
                fields = line.rstrip("\n").split("\t")
                if len(fields) != len(header):
                    continue
                row = dict(zip(header, fields))
                key = (row["source"], row["source_id"], row["version"])
                if not ordered or ordered[-1] != key:
                    ordered.append(key)
        processed.update(ordered[:-1])  # drop possibly-partial final group
    return processed


def summarize_reports(report_paths: list[str]) -> None:
    """Merge dry-run reports into a review summary and cross-check coverage.

    Reports are applied in order; when the same (source, source_id, version)
    group appears in several reports, the LAST report wins — pass the delta
    report after the full report. The summary answers the review questions:
    predicted before/after row counts, denominators, noise collapses vs
    genuine mutations preserved, unreadable rows, spot checks, and any live
    rows not covered by any report.
    """
    merged = {}  # group key -> {skill_id: report line dict}
    for path in report_paths:
        with open(path) as report:
            header = report.readline().rstrip("\n").split("\t")
            per_group = {}
            for line in report:
                row = dict(zip(header, line.rstrip("\n").split("\t")))
                key = (row["source"], row["source_id"], row["version"])
                per_group.setdefault(key, {})[int(row["skill_id"])] = row
            merged.update(per_group)  # later report replaces the whole group

    rows = [r for group in merged.values() for r in group.values()]
    actions = {}
    for row in rows:
        actions[row["action"]] = actions.get(row["action"], 0) + 1

    deletes = actions.get("collapse_delete", 0)
    unreadable = [r for r in rows if r["action"] == "skip_unreadable"]
    old_hashes = {r["old_hash"] for r in rows}
    new_hashes = {r["new_hash"] for r in rows if r["new_hash"] not in ("None", "")}

    # Genuine same-version mutations = groups keeping >1 distinct content hash.
    mutation_groups = 0
    for group in merged.values():
        survivors = {r["new_hash"] for r in group.values()
                     if r["action"] in ("noop", "rehash", "collapse_survivor")}
        if len(survivors) > 1:
            mutation_groups += 1

    print(f"Merged reports: {', '.join(report_paths)}")
    print(f"\n== predicted actions ==\n   {dict(sorted(actions.items()))}")
    print(f"\n== rows ==")
    print(f"   covered by reports:            {len(rows)}")
    print(f"   predicted deletions (noise):   {deletes}")
    print(f"   predicted rows after:          {len(rows) - deletes}")
    print(f"   unreadable (left untouched):   {len(unreadable)}")
    print(f"\n== content hashes ==")
    print(f"   distinct old hashes (covered rows): {len(old_hashes)}")
    print(f"   distinct new hashes (covered rows): {len(new_hashes)}")
    print(f"\n== genuine same-version mutations preserved ==")
    print(f"   groups keeping >1 content hash: {mutation_groups}")

    with engine.connect() as conn:
        db_stats = conn.execute(text("""
            SELECT count(*),
                   count(DISTINCT source_id),
                   count(DISTINCT (source_id, version))
            FROM skills WHERE artifact_uri IS NOT NULL AND artifact_hash IS NOT NULL
        """)).one()
        print(f"\n== live table (now) vs predicted (after) ==")
        print(f"   rows:                    {db_stats[0]} -> {db_stats[0] - deletes}")
        print(f"   distinct skills:         {db_stats[1]} -> {db_stats[1]} (collapse never removes a skill)")
        print(f"   distinct (skill,version): {db_stats[2]} -> {db_stats[2]} (survivor kept per group)")

        covered_ids = {int(r["skill_id"]) for r in rows}
        live_ids = {row[0] for row in conn.execute(text(
            "SELECT id FROM skills WHERE artifact_uri IS NOT NULL AND artifact_hash IS NOT NULL"
        ))}
        uncovered = sorted(live_ids - covered_ids)
        stale = len(covered_ids - live_ids)
        print(f"\n== coverage cross-check ==")
        print(f"   live rows not in any report:  {len(uncovered)}"
              + (f"  ids (first 20): {uncovered[:20]}" if uncovered else "  — full coverage"))
        if stale:
            print(f"   report rows no longer live:   {stale} (inserted-then-changed; execute re-plans live)")

    print(f"\n== spot checks ==")
    for key in sorted(merged):
        if key[1] in EXAMPLE_SOURCE_IDS:
            for r in merged[key].values():
                print(f"   {key[1]} v{key[2]}: row {r['skill_id']} {r['action']} "
                      f"{r['old_hash'][:12]} -> {str(r['new_hash'])[:12]}")
    if unreadable:
        print(f"\n== unreadable rows (report and resolve before/with --execute) ==")
        for r in unreadable[:50]:
            print(f"   row {r['skill_id']} {r['source']}/{r['source_id']} v{r['version']} {r['artifact_uri']}")


def run_validation() -> None:
    """Post-migration invariant checks (safe to run any time; read-only)."""
    checks = [
        ("rows per source",
         "SELECT source, count(*) FROM skills GROUP BY source ORDER BY source"),
        ("groups with >1 row (should be genuine mutations / multi-version only)",
         """SELECT n_rows, count(*) FROM (
                SELECT count(*) AS n_rows FROM skills
                WHERE artifact_hash IS NOT NULL
                GROUP BY source, source_id, version) t
            GROUP BY n_rows ORDER BY n_rows"""),
        ("duplicate (source, source_id, version, artifact_hash) tuples (MUST be 0)",
         """SELECT count(*) FROM (
                SELECT 1 FROM skills WHERE artifact_hash IS NOT NULL
                GROUP BY source, source_id, version, artifact_hash
                HAVING count(*) > 1) t"""),
        ("audit rows by superseding crawl run",
         """SELECT last_crawl_run_id, count(*) FROM skills_hash_migration_audit
            GROUP BY last_crawl_run_id ORDER BY count(*) DESC LIMIT 5"""),
        ("representative examples",
         """SELECT source_id, version, count(*) AS rows_now
            FROM skills
            WHERE source_id IN ('traefik-mantrae-diagnostics', '1password-old', '0codekit')
            GROUP BY source_id, version ORDER BY source_id"""),
    ]
    with engine.connect() as conn:
        for label, sql in checks:
            print(f"\n== {label} ==")
            try:
                for row in conn.execute(text(sql)):
                    print("  ", tuple(row))
            except Exception as exc:  # audit table may not exist before --execute
                print("   (query failed:", exc, ")")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--execute", action="store_true",
                        help="apply changes (default: dry-run report only). Take a pg_dump first.")
    parser.add_argument("--source", help="only process this source (e.g. clawhub)")
    parser.add_argument("--source-id", help="only process this source_id (spot checks)")
    parser.add_argument("--limit", type=int, help="only process the first N groups")
    parser.add_argument("--since-run", type=int,
                        help="delta mode: only groups with a row first seen in crawl run >= N")
    parser.add_argument("--skip-groups-in", nargs="+", metavar="REPORT_TSV",
                        help="resume: skip groups already covered by these dry-run reports "
                             "(each report's final group is re-planned in case it was cut off)")
    parser.add_argument("--summarize", nargs="+", metavar="REPORT_TSV",
                        help="merge dry-run reports (later files win per group) into a review "
                             "summary with live-table coverage cross-check, then exit")
    parser.add_argument("--validate-only", action="store_true",
                        help="run post-migration invariant checks and exit")
    args = parser.parse_args()

    if args.validate_only:
        run_validation()
        return
    if args.summarize:
        summarize_reports(args.summarize)
        return

    bucket = os.environ["S3_BUCKET"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    s3_client = boto3.client("s3", region_name=region)

    with engine.connect() as conn:
        groups = fetch_groups(conn, args.source, args.source_id, args.since_run)
    group_items = list(groups.items())
    if args.skip_groups_in:
        processed = load_processed_groups(args.skip_groups_in)
        before = len(group_items)
        group_items = [(key, rows) for key, rows in group_items if key not in processed]
        print(f"[resume] skipping {before - len(group_items)} groups already covered by "
              f"{len(args.skip_groups_in)} report(s)")
    if args.limit:
        group_items = group_items[: args.limit]

    sources = sorted({key[0] for key, _ in group_items})
    locks = [acquire_source_lock(s, args.execute) for s in sources]  # held until exit

    if args.execute:
        with engine.begin() as conn:
            conn.execute(text(AUDIT_TABLE_DDL))

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "logs"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / f"hash_migration_report_{timestamp}.tsv"

    mode = "EXECUTE" if args.execute else "DRY-RUN"
    print(f"[{mode}] {len(group_items)} groups across sources {sources}; bucket={bucket}")
    print(f"[{mode}] report: {report_path}")

    counts = {}
    started = time.monotonic()
    with open(report_path, "w") as report:
        report.write("action\tskill_id\tsource\tsource_id\tversion\told_hash\tnew_hash\tsurvivor_id\tartifact_uri\n")
        for index, (key, rows) in enumerate(group_items, start=1):
            planned = plan_group(s3_client, rows)
            if args.execute and any(r["action"] not in ("noop", "skip_unreadable") for r in planned):
                with engine.begin() as conn:
                    apply_group(conn, planned)
            for row in planned:
                counts[row["action"]] = counts.get(row["action"], 0) + 1
                report.write("\t".join(str(v) for v in (
                    row["action"], row["id"], row["source"], row["source_id"], row["version"],
                    row["artifact_hash"], row.get("new_hash"), row.get("survivor_id", ""),
                    row["artifact_uri"],
                )) + "\n")
            if index % 500 == 0:
                elapsed = time.monotonic() - started
                rate = index / elapsed
                remaining = (len(group_items) - index) / rate
                print(f"[{mode}] {index}/{len(group_items)} groups "
                      f"({rate:.1f}/s, ~{remaining/3600:.1f}h left)  {dict(sorted(counts.items()))}")

    print(f"[{mode}] done in {(time.monotonic() - started)/60:.1f} min: {dict(sorted(counts.items()))}")
    if args.execute:
        run_validation()
    else:
        print("Dry-run only — nothing was written. Re-run with --execute after review "
              "and a pg_dump backup.")


if __name__ == "__main__":
    main()
