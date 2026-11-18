"""Migrate locally-stored skill artifacts into S3 and update artifact_uri in the DB.

For each skill row with a local artifact_uri, this script:
  1. Reads the artifact files from disk.
  2. Uploads them to S3 via S3ArtifactStore (preserving the same key structure).
  3. Updates artifact_uri in the DB to the returned s3:// URI.

Idempotent: rows whose artifact_uri already starts with "s3://" are skipped.
Local files are NOT deleted — they remain as a backup.

Usage:
    python migrate_to_s3.py [options]

Options:
    --dry-run           Log what would happen; make no uploads or DB writes.
    --source SOURCE     Restrict to one source (default: all sources).
    --limit N           Process at most N rows (useful for test runs).
    --resume-from-id ID Skip rows with id < ID (resume an interrupted run).
    -v, --verbose       Enable DEBUG-level logging for per-file upload detail.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from db.models import Skill  # noqa: E402
from db.session import SessionLocal  # noqa: E402
from storage.s3 import S3ArtifactStore  # noqa: E402

logger = logging.getLogger(__name__)

PROGRESS_INTERVAL = 500


def _build_files_dict(local_dir: Path) -> dict[str, bytes]:
    """Read all files under local_dir into a {relative_path: bytes} dict."""
    files = {}
    for f in sorted(local_dir.rglob("*")):
        if f.is_file():
            files[str(f.relative_to(local_dir))] = f.read_bytes()
    return files


def migrate(
    *,
    dry_run: bool = False,
    source: str | None = None,
    limit: int | None = None,
    resume_from_id: int | None = None,
) -> dict:
    """Run the migration and return a stats dict."""
    store = S3ArtifactStore()
    session = SessionLocal()
    start = time.monotonic()

    try:
        query = session.query(Skill).order_by(Skill.id)
        if source:
            query = query.filter(Skill.source == source)
        if resume_from_id is not None:
            query = query.filter(Skill.id >= resume_from_id)
        rows = query.all()

        total = len(rows)
        if limit is not None:
            rows = rows[:limit]
            logger.info("Processing %d of %d rows (--limit %d)", len(rows), total, limit)
        else:
            logger.info("Processing %d rows", len(rows))

        migrated = 0
        skipped_s3 = 0
        skipped_missing = 0
        errors = []
        processed = 0

        for row in rows:
            processed += 1
            uri = row.artifact_uri or ""

            if uri.startswith("s3://"):
                skipped_s3 += 1
                logger.debug("[skip-s3]  id=%-6d  %s", row.id, row.source_id)
                _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)
                continue

            try:
                if uri.endswith("/"):
                    # Directory artifact — multi-file
                    local_dir = Path(uri)
                    if not local_dir.exists() or not local_dir.is_dir():
                        logger.warning(
                            "[skip-missing]  id=%-6d  %s  path=%s",
                            row.id, row.source_id, uri,
                        )
                        skipped_missing += 1
                        _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)
                        continue

                    files = _build_files_dict(local_dir)
                    if dry_run:
                        logger.info(
                            "[dry-run] would migrate %s  v%s  (%d files)",
                            row.source_id, row.version, len(files),
                        )
                        migrated += 1
                        _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)
                        continue

                    s3_uri = store.save_many(
                        source=row.source,
                        skill_id=row.source_id,
                        version=row.version,
                        files=files,
                    )

                else:
                    # Single-file artifact
                    local_path = Path(uri)
                    if not local_path.exists() or not local_path.is_file():
                        logger.warning(
                            "[skip-missing]  id=%-6d  %s  path=%s",
                            row.id, row.source_id, uri,
                        )
                        skipped_missing += 1
                        _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)
                        continue

                    if dry_run:
                        logger.info(
                            "[dry-run] would migrate %s  v%s  (single file: %s)",
                            row.source_id, row.version, local_path.name,
                        )
                        migrated += 1
                        _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)
                        continue

                    s3_uri = store.save(
                        source=row.source,
                        skill_id=row.source_id,
                        version=row.version,
                        content=local_path.read_bytes(),
                        filename=local_path.name,
                    )

                # Update DB
                logger.debug("[migrated]  id=%-6d  %s  %s → %s", row.id, row.source_id, uri, s3_uri)
                session.query(Skill).filter(Skill.id == row.id).update(
                    {"artifact_uri": s3_uri},
                    synchronize_session=False,
                )
                session.commit()
                migrated += 1

            except Exception as exc:
                session.rollback()
                logger.error("[error]  id=%-6d  %s: %s", row.id, row.source_id, exc)
                errors.append({"id": row.id, "skill_id": row.source_id, "error": str(exc)})

            _maybe_log_progress(processed, len(rows), migrated, skipped_s3, skipped_missing, errors, start)

        elapsed = round(time.monotonic() - start, 1)
        stats = {
            "total_processed": len(rows),
            "migrated": migrated,
            "skipped_s3": skipped_s3,
            "skipped_missing": skipped_missing,
            "errors": len(errors),
            "elapsed_seconds": elapsed,
        }
        if errors:
            stats["error_details"] = errors
        if dry_run:
            stats["dry_run"] = True
        return stats

    finally:
        session.close()


def _maybe_log_progress(
    processed: int,
    total: int,
    migrated: int,
    skipped_s3: int,
    skipped_missing: int,
    errors: list,
    start: float,
) -> None:
    if processed % PROGRESS_INTERVAL != 0:
        return
    elapsed = time.monotonic() - start
    throughput = processed / elapsed if elapsed > 0 else 0
    remaining_rows = total - processed
    est_remaining = remaining_rows / throughput if throughput > 0 else float("inf")
    logger.info(
        "Progress: %d/%d  migrated=%d  skipped_s3=%d  skipped_missing=%d  errors=%d  "
        "elapsed=%.0fs  throughput=%.1f skills/sec  est_remaining=~%.0fs",
        processed, total, migrated, skipped_s3, skipped_missing, len(errors),
        elapsed, throughput, est_remaining,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="Log only; no uploads or DB writes")
    parser.add_argument("--source", help="Restrict to one source (e.g. clawhub)")
    parser.add_argument("--limit", type=int, metavar="N", help="Process at most N rows")
    parser.add_argument("--resume-from-id", type=int, metavar="ID", help="Skip rows with id < ID")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    stats = migrate(
        dry_run=args.dry_run,
        source=args.source,
        limit=args.limit,
        resume_from_id=args.resume_from_id,
    )

    label = "DRY-RUN " if stats.get("dry_run") else ""
    print(
        f"\n{label}Migration complete:\n"
        f"  total_processed : {stats['total_processed']}\n"
        f"  migrated        : {stats['migrated']}\n"
        f"  skipped (s3)    : {stats['skipped_s3']}\n"
        f"  skipped (missing): {stats['skipped_missing']}\n"
        f"  errors          : {stats['errors']}\n"
        f"  elapsed         : {stats['elapsed_seconds']}s"
    )
    if stats.get("error_details"):
        print("\nErrors:")
        for e in stats["error_details"]:
            print(f"  id={e['id']}  {e['skill_id']}: {e['error']}")

    return 1 if stats["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
