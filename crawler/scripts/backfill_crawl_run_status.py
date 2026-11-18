"""One-time backfill: recalculate status for completed crawl runs using the current rules.

Only processes runs whose stats contain 'skills_seen' (new-format crawl runs) or
'backfilled'/'skipped'/'errors' (backfill runs). Old-format runs without these keys
cannot be recalculated reliably and are skipped.

Status rules applied:
    failed          — pagination_stopped_early=true, or zero skills/rows processed
    partial_success — per-item failure rate >= 5%
    success         — completed end-to-end with acceptable failure rate

Runs with status='running' are always skipped (they may still be active).

Usage:
    python3 scripts/backfill_crawl_run_status.py            # live run
    python3 scripts/backfill_crawl_run_status.py --dry-run  # preview only
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from db.models import CrawlRun
from db.session import SessionLocal

_PARTIAL_SUCCESS_FAILURE_RATE = 0.05


def _recalculate(stats: dict) -> str | None:
    """Return the correct status for a run given its stats, or None if undeterminable."""
    if not stats:
        return None

    # New-format crawl run
    if "skills_seen" in stats:
        skills_seen = int(stats["skills_seen"])
        failures = int(stats.get("failures", 0))
        stopped_early = bool(stats.get("pagination_stopped_early", False))
        if stopped_early or skills_seen == 0:
            return "failed"
        if failures / skills_seen >= _PARTIAL_SUCCESS_FAILURE_RATE:
            return "partial_success"
        return "success"

    # Backfill run
    if "backfilled" in stats or "skipped" in stats:
        backfilled = int(stats.get("backfilled", 0))
        skipped = int(stats.get("skipped", 0))
        errors = int(stats.get("errors", 0))
        total = backfilled + skipped + errors
        if total == 0:
            return "failed"
        if errors / total >= _PARTIAL_SUCCESS_FAILURE_RATE:
            return "partial_success"
        return "success"

    # Old-format or unknown — cannot recalculate
    return None


def run(dry_run: bool = False):
    session = SessionLocal()
    try:
        runs = session.query(CrawlRun).filter(
            CrawlRun.status != "running"
        ).order_by(CrawlRun.id).all()

        updated = 0
        skipped = 0

        for run in runs:
            new_status = _recalculate(run.stats)

            if new_status is None:
                skipped += 1
                continue

            if new_status == run.status:
                continue

            print(f"  run {run.id}: {run.status!r} → {new_status!r}  "
                  f"(skills_seen={run.stats.get('skills_seen', run.stats.get('backfilled', '?'))}, "
                  f"failures={run.stats.get('failures', run.stats.get('errors', '?'))})")

            if not dry_run:
                run.status = new_status

            updated += 1

        if not dry_run:
            session.commit()

        label = "[dry-run] " if dry_run else ""
        print(f"\n{label}{updated} run(s) would be updated, {skipped} skipped (insufficient stats)")

    finally:
        session.close()


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    if dry_run:
        print("Dry-run mode — no changes will be written\n")
    run(dry_run=dry_run)
