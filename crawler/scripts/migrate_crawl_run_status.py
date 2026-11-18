"""Migration: expand crawl_runs.status CHECK constraint to include 'partial_success'.

Safe to re-run (idempotent):
  - Drops the existing ck_crawl_runs_status constraint if present.
  - Re-adds it with allowed values: running, success, partial_success, failed.
  - Updates stranded 'running' rows (started > 24 hours ago, never finished)
    to 'failed'. Rows from active or recent runs are not touched.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from db.session import engine
from sqlalchemy import text


def run():
    with engine.begin() as conn:
        # Drop existing constraint (IF EXISTS makes this idempotent).
        conn.execute(text(
            "ALTER TABLE crawl_runs DROP CONSTRAINT IF EXISTS ck_crawl_runs_status"
        ))
        print("Dropped ck_crawl_runs_status (if it existed)")

        # Re-add with expanded allowed values.
        conn.execute(text("""
            ALTER TABLE crawl_runs
            ADD CONSTRAINT ck_crawl_runs_status
            CHECK (status IN ('running', 'success', 'partial_success', 'failed'))
        """))
        print("Added ck_crawl_runs_status with partial_success")

        # Mark stranded 'running' rows as 'failed'.
        # Only affects rows started more than 24 hours ago with no finished_at —
        # these were never finalized (process crash, OOM kill, etc.).
        result = conn.execute(text("""
            UPDATE crawl_runs
            SET status = 'failed',
                finished_at = NOW()
            WHERE status = 'running'
              AND finished_at IS NULL
              AND started_at < NOW() - INTERVAL '24 hours'
        """))
        print(f"Marked {result.rowcount} stranded 'running' row(s) as 'failed'")


if __name__ == "__main__":
    run()
