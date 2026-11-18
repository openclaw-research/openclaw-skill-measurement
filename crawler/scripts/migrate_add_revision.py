"""Migration: add the nullable skills.revision column and its index.

`revision` holds a source-specific immutable/semi-immutable identifier (git commit
SHA, tag target SHA, branch HEAD SHA, package digest, ...), distinct from the human
`version` string. It is NOT part of the uniqueness key — byte identity is already
captured by artifact_hash.

Safe to re-run (idempotent):
  - ADD COLUMN IF NOT EXISTS skills.revision TEXT (nullable, no default).
  - CREATE INDEX IF NOT EXISTS idx_skills_revision.

Existing rows are left with revision = NULL. This is intentional and cheap (no
full-table rewrite): the only existing source is ClawHub, which exposes a semantic
`version` but no separate VCS-style revision, so NULL is the correct, honest value
rather than duplicating `version` into `revision`. See migrate notes in
docs/misc/third_party_crawling_exploration.md (§5).

Usage:
    python3 scripts/migrate_add_revision.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from db.session import engine


def run():
    with engine.begin() as conn:
        # Additive, nullable column — existing rows get NULL, no rewrite.
        conn.execute(text(
            "ALTER TABLE skills ADD COLUMN IF NOT EXISTS revision TEXT"
        ))
        print("Added skills.revision (if it did not exist)")

        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS idx_skills_revision ON skills(revision)"
        ))
        print("Created idx_skills_revision (if it did not exist)")


if __name__ == "__main__":
    run()
