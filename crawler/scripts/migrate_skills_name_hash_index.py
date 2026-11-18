"""Migration: replace idx_skills_name btree index with a hash index.

The btree index on skills.name rejects values larger than ~2704 bytes
(btree v4 page limit), causing INSERT failures for skills with very long
names. Hash indexes have no such size restriction and support the equality
lookups this index exists for.

Safe to re-run (idempotent): drops and recreates the index unconditionally.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from db.session import engine
from sqlalchemy import text


def run():
    with engine.begin() as conn:
        print("Dropping idx_skills_name (btree)...")
        conn.execute(text("DROP INDEX IF EXISTS idx_skills_name"))

        print("Creating idx_skills_name (hash)...")
        conn.execute(text("CREATE INDEX idx_skills_name ON skills USING hash (name)"))

    print("Done.")


if __name__ == "__main__":
    run()
