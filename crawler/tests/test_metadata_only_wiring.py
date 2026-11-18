"""Offline wiring checks for --metadata-only.

Run from the project root:
    ./venv/bin/python -m unittest tests.test_metadata_only_wiring

Verifies the flag and parameter are plumbed through. The DB-writing metadata-only
path itself needs Postgres (JSONB) and is not unit-tested here.
"""

import inspect
import os
import subprocess
import sys
import unittest

from pipeline import run_crawl

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MetadataOnlyWiringTests(unittest.TestCase):
    def test_run_crawl_accepts_metadata_only_default_false(self):
        params = inspect.signature(run_crawl).parameters
        self.assertIn("metadata_only", params)
        self.assertIs(params["metadata_only"].default, False)

    def test_cli_crawl_help_lists_metadata_only(self):
        # Exercise the genuine CLI surface without side effects via --help.
        out = subprocess.run(
            [sys.executable, "cli.py", "crawl", "--help"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--metadata-only", out.stdout)


if __name__ == "__main__":
    unittest.main()
