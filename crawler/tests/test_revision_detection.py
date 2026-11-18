"""Offline tests for revision-aware re-fetch decisions (pipeline._needs_artifact_fetch).

Run from the project root:
    ./venv/bin/python -m unittest tests.test_revision_detection
"""

import unittest
from types import SimpleNamespace

from pipeline import _needs_artifact_fetch


def row(revision, artifact_hash="h"):
    return SimpleNamespace(revision=revision, artifact_hash=artifact_hash)


class NeedsArtifactFetchTests(unittest.TestCase):
    def test_no_existing_row_fetches(self):
        self.assertTrue(_needs_artifact_fetch(None, "sha1", verify_existing=False))

    def test_verify_existing_always_fetches(self):
        self.assertTrue(_needs_artifact_fetch(row("sha1"), "sha1", verify_existing=True))

    def test_stub_without_hash_fetches(self):
        # metadata-only stub: artifact_hash is None -> upgrade it even if revision matches
        self.assertTrue(_needs_artifact_fetch(row("sha1", artifact_hash=None), "sha1", verify_existing=False))

    def test_same_revision_skips(self):
        self.assertFalse(_needs_artifact_fetch(row("sha1"), "sha1", verify_existing=False))

    def test_changed_revision_fetches(self):
        self.assertTrue(_needs_artifact_fetch(row("sha1"), "sha2", verify_existing=False))

    def test_clawhub_style_none_revisions_skip(self):
        # ClawHub never sets revision; None == None must preserve the skip behavior.
        self.assertFalse(_needs_artifact_fetch(row(None), None, verify_existing=False))


if __name__ == "__main__":
    unittest.main()
