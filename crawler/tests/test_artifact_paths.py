"""Focused tests for hash-segmented artifact paths (storage immutability cutover).

Run from the project root:
    ./venv/bin/python -m unittest tests.test_artifact_paths

These tests are fully offline:
  - LocalArtifactStore writes into a temp directory.
  - S3ArtifactStore key construction is a pure string operation; the store is
    built with explicit bucket/region so no env vars or network are needed
    (boto3 client construction does not make any network calls).
"""

import tempfile
import unittest
from pathlib import Path

from storage.base import ARTIFACT_HASH_SEGMENT_LEN
from storage.local import LocalArtifactStore
from storage.s3 import S3ArtifactStore

# 64-char sha256-shaped hex string.
HASH = "abcdef0123456789" * 4
SEG = HASH[:ARTIFACT_HASH_SEGMENT_LEN]


class LocalHashPathTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = LocalArtifactStore(root=self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_save_many_includes_hash_segment(self):
        uri = self.store.save_many("clawhub", "slug", "1.0.0", {"SKILL.md": b"x"}, artifact_hash=HASH)
        self.assertIn(f"/clawhub/slug/1.0.0/{SEG}/", uri)
        # Files are written under the hash segment.
        self.assertTrue((Path(uri) / "SKILL.md").is_file())

    def test_save_many_uri_has_trailing_slash(self):
        uri = self.store.save_many("clawhub", "slug", "1.0.0", {"SKILL.md": b"x"}, artifact_hash=HASH)
        self.assertTrue(uri.endswith("/"), uri)

    def test_save_includes_hash_segment(self):
        uri = self.store.save("clawhub", "slug", "1.0.0", b"x", "SKILL.md", artifact_hash=HASH)
        self.assertIn(f"/1.0.0/{SEG}/SKILL.md", uri)

    def test_legacy_layout_without_hash(self):
        # Omitting the hash reproduces the pre-cutover flat layout.
        uri = self.store.save_many("clawhub", "slug", "1.0.0", {"SKILL.md": b"x"})
        self.assertNotIn(SEG, uri)
        self.assertTrue(uri.rstrip("/").endswith("/1.0.0"), uri)

    def test_deterministic_path(self):
        u1 = self.store.save_many("clawhub", "slug", "1.0.0", {"a.txt": b"1"}, artifact_hash=HASH)
        u2 = self.store.save_many("clawhub", "slug", "1.0.0", {"a.txt": b"1"}, artifact_hash=HASH)
        self.assertEqual(u1, u2)

    def test_distinct_hash_distinct_path(self):
        u1 = self.store.save_many("clawhub", "slug", "1.0.0", {"a.txt": b"1"}, artifact_hash=HASH)
        other = "f" * 64
        u2 = self.store.save_many("clawhub", "slug", "1.0.0", {"a.txt": b"1"}, artifact_hash=other)
        self.assertNotEqual(u1, u2)


class S3KeyTests(unittest.TestCase):
    def setUp(self):
        # Explicit bucket/region: no env vars required, no network performed.
        self.store = S3ArtifactStore(bucket="test-bucket", region="us-east-1")

    def test_key_includes_hash_segment(self):
        key = self.store._key("clawhub", "slug", "1.0.0", "SKILL.md", artifact_hash=HASH)
        self.assertEqual(key, f"clawhub/slug/1.0.0/{SEG}/SKILL.md")

    def test_prefix_has_trailing_slash(self):
        # save_many builds its prefix with an empty filename.
        prefix = self.store._key("clawhub", "slug", "1.0.0", "", artifact_hash=HASH)
        self.assertEqual(prefix, f"clawhub/slug/1.0.0/{SEG}/")

    def test_legacy_key_without_hash(self):
        key = self.store._key("clawhub", "slug", "1.0.0", "SKILL.md")
        self.assertEqual(key, "clawhub/slug/1.0.0/SKILL.md")

    def test_deterministic_key(self):
        k1 = self.store._key("clawhub", "slug", "1.0.0", "SKILL.md", artifact_hash=HASH)
        k2 = self.store._key("clawhub", "slug", "1.0.0", "SKILL.md", artifact_hash=HASH)
        self.assertEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()
