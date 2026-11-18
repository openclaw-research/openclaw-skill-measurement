"""Offline tests for the GitHub artifact-fetch path.

Run from the project root:
    ./venv/bin/python -m unittest tests.test_github_fetch

Builds synthetic .tar.gz blobs in memory (mirroring GitHub's "{repo}-{sha}/" top-level
layout) and exercises the pure extraction/guard logic. No network is performed.
"""

import io
import json
import tarfile
import unittest

from sources.base import CaptureLimitExceeded
from sources.github import GitHubSkillsSource, MAX_FILE_BYTES, WARN_FILES

TOP = "obsidian-skills-a1dc48/"  # GitHub-style top-level dir


def make_targz(entries, *, with_pax_header=False):
    """entries: list of (name, bytes|None|('link', target)). None => directory; ('link',t) => symlink."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        if with_pax_header:
            # A pax_global_header member has no "/" in its name (like real GH tarballs).
            ti = tarfile.TarInfo("pax_global_header")
            ti.type = tarfile.XGLTYPE
            tf.addfile(ti, io.BytesIO(b""))
        for name, payload in entries:
            if payload is None:
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif isinstance(payload, tuple) and payload[0] == "link":
                ti = tarfile.TarInfo(name)
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload[1]
                tf.addfile(ti)
            else:
                ti = tarfile.TarInfo(name)
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


class ParseSourceIdTests(unittest.TestCase):
    def test_nested(self):
        self.assertEqual(
            GitHubSkillsSource._parse_source_id("openclaw/skills//document-skills/pdf"),
            ("openclaw", "skills", "document-skills/pdf"),
        )

    def test_root(self):
        self.assertEqual(
            GitHubSkillsSource._parse_source_id("owner/repo//"),
            ("owner", "repo", ""),
        )


class ExtractionTests(unittest.TestCase):
    def test_extracts_only_skill_subtree_relative(self):
        tar = make_targz([
            (TOP, None),
            (TOP + "skills/pdf/", None),
            (TOP + "skills/pdf/SKILL.md", b"# pdf\n"),
            (TOP + "skills/pdf/scripts/run.py", b"print('x')\n"),
            (TOP + "skills/other/SKILL.md", b"# other\n"),
            (TOP + "README.md", b"top\n"),
        ], with_pax_header=True)
        files = GitHubSkillsSource._extract_skill_subtree(tar, "skills/pdf")
        self.assertEqual(set(files), {"SKILL.md", "scripts/run.py"})
        self.assertEqual(files["SKILL.md"], b"# pdf\n")

    def test_skips_symlinks(self):
        tar = make_targz([
            (TOP + "skills/x/SKILL.md", b"ok\n"),
            (TOP + "skills/x/evil", ("link", "/etc/passwd")),
        ])
        files = GitHubSkillsSource._extract_skill_subtree(tar, "skills/x")
        self.assertEqual(set(files), {"SKILL.md"})

    def test_per_file_size_cap(self):
        tar = make_targz([(TOP + "skills/x/big.bin", b"a" * 32)])
        with self.assertRaises(CaptureLimitExceeded) as cm:
            GitHubSkillsSource._extract_skill_subtree(tar, "skills/x", max_file_bytes=16)
        self.assertEqual(cm.exception.limit, "per_file")

    def test_total_size_cap(self):
        tar = make_targz([
            (TOP + "skills/x/a", b"a" * 20),
            (TOP + "skills/x/b", b"b" * 20),
        ])
        with self.assertRaises(CaptureLimitExceeded) as cm:
            GitHubSkillsSource._extract_skill_subtree(tar, "skills/x", max_total_bytes=30)
        self.assertEqual(cm.exception.limit, "total_uncompressed")

    def test_file_count_cap(self):
        tar = make_targz([(TOP + f"skills/x/f{i}", b"y") for i in range(5)])
        with self.assertRaises(CaptureLimitExceeded) as cm:
            GitHubSkillsSource._extract_skill_subtree(tar, "skills/x", max_files=3)
        self.assertEqual(cm.exception.limit, "file_count")

    def test_empty_when_skill_dir_absent(self):
        tar = make_targz([(TOP + "skills/x/SKILL.md", b"ok\n")])
        self.assertEqual(GitHubSkillsSource._extract_skill_subtree(tar, "skills/does-not-exist"), {})

    def test_default_caps_are_sane(self):
        # Guard against accidental shrink of the per-file cap below a realistic skill file.
        self.assertGreaterEqual(MAX_FILE_BYTES, 1024 * 1024)


class FetchArtifactTests(unittest.TestCase):
    """fetch_artifact() with the network download monkeypatched to a synthetic tarball."""

    def setUp(self):
        self.src = GitHubSkillsSource(seeds=[], token="x", delay=0)
        tar = make_targz([
            (TOP + "skills/pdf/SKILL.md", b"# pdf\n"),
            (TOP + "skills/pdf/reference.md", b"ref\n"),
        ], with_pax_header=True)
        self.src._download_tarball = lambda owner, repo, sha: tar  # no network

    def test_returns_skill_files_plus_provenance(self):
        detail = {"sha": "c0ffee", "default_branch": "main", "skill_dir": "skills/pdf",
                  "skill_path": "skills/pdf/SKILL.md"}
        files = self.src.fetch_artifact("kepano/obsidian-skills//skills/pdf", "unversioned", detail)
        self.assertIn("SKILL.md", files)
        self.assertIn("reference.md", files)
        self.assertIn("_github.json", files)
        prov = json.loads(files["_github.json"])
        self.assertEqual(prov["repo"], "obsidian-skills")
        self.assertEqual(prov["skill_dir"], "skills/pdf")
        self.assertEqual(prov["skill_path"], "skills/pdf/SKILL.md")

    def test_provenance_is_content_stable_across_commits(self):
        # The provenance file (and thus the artifact bytes) must NOT depend on the
        # repo commit SHA — otherwise every commit would look like a skill mutation.
        files = self.src.fetch_artifact(
            "kepano/obsidian-skills//skills/pdf", "unversioned",
            {"sha": "c0ffee", "skill_dir": "skills/pdf", "skill_path": "skills/pdf/SKILL.md"},
        )
        prov = files["_github.json"]
        self.assertNotIn(b"c0ffee", prov)
        self.assertNotIn(b"commit_sha", prov)


class CaptureMetadataTests(unittest.TestCase):
    def setUp(self):
        self.src = GitHubSkillsSource(seeds=[], token="x", delay=0)

    def test_normal_skill_has_no_capture_flags(self):
        files = {"SKILL.md": b"x" * 100, "_github.json": b"{}"}
        self.src._tar_cache_bytes = b"z" * 1000
        self.assertEqual(self.src.capture_metadata(files), {})

    def test_near_limit_file_count_flagged(self):
        files = {f"f{i}": b"y" for i in range(WARN_FILES + 1)}
        self.src._tar_cache_bytes = b"z" * 1000
        meta = self.src.capture_metadata(files)
        self.assertEqual(meta["capture_status"], "near_limit")
        self.assertIn("file_count", meta["capture_warnings"])
        self.assertEqual(meta["observed_files"], WARN_FILES + 1)


if __name__ == "__main__":
    unittest.main()
