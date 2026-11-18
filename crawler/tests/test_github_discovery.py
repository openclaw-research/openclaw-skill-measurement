"""Offline tests for the read-only GitHub discovery spike.

Run from the project root:
    ./venv/bin/python -m unittest tests.test_github_discovery

These tests exercise only the pure mapping logic (tree filtering + metadata
construction) and registration. No network is performed — the GitHub HTTP methods
(_resolve_head/_fetch_tree/_get) are not called here.
"""

import os
import tempfile
import unittest

import cli
from sources.base import BaseSource, SkillMetadata
from sources.github import GitHubSkillsSource, SEEDS_FILE, load_seeds

# A synthetic recursive git-tree response (subset of the GitHub API shape).
FAKE_TREE = [
    {"path": "SKILL.md", "type": "blob"},
    {"path": "document-skills", "type": "tree"},
    {"path": "document-skills/pdf", "type": "tree"},
    {"path": "document-skills/pdf/SKILL.md", "type": "blob"},
    {"path": "document-skills/pdf/reference.md", "type": "blob"},
    {"path": "README.md", "type": "blob"},
    {"path": "nested/MYSKILL.md", "type": "blob"},   # basename != SKILL.md
    {"path": "nested/skill.md", "type": "blob"},     # wrong case, excluded
]


class SkillPathFilterTests(unittest.TestCase):
    def test_only_exact_skill_md_blobs(self):
        paths = list(GitHubSkillsSource._iter_skill_paths(FAKE_TREE))
        self.assertEqual(paths, ["SKILL.md", "document-skills/pdf/SKILL.md"])

    def test_ignores_tree_entries_and_other_files(self):
        paths = set(GitHubSkillsSource._iter_skill_paths(FAKE_TREE))
        self.assertNotIn("document-skills/pdf", paths)        # a tree
        self.assertNotIn("README.md", paths)
        self.assertNotIn("nested/MYSKILL.md", paths)
        self.assertNotIn("nested/skill.md", paths)            # case-sensitive

    def test_empty_tree(self):
        self.assertEqual(list(GitHubSkillsSource._iter_skill_paths([])), [])


class MetadataMappingTests(unittest.TestCase):
    def setUp(self):
        self.src = GitHubSkillsSource(seeds=[], token="x")  # token avoids env lookup; no network

    def test_nested_skill_metadata(self):
        m = self.src._build_metadata("openclaw", "skills", "main", "a" * 40, "document-skills/pdf/SKILL.md")
        self.assertEqual(m.source_id, "openclaw/skills//document-skills/pdf")
        self.assertEqual(m.name, "pdf")
        self.assertEqual(m.version, "unversioned")
        self.assertEqual(m.revision, "a" * 40)
        self.assertEqual(m.author, "openclaw")
        self.assertIn("blob/" + "a" * 40 + "/document-skills/pdf/SKILL.md", m.source_url)
        self.assertEqual(m.extra["skill_path"], "document-skills/pdf/SKILL.md")
        self.assertEqual(m.extra["repo"], "openclaw/skills")
        # raw_detail carries the pinned SHA through to fetch_artifact().
        self.assertEqual(m.raw_detail["sha"], "a" * 40)
        self.assertEqual(m.raw_detail["skill_dir"], "document-skills/pdf")

    def test_root_skill_metadata(self):
        m = self.src._build_metadata("owner", "repo", "main", "deadbeef", "SKILL.md")
        # Repo-root SKILL.md → empty skill_dir → trailing "//", name falls back to repo.
        self.assertEqual(m.source_id, "owner/repo//")
        self.assertEqual(m.name, "repo")
        self.assertEqual(m.revision, "deadbeef")

    def test_revision_is_commit_sha(self):
        m = self.src._build_metadata("o", "r", "main", "c0ffee", "x/SKILL.md")
        self.assertEqual(m.revision, "c0ffee")


class ContractAndRegistrationTests(unittest.TestCase):
    def test_is_base_source(self):
        self.assertTrue(issubclass(GitHubSkillsSource, BaseSource))
        self.assertEqual(GitHubSkillsSource.source_name, "github-skills")
        self.assertFalse(GitHubSkillsSource(seeds=[], token="x").pagination_stopped_early)

    def test_registered_in_cli(self):
        registry = cli._source_registry()
        self.assertIn("github-skills", registry)
        self.assertIs(registry["github-skills"], GitHubSkillsSource)

    def test_constructible_with_cli_kwargs(self):
        # cmd_crawl builds sources as source_cls(page_size=, max_skills=, delay=).
        src = GitHubSkillsSource(page_size=100, max_skills=5, delay=0.1)
        self.assertEqual(src.max_skills, 5)

    def test_discover_is_generator_and_skips_bad_seed(self):
        # A malformed seed (no slash) is skipped without any network call.
        src = GitHubSkillsSource(seeds=["not-a-repo"], token="x", delay=0)
        self.assertEqual(list(src.discover()), [])


class SeedLoaderTests(unittest.TestCase):
    def test_load_seeds_ignores_comments_and_blanks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# header comment\n\nowner/repo-a\n  owner/repo-b  # inline note\n\n# trailing\n")
            path = f.name
        try:
            self.assertEqual(load_seeds(path), ["owner/repo-a", "owner/repo-b"])
        finally:
            os.unlink(path)

    def test_shipped_seeds_file_is_valid(self):
        seeds = load_seeds(SEEDS_FILE)
        self.assertGreater(len(seeds), 0)
        for s in seeds:
            self.assertIn("/", s, f"malformed seed: {s!r}")
            self.assertNotIn("#", s)
            self.assertEqual(s, s.strip())

    def test_default_seeds_loaded_from_file_when_unset(self):
        src = GitHubSkillsSource()  # no seeds arg -> reads the shipped file
        self.assertEqual(src.seeds, load_seeds(SEEDS_FILE))
        self.assertGreater(len(src.seeds), 0)


if __name__ == "__main__":
    unittest.main()
