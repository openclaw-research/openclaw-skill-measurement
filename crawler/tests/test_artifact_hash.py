"""Focused tests for compute_artifact_hash() and per-source hash exclusions.

Run from the project root:
    ./venv/bin/python -m unittest tests.test_artifact_hash

Background: ClawHub's _detail.json is collector-injected provenance embedding
volatile API counters (downloads, installs, updatedAt). Hashing it made every
verify re-fetch of an unchanged skill look like a content mutation. The hash
now skips each source's hash_excluded_files while still storing those files.
"""

import unittest

from pipeline import compute_artifact_hash
from sources.base import BaseSource
from sources.clawhub import ClawHubSource
from sources.github import GitHubSkillsSource

FILES = {
    "SKILL.md": b"# skill body",
    "_meta.json": b'{"slug": "x"}',
    "scripts/run.py": b"print('hi')",
}


class ComputeArtifactHashTests(unittest.TestCase):
    def test_deterministic_regardless_of_dict_order(self):
        reordered = dict(reversed(list(FILES.items())))
        self.assertEqual(compute_artifact_hash(FILES), compute_artifact_hash(reordered))

    def test_content_change_changes_hash(self):
        changed = {**FILES, "SKILL.md": b"# different body"}
        self.assertNotEqual(compute_artifact_hash(FILES), compute_artifact_hash(changed))

    def test_added_file_changes_hash(self):
        grown = {**FILES, "skill-card.md": b"card"}
        self.assertNotEqual(compute_artifact_hash(FILES), compute_artifact_hash(grown))

    def test_excluded_file_does_not_affect_hash(self):
        exclude = frozenset({"_detail.json"})
        with_detail = {**FILES, "_detail.json": b'{"downloads": 94}'}
        mutated_detail = {**FILES, "_detail.json": b'{"downloads": 314}'}
        base = compute_artifact_hash(FILES, exclude=exclude)
        self.assertEqual(base, compute_artifact_hash(with_detail, exclude=exclude))
        self.assertEqual(base, compute_artifact_hash(mutated_detail, exclude=exclude))

    def test_exclusion_only_hides_listed_names(self):
        # A real content change must still flip the hash even when an
        # exclusion set is in effect.
        exclude = frozenset({"_detail.json"})
        a = {**FILES, "_detail.json": b"{}"}
        b = {**FILES, "SKILL.md": b"# different body", "_detail.json": b"{}"}
        self.assertNotEqual(
            compute_artifact_hash(a, exclude=exclude),
            compute_artifact_hash(b, exclude=exclude),
        )

    def test_no_exclusion_preserves_legacy_behaviour(self):
        # Without an exclude set every file participates — the pre-fix definition.
        with_detail = {**FILES, "_detail.json": b'{"downloads": 94}'}
        mutated_detail = {**FILES, "_detail.json": b'{"downloads": 314}'}
        self.assertNotEqual(
            compute_artifact_hash(with_detail),
            compute_artifact_hash(mutated_detail),
        )


class SourceExclusionContractTests(unittest.TestCase):
    def test_base_default_is_empty(self):
        self.assertEqual(BaseSource.hash_excluded_files, frozenset())

    def test_clawhub_excludes_detail_json(self):
        self.assertEqual(ClawHubSource.hash_excluded_files, frozenset({"_detail.json"}))

    def test_github_excludes_nothing(self):
        # _github.json is deliberately content-stable and stays part of identity.
        self.assertEqual(GitHubSkillsSource.hash_excluded_files, frozenset())


if __name__ == "__main__":
    unittest.main()
