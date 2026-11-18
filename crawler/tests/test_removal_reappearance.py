# tests/test_removal_reappearance.py
"""
Unit tests for removal_reappearance_analysis.py

Tests cover:
- next_crawl mapping
- Removal detection (single and multiple events)
- Reappearance detection
- Zombie run exclusion
- Month exclusion
- Edge cases
"""

import pytest
from collections import defaultdict, Counter
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Import functions from the script
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from removal_reappearance_analysis import build_next_crawl, analyze


# Helpers

def make_dt(year, month, day, hour=0):
    return datetime(year, month, day, hour, tzinfo=timezone.utc)


def make_skill(source_id, author, name,
               first_crawl_run_id, last_crawl_run_id,
               first_seen_at, last_seen_at,
               artifact_hash="abc123",
               version="1.0.0"):
    return (source_id, author, name, version,
            first_crawl_run_id, last_crawl_run_id,
            first_seen_at, last_seen_at,
            artifact_hash)


def make_crawl_run(run_id, date, status="success", skills_seen=1000):
    return (run_id, make_dt(*date), status, {"skills_seen": skills_seen})


def run_analyze(crawl_runs, skill_rows_list, source="clawhub"):
    """
    Run analyze() with mocked DB connection.
    crawl_runs: list of (id, started_at, status, stats)
    skill_rows_list: list of skill tuples
    """
    mock_conn = MagicMock()

    # Mock load_crawl_runs
    def mock_load_crawl_runs(conn, source):
        return [r for r in crawl_runs
                if r[2] in ("success", "partial_success")]

    # Mock load_skill_rows
    def mock_load_skill_rows(conn, source):
        return skill_rows_list

    with patch("removal_reappearance_analysis.load_crawl_runs", mock_load_crawl_runs), \
         patch("removal_reappearance_analysis.load_skill_rows", mock_load_skill_rows):
        return analyze(mock_conn, source)


# Tests: build_next_crawl

class TestBuildNextCrawl:
    def test_basic_sequence(self):
        ids = [1, 2, 3, 4]
        result = build_next_crawl(ids)
        assert result == {1: 2, 2: 3, 3: 4}

    def test_single_run(self):
        result = build_next_crawl([1])
        assert result == {}

    def test_empty(self):
        result = build_next_crawl([])
        assert result == {}

    def test_non_consecutive_ids(self):
        ids = [5, 10, 20, 100]
        result = build_next_crawl(ids)
        assert result == {5: 10, 10: 20, 20: 100}


# Tests: Removals

class TestRemovals:

    def test_no_removals_skill_present_in_all_crawls(self):
        """Skill seen in all 3 crawls — not removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 6, 5)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 5)),
        ]
        r = run_analyze(crawl_runs, skills)
        # All dates within 5 days of each other — none exceed 14-day threshold
        assert r["removed_distinct"] == 0

    def test_single_removal_absent_from_latest(self):
        """Skill last seen in Jun, reference date Oct — gap > 14 days = removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 1

    def test_temporary_removal_and_return(self):
        """Skill removed in run 2, returns in run 3 — reappearance detected.
        Final last_seen is recent so not counted as removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        # MAX(last_seen) = Oct 13 — recent, not removed
        assert r["removed_distinct"] == 0
        assert r["reapp_distinct"] == 1
        assert r["reapp_events"] == 1

    def test_multiple_removals_same_skill(self):
        """Skill reappeared twice — 1 distinct reappeared, 2 reappearance events.
        Final last_seen is old — also counted as removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 7, 1)),
            make_crawl_run(4, (2026, 7, 3)),
            make_crawl_run(5, (2026, 9, 1)),
            make_crawl_run(6, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 7, 1),
                       last_seen_at=make_dt(2026, 7, 1),
                       artifact_hash="hash2"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=5, last_crawl_run_id=5,
                       first_seen_at=make_dt(2026, 9, 1),
                       last_seen_at=make_dt(2026, 9, 1),
                       artifact_hash="hash3"),
        ]
        r = run_analyze(crawl_runs, skills)
        # MAX(last_seen) = Jun 9, reference = Oct 13 — gap > 14 days = removed
        assert r["removed_distinct"] == 1
        assert r["reapp_distinct"] == 1
        assert r["reapp_events"] == 2

    def test_multiple_skills_some_removed(self):
        """3 skills — 2 removed (old last_seen), 1 active (recent last_seen)."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
            make_skill("skill-b", "author2", "Skill B",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 3)),
            make_skill("skill-c", "author3", "Skill C",
                       first_crawl_run_id=2, last_crawl_run_id=2,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 2
        assert r["total_ever"] == 3

    def test_skill_seen_only_once_then_gone(self):
        """Skill appears once in June, reference date Oct — gap > 14 days = removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 1


# Tests: Zombie run exclusion

class TestZombieRunExclusion:

    def test_skill_recently_seen_not_removed(self):
        """Skill with recent last_seen_at not counted as removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            # Active — recently seen
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=2,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 10, 13)),
            # Removed — old last_seen
            make_skill("skill-b", "author2", "Skill B",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 1  # only skill-b

    def test_partial_success_included(self):
        """partial_success runs still used for reappearance detection."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1), status="success"),
            make_crawl_run(2, (2026, 6, 3), status="partial_success"),
            make_crawl_run(3, (2026, 10, 13), status="success"),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["reapp_distinct"] == 1

    def test_failed_run_excluded_from_reappearance(self):
        """'failed' status run excluded from crawl sequence for reappearance."""
        all_crawl_runs = [
            make_crawl_run(1, (2026, 6, 1), status="success"),
            make_crawl_run(2, (2026, 6, 3), status="failed"),
            make_crawl_run(3, (2026, 6, 5), status="success"),
            make_crawl_run(4, (2026, 10, 13), status="success"),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            # Skipped run 3 (first_crawl_run_id=4, but next_crawl[1]=3)
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=4, last_crawl_run_id=4,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(all_crawl_runs, skills)
        assert r["reapp_distinct"] == 1

    def test_partial_success_included_in_reappearance(self):
        """partial_success runs included in crawl sequence for reappearance."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1), status="success"),
            make_crawl_run(2, (2026, 6, 3), status="partial_success"),
            make_crawl_run(3, (2026, 10, 13), status="success"),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        # partial_success run 2 in sequence — run 3 skipped run 2 = reappearance
        assert r["reapp_distinct"] == 1


# Tests: Reappearances

class TestReappearances:

    def test_no_reappearance_continuous_versions(self):
        """Skill with v1 in run 1, v2 in run 2 — NOT a reappearance."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 6, 5)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=2, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 6, 3),
                       last_seen_at=make_dt(2026, 6, 5),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["reapp_distinct"] == 0
        assert r["reapp_events"] == 0

    def test_reappearance_skipped_one_crawl(self):
        """Skill absent for >14 days, returns — true reappearance."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["reapp_distinct"] == 1
        assert r["reapp_events"] == 1

    def test_reappearance_content_changed(self):
        """Reappeared skill has different artifact_hash."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="old_hash"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="new_hash"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["content_changed"] == 1

    def test_reappearance_name_changed(self):
        """Reappeared skill has different name."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Old Name",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "New Name",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["name_changed"] == 1

    def test_multiple_reappearances_counted_once_distinct(self):
        """Skill reappears twice — 1 distinct, 2 events."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 7, 1)),
            make_crawl_run(4, (2026, 7, 3)),
            make_crawl_run(5, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 7, 1),
                       last_seen_at=make_dt(2026, 7, 1),
                       artifact_hash="hash2"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=5, last_crawl_run_id=5,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13),
                       artifact_hash="hash3"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["reapp_distinct"] == 1
        assert r["reapp_events"] == 2


# Tests: Month exclusion

class TestMonthExclusion:

    def test_may_excluded_from_monthly_tables(self):
        """May 2026 removal not counted in monthly breakdown."""
        crawl_runs = [
            make_crawl_run(1, (2026, 5, 26), status="success"),
            make_crawl_run(2, (2026, 10, 13), status="success"),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 5, 26),
                       last_seen_at=make_dt(2026, 5, 26)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 1
        assert "2026-05" not in r["monthly_removed_distinct"]

    def test_june_included_in_monthly_tables(self):
        """June removals appear in monthly breakdown."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert "2026-06" in r["monthly_removed_distinct"]
        assert r["monthly_removed_distinct"]["2026-06"] == 1


# Tests: Author concentration

class TestAuthorConcentration:

    def test_author_counts_removed_skills(self):
        """Author concentration counts correctly."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
            make_skill("skill-b", "author1", "Skill B",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
            make_skill("skill-c", "author2", "Skill C",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["total_authors_removed"] == 2
        top_authors = dict(r["top10_authors"])
        assert top_authors.get("author1") == 2
        assert top_authors.get("author2") == 1


# Tests: Edge cases

class TestEdgeCases:

    def test_empty_corpus(self):
        """No skills — all counts zero."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
        ]
        r = run_analyze(crawl_runs, [])
        assert r["total_ever"] == 0
        assert r["removed_distinct"] == 0
        assert r["reapp_distinct"] == 0

    def test_single_crawl_no_removals(self):
        """Only one crawl — skill last_seen = reference_date, gap = 0 = not removed."""
        crawl_runs = [make_crawl_run(1, (2026, 6, 1))]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 0

    def test_skill_recently_seen_not_removed(self):
        """Skill last_seen = reference_date — gap = 0 = not removed."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=2, last_crawl_run_id=2,
                       first_seen_at=make_dt(2026, 10, 13),
                       last_seen_at=make_dt(2026, 10, 13)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["removed_distinct"] == 0

    def test_lifespan_calculation(self):
        """Lifespan = last_seen - first_seen for removed skills."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 10, 13)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1)),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["lifespan_days"] == [0]  # last_seen - first_seen = 0 days

    def test_gap_calculation(self):
        """Gap = first_seen of return - last_seen of departure."""
        crawl_runs = [
            make_crawl_run(1, (2026, 6, 1)),
            make_crawl_run(2, (2026, 6, 3)),
            make_crawl_run(3, (2026, 7, 1)),
        ]
        skills = [
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=1, last_crawl_run_id=1,
                       first_seen_at=make_dt(2026, 6, 1),
                       last_seen_at=make_dt(2026, 6, 1),
                       artifact_hash="hash1"),
            make_skill("skill-a", "author1", "Skill A",
                       first_crawl_run_id=3, last_crawl_run_id=3,
                       first_seen_at=make_dt(2026, 7, 1),
                       last_seen_at=make_dt(2026, 7, 1),
                       artifact_hash="hash2"),
        ]
        r = run_analyze(crawl_runs, skills)
        assert r["reapp_gap_days"] == [30]  # Jul 1 - Jun 1 = 30 days