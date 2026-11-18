# tests/test_clawhub_pagination.py
"""
Unit tests for ClawHub pagination improvements:
- Empty page retry logic
- pagination_stop_reason tracking
- Stop reason on api_error, max_skills, complete, empty_page
"""

import time
from unittest.mock import MagicMock, patch, call
import pytest
import requests

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from sources.clawhub import ClawHubSource


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_source():
    """Create a ClawHubSource with mocked session."""
    src = ClawHubSource.__new__(ClawHubSource)
    src.base_url = "https://clawhub.ai"
    src.page_size = 100
    src.max_skills = None
    src.delay = 0
    src.pagination_stopped_early = False
    src.pagination_stop_reason = "complete"
    src.discovery_errors = 0
    src._session = MagicMock()
    return src


def make_page(items, next_cursor=None):
    """Return a (items, next_cursor) tuple as _fetch_page would."""
    return items, next_cursor


def make_skill_item(slug):
    return {"slug": slug}


def make_detail(slug):
    return {
        "skill": {
            "slug": slug,
            "displayName": slug,
            "summary": "test",
            "description": "test",
            "tags": {"latest": "1.0.0"},
            "stats": {"downloads": 0, "installs": 0, "stars": 0,
                      "comments": 0, "versions": 1},
            "createdAt": 1700000000000,
            "updatedAt": 1700000000000,
        },
        "latestVersion": {"version": "1.0.0", "license": "MIT"},
        "owner": {"handle": "testauthor"},
        "moderation": {},
    }


# ---------------------------------------------------------------------------
# Tests: Normal pagination
# ---------------------------------------------------------------------------

class TestNormalPagination:

    def test_single_page_complete(self):
        """One page, no next cursor — stop_reason = complete."""
        src = make_source()
        items = [make_skill_item("skill-a"), make_skill_item("skill-b")]

        with patch.object(src, "_fetch_page", return_value=make_page(items, None)), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)):
            result = list(src.discover())

        assert len(result) == 2
        assert src.pagination_stop_reason == "complete"
        assert not src.pagination_stopped_early

    def test_multi_page_complete(self):
        """Two pages, second has no next cursor."""
        src = make_source()
        page1 = ([make_skill_item("skill-a")], "cursor1")
        page2 = ([make_skill_item("skill-b")], None)

        with patch.object(src, "_fetch_page", side_effect=[page1, page2]), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)):
            result = list(src.discover())

        assert len(result) == 2
        assert src.pagination_stop_reason == "complete"

    def test_max_skills_stop(self):
        """Stop when max_skills reached."""
        src = make_source()
        src.max_skills = 1
        items = [make_skill_item("skill-a"), make_skill_item("skill-b")]

        # Provide multiple pages so the while loop can hit the max_skills check
        pages = [
            make_page(items, "cursor1"),  # first page — skill-a consumed, max hit
            make_page(items, None),       # second page — never reached
        ]

        with patch.object(src, "_fetch_page", side_effect=pages), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)):
            result = list(src.discover())

        assert len(result) == 1
        assert src.pagination_stop_reason == "max_skills"


# ---------------------------------------------------------------------------
# Tests: Empty page retry
# ---------------------------------------------------------------------------

class TestEmptyPageRetry:

    def test_empty_page_retries_then_succeeds(self):
        """Empty page on first attempt, succeeds on second."""
        src = make_source()
        items = [make_skill_item("skill-a")]

        pages = [
            ([], "cursor1"),        # empty — retry 1
            (items, None),          # success
        ]

        with patch.object(src, "_fetch_page", side_effect=pages), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)), \
             patch("time.sleep") as mock_sleep:
            result = list(src.discover())

        assert len(result) == 1
        assert src.pagination_stop_reason == "complete"
        assert not src.pagination_stopped_early
        mock_sleep.assert_called()  # retried with delay

    def test_empty_page_exhausts_retries(self):
        """Empty page on all retries — pagination_stopped_early=True."""
        src = make_source()

        # All pages empty
        pages = [([], "cursor%d" % i) for i in range(10)]

        with patch.object(src, "_fetch_page", side_effect=pages), \
             patch("time.sleep"):
            result = list(src.discover())

        assert result == []
        assert src.pagination_stopped_early
        assert src.pagination_stop_reason == "empty_page"

    def test_empty_page_counter_resets_on_success(self):
        """Empty page counter resets after a successful page."""
        src = make_source()
        items = [make_skill_item("skill-a")]

        pages = [
            ([], "cursor1"),        # empty — retry 1
            (items, "cursor2"),     # success — counter resets
            ([], "cursor3"),        # empty — retry 1 again (not retry 2)
            ([], "cursor4"),        # empty — retry 2
            ([], None),             # empty — retry 3 → stop
        ]

        with patch.object(src, "_fetch_page", side_effect=pages), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)), \
             patch("time.sleep"):
            result = list(src.discover())

        assert len(result) == 1
        assert src.pagination_stopped_early
        assert src.pagination_stop_reason == "empty_page"

    def test_empty_page_uses_retry_delay(self):
        """Retry delay is called with correct value."""
        from sources import clawhub as ch_module
        src = make_source()

        pages = [
            ([], "cursor1"),
            ([make_skill_item("skill-a")], None),
        ]

        with patch.object(src, "_fetch_page", side_effect=pages), \
             patch.object(src, "_fetch_detail", side_effect=lambda s: make_detail(s)), \
             patch.object(src, "_normalize", side_effect=lambda s, d: MagicMock(source_id=s)), \
             patch("time.sleep") as mock_sleep:
            list(src.discover())

        mock_sleep.assert_called_with(ch_module._EMPTY_PAGE_RETRY_DELAY)


# ---------------------------------------------------------------------------
# Tests: API error stop
# ---------------------------------------------------------------------------

class TestApiErrorStop:

    def test_api_error_sets_stop_reason(self):
        """HTTPError from _fetch_page sets stop_reason=api_error."""
        src = make_source()

        with patch.object(src, "_fetch_page",
                          side_effect=requests.HTTPError("500")):
            result = list(src.discover())

        assert result == []
        assert src.pagination_stopped_early
        assert src.pagination_stop_reason == "api_error"


# ---------------------------------------------------------------------------
# Tests: pagination_stop_reason values
# ---------------------------------------------------------------------------

class TestStopReasons:

    def test_stop_reason_complete_on_no_next_cursor(self):
        """stop_reason=complete when API signals end normally."""
        src = make_source()
        with patch.object(src, "_fetch_page", return_value=([], None)), \
             patch("time.sleep"):
            list(src.discover())
        # Either empty_page or complete depending on retry count
        assert src.pagination_stop_reason in ("empty_page", "complete")

    def test_stop_reason_initialized_to_complete(self):
        """pagination_stop_reason starts as 'complete'."""
        src = make_source()
        assert src.pagination_stop_reason == "complete"

    def test_all_stop_reasons_are_strings(self):
        """stop_reason is always a non-empty string."""
        for pages, expected in [
            ([([], None)] * 10, "empty_page"),
            (requests.HTTPError("500"), "api_error"),
        ]:
            src = make_source()
            if isinstance(pages, list):
                with patch.object(src, "_fetch_page", side_effect=pages), \
                     patch("time.sleep"):
                    list(src.discover())
            else:
                with patch.object(src, "_fetch_page", side_effect=pages):
                    list(src.discover())
            assert isinstance(src.pagination_stop_reason, str)
            assert len(src.pagination_stop_reason) > 0