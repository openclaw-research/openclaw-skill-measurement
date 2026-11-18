"""ClawHub (clawhub.ai) skill source.

Uses the public ClawHub REST API to discover and fetch full skill artifacts.
No authentication is required.

API endpoints used:
    GET /api/v1/skills?sort=createdAt&limit={n}&cursor={c}  — full catalog listing
    GET /api/v1/skills/{slug}                                — full skill detail
    GET /api/v1/download?slug={slug}&version={v}            — ZIP artifact download

Artifact strategy:
    Each skill is downloaded as a ZIP via the download endpoint. The ZIP
    always contains SKILL.md and _meta.json and may also include scripts,
    reference docs, configs, and other files. All ZIP entries are stored at
    their original paths. The collector appends _detail.json (the raw API
    detail response) alongside the ZIP contents.

Rate limiting:
    List/detail: 3000 requests per window.
    Download:    1200 requests per window.
    Both use ratelimit-remaining and ratelimit-reset response headers,
    read and respected automatically by _handle_rate_limit().
"""

import email.utils
import io
import json
import logging
import random
import time
import zipfile
from datetime import datetime, timezone
from typing import Iterator

import requests

from sources.base import BaseSource, SkillMetadata

logger = logging.getLogger(__name__)

CLAWHUB_BASE_URL = "https://clawhub.ai"

# Pause and wait for reset when remaining requests drop below this threshold.
_RATE_LIMIT_LOW_WATERMARK = 50

_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
_RETRY_BUDGET_SECS = 3600   # total retry window per page fetch
_EMPTY_PAGE_RETRIES = 3        # retry empty listing pages before stopping
_EMPTY_PAGE_RETRY_DELAY = 10   # seconds between empty page retries
_RETRY_INITIAL_DELAY = 5    # seconds before first retry
_RETRY_MAX_DELAY = 300      # cap per individual sleep (5 minutes)
_RETRY_JITTER_MAX = 2       # seconds of random jitter added to backoff sleeps


class ClawHubSource(BaseSource):
    """Crawls clawhub.ai using the public REST API.

    Discovery flow:
        1. Paginate through /api/v1/skills using cursor-based pagination
           (sort=createdAt). End of results is detected when nextCursor is null.
        2. Fetch full detail for each slug via /api/v1/skills/{slug}.
        3. Download the full ZIP artifact and normalize into a SkillMetadata.

    Per-skill HTTP errors are logged and skipped; they do not abort the crawl.
    """

    source_name = "clawhub"

    # _detail.json is collector-injected provenance holding the raw detail API
    # response, which embeds volatile counters (downloads, installs, updatedAt).
    # It must not define artifact identity: hashing it made every verify re-fetch
    # look like a content mutation (65k spurious snapshot rows on 2026-07-02, see
    # docs/misc/artifact-duplication-investigation.md). It is still stored in S3.
    hash_excluded_files = frozenset({"_detail.json"})

    def __init__(
        self,
        base_url: str = CLAWHUB_BASE_URL,
        page_size: int = 100,
        max_skills: int = None,
        delay: float = 0.1,
    ):
        """
        Args:
            base_url:   ClawHub base URL. Override for testing or staging.
            page_size:  Results per listing page (max reliably tested: 100).
            max_skills: Stop after yielding this many skills. None = no limit.
            delay:      Seconds to sleep between HTTP requests to stay within
                        the rate limit. Default 0.1s gives ~10 req/s headroom.
        """
        self.base_url = base_url.rstrip("/")
        self.page_size = page_size
        self.max_skills = max_skills
        self.delay = delay
        self.pagination_stopped_early = False
        # Counts per-slug failures that occur inside discover() (e.g. detail-fetch
        # 503/409) and are swallowed there. The pipeline never sees these as yielded
        # skills, so they would otherwise be invisible in the stats and failure-rate
        # calculation. The pipeline reads this via getattr after iteration completes.
        self.discovery_errors = 0
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "openclaw-skill-collector/0.1"

    def discover(self) -> Iterator[SkillMetadata]:
        """Paginate through the ClawHub skill listing and yield SkillMetadata."""
        discovered = 0
        cursor = None
        empty_consecutive = 0
        self.pagination_stop_reason = "complete"

        while True:
            if self.max_skills is not None and discovered >= self.max_skills:
                logger.debug("Reached max_skills limit (%d)", self.max_skills)
                self.pagination_stop_reason = "max_skills"
                break

            try:
                items, next_cursor = self._fetch_page(cursor)
            except requests.HTTPError as exc:
                logger.critical("List API failed after retries; stopping pagination: %s", exc)
                self.pagination_stopped_early = True
                self.pagination_stop_reason = "api_error"
                break
            if not items:
                empty_consecutive += 1
                if empty_consecutive < _EMPTY_PAGE_RETRIES:
                    logger.warning(
                        "Empty page from listing API (attempt %d/%d, discovered=%d) "
                        "— possible premature end-of-catalog; retrying in %ds",
                        empty_consecutive, _EMPTY_PAGE_RETRIES, discovered,
                        _EMPTY_PAGE_RETRY_DELAY,
                    )
                    time.sleep(_EMPTY_PAGE_RETRY_DELAY)
                    continue
                else:
                    logger.warning(
                        "Empty page after %d retries (discovered=%d) "
                        "— treating as end of catalog. "
                        "ClawHub listing API may have returned premature "
                        "end-of-catalog signal.",
                        empty_consecutive, discovered,
                    )
                    self.pagination_stopped_early = True
                    self.pagination_stop_reason = "empty_page"
                    break
            else:
                empty_consecutive = 0  # reset on non-empty page

            for item in items:
                if self.max_skills is not None and discovered >= self.max_skills:
                    break

                slug = item.get("slug", "")
                if not slug:
                    logger.warning("Skipping listing result with missing slug: %s", item)
                    continue

                try:
                    detail = self._fetch_detail(slug)
                    yield self._normalize(slug, detail)
                    discovered += 1
                except requests.HTTPError as exc:
                    logger.error("HTTP error fetching detail for '%s': %s", slug, exc)
                    self.discovery_errors += 1
                except Exception as exc:
                    logger.error("Unexpected error processing slug '%s': %s", slug, exc)
                    self.discovery_errors += 1

                if self.delay:
                    time.sleep(self.delay)

            if next_cursor is None:
                logger.info(
                    "Pagination complete: no next cursor after %d skills discovered",
                    discovered,
                )
                self.pagination_stop_reason = "complete"
                break

            cursor = next_cursor

    def _fetch_page(self, cursor: str = None) -> tuple:
        """Fetch one page from the ClawHub skill listing API.

        Returns (items, next_cursor). next_cursor is None on the last page.
        Retries transient failures for up to 1 hour before raising.
        """
        url = f"{self.base_url}/api/v1/skills"
        params = {"sort": "createdAt", "limit": self.page_size}
        if cursor is not None:
            params["cursor"] = cursor

        context = f"list page cursor={(cursor or '')[:40]!r}"
        logger.debug("GET skills page: cursor=%.40s limit=%d", cursor or "", self.page_size)

        response = self._fetch_with_retry(url, params, context)
        self._handle_rate_limit(response)

        data = response.json()
        items = data.get("items", [])
        next_cursor = data.get("nextCursor")
        logger.debug("Skills page returned %d items, has_next=%s", len(items), next_cursor is not None)
        return items, next_cursor

    def _fetch_with_retry(self, url: str, params: dict, context: str) -> requests.Response:
        """GET url retrying transient HTTP errors and network failures.

        Retries: 429, 500, 502, 503, 504, timeouts, connection errors.
        No retry: 400, 401, 403, 404, or any other client error.
        Total retry budget: 1 hour. Raises on budget exhaustion or non-retryable error.
        """
        budget = float(_RETRY_BUDGET_SECS)
        delay = float(_RETRY_INITIAL_DELAY)
        attempt = 0

        while True:
            attempt += 1
            response = None
            net_exc = None

            try:
                response = self._session.get(url, params=params, timeout=15)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
                net_exc = exc

            if net_exc is None and response.status_code not in _RETRYABLE_STATUSES:
                response.raise_for_status()
                return response

            # Retryable situation — check budget before sleeping.
            if budget <= 0:
                if net_exc:
                    logger.error(
                        "%s: %s after %d attempt(s), retry budget exhausted",
                        context, type(net_exc).__name__, attempt,
                    )
                    raise net_exc
                logger.error(
                    "%s: HTTP %d after %d attempt(s), retry budget exhausted",
                    context, response.status_code, attempt,
                )
                response.raise_for_status()

            sleep_secs = self._retry_sleep(response, delay, budget)

            if net_exc:
                logger.warning(
                    "%s: %s (attempt %d); retrying in %.0fs (budget %.0fs remaining)",
                    context, type(net_exc).__name__, attempt, sleep_secs, budget,
                )
            else:
                logger.warning(
                    "%s: HTTP %d (attempt %d); retrying in %.0fs (budget %.0fs remaining)",
                    context, response.status_code, attempt, sleep_secs, budget,
                )

            time.sleep(sleep_secs)
            budget -= sleep_secs
            delay = min(delay * 2, _RETRY_MAX_DELAY)

    def _retry_sleep(self, response: "requests.Response | None", backoff: float, budget: float) -> float:
        """Return sleep duration for a retry, respecting Retry-After and budget cap."""
        if response is not None:
            raw = response.headers.get("Retry-After")
            if raw:
                sleep = None
                try:
                    sleep = float(int(raw))
                except ValueError:
                    try:
                        parsed = email.utils.parsedate_to_datetime(raw)
                        sleep = max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
                    except Exception:
                        logger.debug("Unparseable Retry-After %r; falling back to backoff", raw)
                if sleep is not None:
                    return min(sleep, _RETRY_MAX_DELAY, budget)

        jitter = random.uniform(0, _RETRY_JITTER_MAX)
        return min(backoff + jitter, _RETRY_MAX_DELAY, budget)

    def _fetch_detail(self, slug: str) -> dict:
        """Fetch the full detail object for a single skill slug."""
        url = f"{self.base_url}/api/v1/skills/{slug}"
        logger.debug("GET detail: %s", slug)
        response = self._session.get(url, timeout=15)
        response.raise_for_status()
        return response.json()

    def _fetch_artifact_zip(self, slug: str, version: str) -> bytes:
        """Download the skill ZIP archive from the ClawHub download endpoint.

        Rate limit for this endpoint is 1200 req/window (lower than search/detail).
        _handle_rate_limit() reads the response headers and pauses if needed.
        """
        url = f"{self.base_url}/api/v1/download"
        logger.debug("GET download: %s v%s", slug, version)
        response = self._session.get(url, params={"slug": slug, "version": version}, timeout=30)
        response.raise_for_status()
        self._handle_rate_limit(response)
        return response.content

    @staticmethod
    def _extract_zip(zip_bytes: bytes) -> dict:
        """Extract a ZIP archive to a {relative_path: bytes} dict.

        All entries are preserved at their original paths. Directory entries
        (names ending with '/') are skipped — only files are returned.
        """
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            return {
                name: z.read(name)
                for name in z.namelist()
                if not name.endswith("/")
            }

    def fetch_artifact(self, source_id: str, version: str, detail: dict = None) -> dict:
        """Download and extract the ZIP artifact for a skill, returning a {path: bytes} dict.

        If detail is provided (already fetched by discover()), it is used directly for
        _detail.json to avoid a redundant API call. Otherwise _fetch_detail() is called.
        """
        if detail is None:
            detail = self._fetch_detail(source_id)
        zip_bytes = self._fetch_artifact_zip(source_id, version)
        artifacts = self._extract_zip(zip_bytes)
        artifacts["_detail.json"] = json.dumps(detail, indent=2).encode("utf-8")
        return artifacts

    def _normalize(self, slug: str, detail: dict) -> SkillMetadata:
        """Map a ClawHub detail API response to a SkillMetadata stub.

        Returns SkillMetadata without artifact content — the pipeline calls
        fetch_artifact() separately if it needs to download the ZIP.

        Uses .get() with safe defaults — the API may omit optional fields for
        skills in draft or with incomplete metadata.
        """
        skill_data = detail.get("skill", {})
        version_data = detail.get("latestVersion", {})
        owner_data = detail.get("owner", {})

        # revision is left as None (the default): ClawHub exposes a semantic `version`
        # but no separate immutable VCS-style revision pointer, and artifact_hash already
        # captures byte-level identity. Setting revision = version would just duplicate
        # the version and muddy the column's meaning for git-based sources.
        return SkillMetadata(
            source_id=slug,
            name=skill_data.get("displayName") or slug,
            version=version_data.get("version") or "unversioned",
            source_url=f"{self.base_url}/skills/{slug}",
            description=skill_data.get("summary"),
            author=owner_data.get("handle"),
            license=version_data.get("license"),
            extra={
                "tags": skill_data.get("tags") or [],
                "stats": skill_data.get("stats") or {},
                "updated_at": skill_data.get("updatedAt"),
                "changelog": version_data.get("changelog"),
            },
            raw_detail=detail,
        )

    def _handle_rate_limit(self, response: requests.Response) -> None:
        """Pause if the rate-limit remaining count drops below the low watermark."""
        remaining_raw = response.headers.get("ratelimit-remaining")
        if remaining_raw is None:
            return
        try:
            remaining = int(remaining_raw)
            reset_secs = int(response.headers.get("ratelimit-reset", 5))
        except ValueError:
            logger.warning("Unparseable rate-limit headers; skipping throttle check")
            return
        if remaining < _RATE_LIMIT_LOW_WATERMARK:
            logger.warning(
                "Rate limit low (%d remaining); pausing %ds for reset",
                remaining, reset_secs,
            )
            time.sleep(reset_secs)
