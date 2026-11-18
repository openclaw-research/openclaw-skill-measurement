"""GitHub skills source.

Discovers OpenClaw-style skills in public GitHub repositories by locating files
named exactly ``SKILL.md`` anywhere in a repo's tree, pinned to the default
branch's HEAD commit SHA, and fetches each skill's files from the commit tarball.

  - ``discover()`` yields lightweight SkillMetadata stubs (no artifact content).
  - ``fetch_artifact()`` downloads the commit tarball and returns the skill's
    subtree as a {path: bytes} map, with safety guards (see below). It is only
    called outside ``--dry-run`` / ``--metadata-only``.

Run modes:
    cli.py crawl --source github-skills --dry-run        # discover only, no writes
    cli.py crawl --source github-skills --metadata-only  # persist stubs, no artifacts
    cli.py crawl --source github-skills                  # full: fetch + store artifacts

Skill identity (source_id):
    "{owner}/{repo}//{skill_dir}" where skill_dir is the POSIX path of the directory
    containing SKILL.md ("" for a repo-root SKILL.md). The "//" separator keeps the
    repo distinct from the intra-repo path so one repo can hold many skills.

revision:
    The resolved default-branch HEAD commit SHA — an immutable pointer for the
    discovered snapshot (populates skills.revision). version is "unversioned": a
    GitHub branch carries no semantic version. The SHA is carried through
    SkillMetadata.raw_detail so fetch_artifact() pins the exact tarball.

Safety (fetch_artifact never executes downloaded code):
    - compressed tarball size cap; per-file, total-uncompressed, and file-count caps
    - only regular files (symlinks/hardlinks/devices skipped); path-traversal rejected
    - a _github.json provenance file is added for reproducibility

Auth:
    Uses GITHUB_TOKEN from the environment if present (raises the rate limit from
    60 to 5000 requests/hour). Works unauthenticated for small seed lists.
"""

import io
import json
import logging
import os
import posixpath
import tarfile
import time
from typing import Iterator

import requests

from sources.base import BaseSource, CaptureLimitExceeded, SkillMetadata

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"

# --- artifact-fetch HARD caps (host protection for an un-sandboxed box) ---
# Set generously so we capture virtually all real skills (including large/suspicious
# ones — this is a security-research corpus); they exist to bound a decompression bomb
# or runaway artifact, not to filter content. Exceeding one raises CaptureLimitExceeded
# and the pipeline records a stub instead of storing a (partial) artifact.
MAX_TARBALL_BYTES = 500 * 1024 * 1024      # compressed repo tarball
MAX_TOTAL_UNCOMPRESSED = 250 * 1024 * 1024  # one skill's total extracted bytes
MAX_FILE_BYTES = 100 * 1024 * 1024          # any single extracted file
MAX_FILES = 10000                            # number of files per skill

# --- "near-cap" WARNING thresholds: still captured, but flagged in metadata ---
WARN_TARBALL_BYTES = 250 * 1024 * 1024
WARN_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024
WARN_FILE_BYTES = 50 * 1024 * 1024
WARN_FILES = 5000

# Exact filename that marks a skill. No fuzzy heuristics yet (e.g. .claude/skills/).
SKILL_MARKER = "SKILL.md"

# Hand-maintained allowlist of repos to crawl. Data lives outside the code so it can
# be edited/reviewed without touching the crawler (see the file's header for format).
SEEDS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "github_skills_seeds.txt",
)


def load_seeds(path: str = SEEDS_FILE) -> list:
    """Read "owner/repo" seeds from a text file.

    One entry per line; blank lines and anything after a '#' are ignored (repo names
    cannot contain '#', so inline comments are safe).
    """
    seeds = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            entry = line.split("#", 1)[0].strip()
            if entry:
                seeds.append(entry)
    return seeds


class GitHubSkillsSource(BaseSource):
    """Read-only discovery of SKILL.md files across a seed list of GitHub repos."""

    source_name = "github-skills"

    def __init__(self, page_size: int = None, max_skills: int = None, delay: float = 0.5,
                 seeds: list = None, token: str = None):
        """
        Args:
            page_size:  Accepted for CLI compatibility but unused — GitHub discovery
                        is repo-driven, not page-driven.
            max_skills: Stop after yielding this many skills. None = no limit.
            delay:      Seconds to sleep before each HTTP request (politeness/rate limit).
            seeds:      List of "owner/repo" strings. Defaults to the entries in
                        config/github_skills_seeds.txt (see load_seeds()).
            token:      GitHub token. Falls back to the GITHUB_TOKEN env var; optional.
        """
        self.max_skills = max_skills
        self.delay = delay
        self.seeds = list(seeds) if seeds is not None else load_seeds()

        # Cache the most-recently-downloaded repo tarball. discover() groups a repo's
        # skills consecutively, so caching just the last (owner, repo, sha) avoids
        # re-downloading the whole repo once per skill while keeping memory bounded.
        self._tar_cache_key = None
        self._tar_cache_bytes = None

        self._session = requests.Session()
        self._session.headers["User-Agent"] = "openclaw-skill-collector/0.1"
        self._session.headers["Accept"] = "application/vnd.github+json"

        token = token or os.environ.get("GITHUB_TOKEN")
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"
            logger.info("GitHub source: using GITHUB_TOKEN (authenticated, 5000 req/hr)")
        else:
            logger.info("GitHub source: no GITHUB_TOKEN found (unauthenticated, 60 req/hr)")

    def discover(self) -> Iterator[SkillMetadata]:
        """Yield a SkillMetadata stub for each SKILL.md found across the seed repos.

        Per-repo errors (404, rate limit, network) are logged and skipped — one bad
        repo never aborts discovery of the others.
        """
        discovered = 0
        for repo_full in self.seeds:
            if self.max_skills is not None and discovered >= self.max_skills:
                break

            if "/" not in repo_full:
                logger.warning("Skipping malformed seed (expected owner/repo): %r", repo_full)
                continue
            owner, repo = repo_full.split("/", 1)

            try:
                default_branch, commit_sha = self._resolve_head(owner, repo)
                tree = self._fetch_tree(owner, repo, commit_sha)
            except requests.HTTPError as exc:
                logger.error("Skipping repo %s: HTTP error: %s", repo_full, exc)
                continue
            except Exception as exc:
                logger.error("Skipping repo %s: unexpected error: %s", repo_full, exc)
                continue

            paths = list(self._iter_skill_paths(tree))
            logger.info("%s @ %s: found %d SKILL.md file(s)", repo_full, commit_sha[:12], len(paths))

            for path in paths:
                if self.max_skills is not None and discovered >= self.max_skills:
                    break
                yield self._build_metadata(owner, repo, default_branch, commit_sha, path)
                discovered += 1

    # --- network ---

    def _get(self, url: str) -> dict:
        """GET a GitHub API URL and return parsed JSON; raises on non-2xx."""
        if self.delay:
            time.sleep(self.delay)
        resp = self._session.get(url, timeout=20)
        resp.raise_for_status()
        return resp.json()

    def _resolve_head(self, owner: str, repo: str) -> tuple:
        """Return (default_branch, commit_sha) for the repo's default-branch HEAD."""
        info = self._get(f"{GITHUB_API}/repos/{owner}/{repo}")
        default_branch = info.get("default_branch") or "main"
        commit = self._get(f"{GITHUB_API}/repos/{owner}/{repo}/commits/{default_branch}")
        return default_branch, commit["sha"]

    def _fetch_tree(self, owner: str, repo: str, commit_sha: str) -> list:
        """Return the recursive git tree (list of entries) at the given commit SHA."""
        data = self._get(
            f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{commit_sha}?recursive=1"
        )
        if data.get("truncated"):
            logger.warning(
                "Tree for %s/%s truncated by the API; some SKILL.md files may be missed",
                owner, repo,
            )
        return data.get("tree", [])

    # --- pure logic (offline-testable) ---

    @staticmethod
    def _iter_skill_paths(tree: list) -> Iterator[str]:
        """Yield paths of blob entries whose basename is exactly SKILL.md."""
        for entry in tree:
            if entry.get("type") == "blob" and posixpath.basename(entry.get("path", "")) == SKILL_MARKER:
                yield entry["path"]

    def _build_metadata(self, owner: str, repo: str, default_branch: str,
                        commit_sha: str, path: str) -> SkillMetadata:
        """Map one SKILL.md path to a SkillMetadata stub (no artifact content)."""
        skill_dir = posixpath.dirname(path)  # "" for a repo-root SKILL.md
        return SkillMetadata(
            source_id=f"{owner}/{repo}//{skill_dir}",
            name=posixpath.basename(skill_dir) if skill_dir else repo,
            version="unversioned",
            revision=commit_sha,
            source_url=f"https://github.com/{owner}/{repo}/blob/{commit_sha}/{path}",
            author=owner,
            extra={
                "repo": f"{owner}/{repo}",
                "default_branch": default_branch,
                "skill_path": path,
                "skill_dir": skill_dir,
            },
            # raw_detail is not persisted; it carries the pinned SHA (and friends)
            # through to fetch_artifact() so it downloads the exact commit tarball.
            raw_detail={
                "owner": owner,
                "repo": repo,
                "sha": commit_sha,
                "default_branch": default_branch,
                "skill_dir": skill_dir,
                "skill_path": path,
            },
        )

    @staticmethod
    def _parse_source_id(source_id: str) -> tuple:
        """Split "owner/repo//skill_dir" into (owner, repo, skill_dir)."""
        repo_part, _, skill_dir = source_id.partition("//")
        owner, _, repo = repo_part.partition("/")
        return owner, repo, skill_dir

    def _download_tarball(self, owner: str, repo: str, sha: str) -> bytes:
        """Download the gzipped commit tarball, capped at MAX_TARBALL_BYTES.

        Caches the most recent (owner, repo, sha) so a repo with many skills is
        downloaded once rather than once per skill.
        """
        key = (owner, repo, sha)
        if self._tar_cache_key == key:
            return self._tar_cache_bytes

        url = f"{GITHUB_API}/repos/{owner}/{repo}/tarball/{sha}"
        if self.delay:
            time.sleep(self.delay)
        resp = self._session.get(url, timeout=60, stream=True)
        resp.raise_for_status()

        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=65536):
            buf.extend(chunk)
            if len(buf) > MAX_TARBALL_BYTES:
                resp.close()
                raise CaptureLimitExceeded(
                    "tarball", len(buf), MAX_TARBALL_BYTES,
                    f"tarball for {owner}/{repo}@{sha[:12]} exceeds "
                    f"{MAX_TARBALL_BYTES} bytes; refusing to download further",
                )
        data = bytes(buf)
        self._tar_cache_key = key
        self._tar_cache_bytes = data
        return data

    @staticmethod
    def _extract_skill_subtree(tar_bytes: bytes, skill_dir: str, *,
                               max_files: int = MAX_FILES,
                               max_file_bytes: int = MAX_FILE_BYTES,
                               max_total_bytes: int = MAX_TOTAL_UNCOMPRESSED) -> dict:
        """Return {path_relative_to_skill_dir: bytes} for files under skill_dir.

        GitHub tarballs wrap everything in a single top-level dir ("{repo}-{sha}/").
        Only regular files are returned (symlinks/hardlinks/devices are skipped, so
        nothing is followed out of the archive), path traversal is rejected, and the
        per-file / total-uncompressed / file-count caps are enforced. Nothing is
        executed and nothing is written to disk here — bytes only.
        """
        files = {}
        total = 0
        count = 0
        want = (skill_dir + "/") if skill_dir else ""

        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
            members = tf.getmembers()
            # Top-level prefix = first path component of the first member that has one
            # (skips a leading pax_global_header entry, which has no "/").
            prefix = None
            for m in members:
                if "/" in m.name:
                    prefix = m.name.split("/", 1)[0] + "/"
                    break
            if prefix is None:
                return files

            for m in members:
                if not m.isfile():  # skip dirs, symlinks, hardlinks, devices
                    continue
                if not m.name.startswith(prefix):
                    continue
                repo_rel = m.name[len(prefix):]
                if want and not repo_rel.startswith(want):
                    continue
                rel = repo_rel[len(want):]
                # Reject absolute paths and any traversal segment.
                if not rel or rel.startswith("/") or ".." in rel.split("/"):
                    logger.warning("Skipping unsafe archive path: %r", m.name)
                    continue

                if m.size > max_file_bytes:
                    raise CaptureLimitExceeded(
                        "per_file", m.size, max_file_bytes,
                        f"file {rel!r} exceeds per-file cap ({m.size} > {max_file_bytes} bytes)",
                    )
                count += 1
                if count > max_files:
                    raise CaptureLimitExceeded(
                        "file_count", count, max_files,
                        f"skill exceeds max file count ({max_files})",
                    )
                total += m.size
                if total > max_total_bytes:
                    raise CaptureLimitExceeded(
                        "total_uncompressed", total, max_total_bytes,
                        f"skill exceeds total uncompressed cap ({max_total_bytes} bytes)",
                    )

                extracted = tf.extractfile(m)
                files[rel] = extracted.read() if extracted is not None else b""

        return files

    def fetch_artifact(self, source_id: str, version: str, detail: dict = None) -> dict:
        """Download the commit tarball and return the skill's files as {path: bytes}.

        Uses the pinned SHA from detail (SkillMetadata.raw_detail) when available;
        otherwise re-resolves the repo's current default-branch HEAD. A _github.json
        provenance file is added for reproducibility (analogue of ClawHub's
        _detail.json). Never executes downloaded content.
        """
        owner, repo, skill_dir = self._parse_source_id(source_id)
        detail = detail or {}
        sha = detail.get("sha")
        if not sha:
            _, sha = self._resolve_head(owner, repo)

        tar_bytes = self._download_tarball(owner, repo, sha)
        files = self._extract_skill_subtree(tar_bytes, skill_dir)

        if not files:
            logger.warning("No files extracted for %s (skill_dir=%r @ %s)", source_id, skill_dir, sha[:12])

        skill_path = detail.get("skill_path") or (
            posixpath.join(skill_dir, SKILL_MARKER) if skill_dir else SKILL_MARKER
        )
        # Provenance is deliberately STABLE (no commit SHA): the artifact hash is computed
        # over the returned files, so embedding the repo's HEAD SHA here would change the
        # hash on every repo commit even when the skill's own files are unchanged, turning
        # ordinary repo churn into false "mutation" rows. The commit SHA is recorded
        # authoritatively in the DB `revision` column (SkillMetadata.revision) instead, and
        # the artifact_uri ties the stored bytes back to that row.
        files["_github.json"] = json.dumps(
            {
                "owner": owner,
                "repo": repo,
                "skill_dir": skill_dir,
                "skill_path": skill_path,
            },
            indent=2, sort_keys=True,
        ).encode("utf-8")
        return files

    def capture_metadata(self, files: dict) -> dict:
        """Flag a captured skill that crossed a near-cap WARNING threshold.

        Returns {} for normal skills (no metadata noise). When a warning fires, returns
        capture_status='near_limit' plus the specific warnings and observed sizes, which
        the pipeline merges into the skill's persisted metadata. The tarball size comes
        from the cached tarball this skill was extracted from.
        """
        total = sum(len(v) for v in files.values())
        count = len(files)
        max_file = max((len(v) for v in files.values()), default=0)
        tarball = len(self._tar_cache_bytes) if self._tar_cache_bytes else 0

        warnings = []
        if max_file > WARN_FILE_BYTES:
            warnings.append("per_file")
        if total > WARN_TOTAL_UNCOMPRESSED:
            warnings.append("total_uncompressed")
        if count > WARN_FILES:
            warnings.append("file_count")
        if tarball > WARN_TARBALL_BYTES:
            warnings.append("tarball")
        if not warnings:
            return {}

        return {
            "capture_status": "near_limit",
            "capture_warnings": warnings,
            "observed_bytes": total,
            "observed_files": count,
            "observed_max_file_bytes": max_file,
            "observed_tarball_bytes": tarball,
        }
