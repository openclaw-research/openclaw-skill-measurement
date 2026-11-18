"""Base interfaces for skill sources.

Defines the SkillMetadata dataclass (the common data contract between sources
and the pipeline) and the BaseSource ABC that all source implementations extend.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class SkillMetadata:
    """All information the pipeline needs about one discovered skill.

    Fields:
        source_id        Stable unique identifier within the source (e.g. slug or repo path).
        name             Human-readable skill name.
        version          Version string; defaults to 'unversioned' if the source has none.
        revision         Source-specific immutable/semi-immutable pointer (git commit SHA,
                         tag target SHA, branch HEAD SHA, package digest, ...). None for
                         sources that expose only a semantic version (e.g. ClawHub).
                         Tracked for provenance; not part of the uniqueness key.
        source_url       Canonical URL for the skill on its origin platform.
        description      Short description of what the skill does.
        author           Author or maintainer name.
        license          SPDX license identifier (e.g. 'MIT', 'Apache-2.0').
        artifacts        Multi-file artifact map: {relative_path: bytes}. Preferred over
                         artifact_content for sources that produce more than one file.
                         When non-empty, the pipeline uses store.save_many() and hashes
                         all files together. artifact_content / artifact_filename are
                         ignored when artifacts is populated.
        artifact_filename Name to use when storing a single-file artifact.
        artifact_content  Raw bytes for a single-file artifact.
        extra            Source-specific fields that don't fit the standard schema (stored as JSONB).
        raw_detail       Raw API detail response passed through for internal pipeline use.
                         Not persisted to the DB — used to avoid re-fetching detail when
                         the pipeline needs to call fetch_artifact() for a new skill.
    """
    source_id: str
    name: str
    version: str = "unversioned"
    revision: str = None
    source_url: str = None
    description: str = None
    author: str = None
    license: str = None
    artifacts: dict = field(default_factory=dict)
    artifact_filename: str = "skill.md"
    artifact_content: bytes = field(default_factory=bytes)
    extra: dict = field(default_factory=dict)
    raw_detail: dict = field(default=None, compare=False, repr=False)


class CaptureLimitExceeded(Exception):
    """Raised by a source's fetch_artifact() when a hard capture cap is exceeded.

    Signals "this skill was observed but could not be safely captured" — distinct
    from a generic error. The pipeline catches it and records a metadata-only stub
    (capture_status='limit_exceeded') instead of dropping the skill silently, so the
    dataset still notes the skill's existence. No partial artifact is stored.

    Attributes:
        limit:        which cap was hit ('tarball', 'per_file', 'total_uncompressed',
                      'file_count').
        observed:     the observed value (bytes or file count).
        limit_value:  the configured cap that was exceeded.
    """

    def __init__(self, limit: str, observed: int, limit_value: int, detail: str = ""):
        self.limit = limit
        self.observed = observed
        self.limit_value = limit_value
        self.detail = detail
        super().__init__(detail or f"{limit} exceeded: observed {observed} > cap {limit_value}")


class BaseSource(ABC):
    """Abstract base class for all skill sources.

    Subclasses must set source_name (used as the 'source' column value in the DB)
    and implement discover() and fetch_artifact().

    Attributes:
        source_name             The 'source' column value in the DB (e.g. 'clawhub').
        pagination_stopped_early Set True by a source if discovery aborted before
                                 reaching the end of the catalog (e.g. list API failed
                                 after retries). The pipeline reads this to decide
                                 whether a run should be marked 'failed'. Defaults to
                                 False; sources that cannot stop early may leave it as-is.
        hash_excluded_files      Filenames (exact relative paths in the artifact dict)
                                 that compute_artifact_hash() must skip for this source.
                                 Use this for collector-injected provenance files whose
                                 content is VOLATILE (e.g. ClawHub's _detail.json embeds
                                 API counters like downloads/installs/updatedAt that
                                 change between crawls). Excluding them keeps
                                 artifact_hash a pure content identity: re-fetching an
                                 unchanged skill yields the same hash instead of a
                                 spurious "mutation" row. Files listed here are still
                                 stored in the artifact — they just don't define identity.
                                 Provenance files that are deliberately content-stable
                                 (e.g. GitHub's _github.json, which omits the commit SHA)
                                 stay hashed and must NOT be listed.
    """

    source_name: str = ""
    pagination_stopped_early: bool = False
    hash_excluded_files: frozenset = frozenset()

    @abstractmethod
    def discover(self) -> Iterator[SkillMetadata]:
        """Yield SkillMetadata for each discovered skill (metadata stubs, no artifact)."""

    @abstractmethod
    def fetch_artifact(self, source_id: str, version: str, detail: dict = None) -> dict:
        """Download a skill's artifact and return a {relative_path: bytes} mapping.

        Called by the pipeline only when an artifact is actually needed (a new skill,
        or a verify/backfill re-check). The returned dict is hashed and persisted
        verbatim by the pipeline.

        Args:
            source_id: The skill's stable identifier within the source.
            version:   The version to fetch.
            detail:    Optional already-fetched raw detail (SkillMetadata.raw_detail),
                       passed through to avoid a redundant network call. Sources that
                       do not have a separate detail step may ignore it.

        Raises CaptureLimitExceeded if a hard size/count cap is exceeded (the pipeline
        records a stub rather than failing the skill).
        """

    def capture_metadata(self, files: dict) -> dict:
        """Return optional capture annotations for a successfully-fetched artifact.

        Called by the pipeline after fetch_artifact() with the returned {path: bytes}.
        A source may flag a skill that was captured but crossed a "near-cap" warning
        threshold (e.g. capture_status='near_limit' plus observed sizes). The returned
        dict is merged into the skill's persisted metadata. Default: no annotations.
        """
        return {}
