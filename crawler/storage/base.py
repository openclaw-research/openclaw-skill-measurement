"""Abstract interface for artifact storage backends.

Concrete implementations (LocalArtifactStore, S3ArtifactStore) must implement
save(), save_many(), and exists(). The pipeline depends only on this interface,
so backends are interchangeable without any pipeline changes.
"""

from abc import ABC, abstractmethod

# Number of leading artifact-hash hex chars used as an immutable path segment.
# 12 chars (48 bits) is ample to keep distinct artifact snapshots from colliding
# while keeping keys short and readable.
ARTIFACT_HASH_SEGMENT_LEN = 12


class ArtifactStore(ABC):
    """Common interface for storing and checking skill artifacts.

    Path layout for a write:
        with artifact_hash    → {source}/{skill_id}/{version}/{hash[:12]}/{filename}
        without artifact_hash → {source}/{skill_id}/{version}/{filename}   (legacy)

    Passing artifact_hash makes each distinct artifact snapshot land at its own
    immutable path, so a mutated artifact never overwrites the previous bytes.
    The pipeline always passes the hash it already computed. Omitting it
    reproduces the pre-cutover flat layout and exists only so historical tooling
    (e.g. the local→S3 migration script) can keep relocating old artifacts to the
    exact keys their DB rows already point at. Old flat paths and new hash paths
    coexist; callers must always rely on the stored artifact_uri, never rebuild it.
    """

    @abstractmethod
    def save(self, source: str, skill_id: str, version: str, content: bytes, filename: str, artifact_hash: str = None) -> str:
        """Persist artifact bytes and return a URI string.

        If artifact_hash is given, the file is stored under a {hash[:12]} segment.

        The URI format is backend-specific:
            local  → absolute filesystem path
            s3     → s3://{bucket}/{key}
        """

    @abstractmethod
    def save_many(self, source: str, skill_id: str, version: str, files: dict, artifact_hash: str = None) -> str:
        """Persist multiple artifact files and return a directory URI.

        files is a {relative_path: bytes} mapping. All paths are written
        verbatim, including any subdirectory structure they contain. If
        artifact_hash is given, all files are stored under a {hash[:12]} segment.

        The returned URI points to the artifact directory (one level deeper when a
        hash segment is used) and always ends with a trailing slash:
            local  → absolute path with trailing slash
            s3     → s3://{bucket}/{prefix}/ with trailing slash
        """

    @abstractmethod
    def exists(self, uri: str) -> bool:
        """Return True if the artifact at the given URI is already stored."""
