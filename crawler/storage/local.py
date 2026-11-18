"""Local filesystem artifact storage.

Artifacts are written under ARTIFACT_ROOT (default: ./artifacts) using the
path layout:
    with artifact_hash    → {root}/{source}/{skill_id}/{version}/{hash[:12]}/{filename}
    without artifact_hash → {root}/{source}/{skill_id}/{version}/{filename}   (legacy)
Returned URIs are absolute filesystem paths.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

from storage.base import ARTIFACT_HASH_SEGMENT_LEN, ArtifactStore

load_dotenv()


class LocalArtifactStore(ArtifactStore):
    """Stores skill artifacts on the local filesystem."""

    def __init__(self, root: str = None):
        """Resolve the storage root from the argument or ARTIFACT_ROOT env var."""
        raw = root or os.environ.get("ARTIFACT_ROOT", "./artifacts")
        self.root = Path(raw).resolve()

    def _dest_dir(self, source: str, skill_id: str, version: str, artifact_hash: str = None) -> Path:
        """Build the destination directory, inserting a {hash[:12]} segment when given."""
        dest_dir = self.root / source / skill_id / version
        if artifact_hash:
            dest_dir = dest_dir / artifact_hash[:ARTIFACT_HASH_SEGMENT_LEN]
        return dest_dir

    def save(self, source: str, skill_id: str, version: str, content: bytes, filename: str, artifact_hash: str = None) -> str:
        """Write artifact bytes to the destination directory and return the absolute path.

        With artifact_hash the path includes a {hash[:12]} segment (see module docstring).
        Creates intermediate directories as needed.
        Raises ValueError if filename resolves outside the destination directory.
        """
        dest_dir = self._dest_dir(source, skill_id, version, artifact_hash)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = (dest_dir / filename).resolve()
        try:
            dest.relative_to(dest_dir.resolve())
        except ValueError:
            raise ValueError(f"Refusing to write outside artifact directory: {filename!r}")
        dest.write_bytes(content)
        return str(dest)

    def save_many(self, source: str, skill_id: str, version: str, files: dict, artifact_hash: str = None) -> str:
        """Write all files to the destination directory and return the directory URI (trailing slash).

        files is a {relative_path: bytes} mapping. Subdirectory structure within
        each path is created automatically before writing. With artifact_hash the
        directory includes a {hash[:12]} segment (see module docstring).
        Raises ValueError if any path resolves outside the destination directory (zip-slip guard).
        """
        dest_dir = self._dest_dir(source, skill_id, version, artifact_hash)
        dest_dir.mkdir(parents=True, exist_ok=True)
        resolved_dir = dest_dir.resolve()
        for relative_path, content in files.items():
            file_path = (dest_dir / relative_path).resolve()
            try:
                file_path.relative_to(resolved_dir)
            except ValueError:
                raise ValueError(f"Refusing to write outside artifact directory: {relative_path!r}")
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(content)
        return str(dest_dir) + "/"

    def exists(self, uri: str) -> bool:
        """Return True if the path exists on disk."""
        return Path(uri).exists()
