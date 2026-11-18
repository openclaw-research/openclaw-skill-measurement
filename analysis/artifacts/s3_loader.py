from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import boto3

# The crawler stores artifacts in two coexisting S3 layouts:
#   legacy flat:    {source}/{skill_id}/{version}/{files...}
#   hash-segmented: {source}/{skill_id}/{version}/{artifact_hash[:12]}/{files...}
# A legacy flat artifact_uri is therefore a string prefix of every sibling
# hash-segmented snapshot stored under the same version. Materialization must
# not recurse into those siblings or every file is downloaded (and analyzed)
# twice. Matches the crawler's ARTIFACT_HASH_SEGMENT_LEN = 12.
HASH_SEGMENT_RE = re.compile(r"^[0-9a-f]{12}$")


@dataclass(frozen=True)
class S3DownloadResult:
    source_uri: str
    root_path: Path
    object_count: int
    bytes_downloaded: int


class S3ArtifactLoader:
    def __init__(self, bucket_name: str, region_name: str, client=None):
        self.bucket_name = bucket_name
        self.region_name = region_name
        self.client = client or boto3.client("s3", region_name=region_name)

    def download_prefix(self, artifact_uri: str, destination: Path) -> S3DownloadResult:
        bucket, prefix = parse_s3_uri(artifact_uri)
        if bucket != self.bucket_name:
            raise ValueError(
                f"Artifact bucket {bucket!r} does not match configured bucket {self.bucket_name!r}."
            )

        listing_prefix = prefix
        destination.mkdir(parents=True, exist_ok=True)
        destination_root = destination.resolve()

        # A hash-segmented URI is already scoped to exactly one snapshot; a
        # legacy flat URI must exclude sibling snapshot subtrees (see
        # HASH_SEGMENT_RE) or their files get materialized alongside the
        # flat copy and every indicator is counted twice.
        exclude_hash_subdirs = not is_hash_segmented_prefix(prefix)

        object_count = 0
        bytes_downloaded = 0
        paginator = self.client.get_paginator("list_objects_v2")

        # Collect all keys first to identify zero-byte directory markers
        all_objects = []
        all_keys = set()
        for page in paginator.paginate(Bucket=bucket, Prefix=listing_prefix):
            for obj in page.get("Contents", []):
                all_objects.append(obj)
                all_keys.add(obj["Key"])

        # A zero-byte key is a directory marker if other keys start with key + "/"
        def is_directory_marker(key: str, size: int) -> bool:
            if size != 0:
                return False
            prefix_slash = key + "/"
            return any(k.startswith(prefix_slash) for k in all_keys)

        for obj in all_objects:
            key = obj["Key"]
            if key.endswith("/"):
                continue
            relative_key = relative_key_for_artifact(prefix, key)
            if relative_key is None:
                continue
            if exclude_hash_subdirs and is_sibling_snapshot_key(relative_key):
                continue

            target_path = safe_destination_path(destination_root, relative_key)

            if is_directory_marker(key, int(obj.get("Size") or 0)):
                continue

            # If any parent component is a file (e.g. 'data' downloaded
            # before 'data/config.json'), remove it so mkdir can proceed
            for parent in target_path.parents:
                if parent == Path(target_path.anchor):
                    break
                if parent.is_file():
                    parent.unlink()
                    break
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if target_path.is_dir():
                # S3 key conflicts with existing directory — skip
                continue
            self.client.download_file(bucket, key, str(target_path))
            object_count += 1
            bytes_downloaded += int(obj.get("Size") or 0)

        if object_count == 0:
            raise FileNotFoundError(f"No S3 objects found under {artifact_uri}.")

        return S3DownloadResult(
            source_uri=artifact_uri,
            root_path=destination_root,
            object_count=object_count,
            bytes_downloaded=bytes_downloaded,
        )


def is_hash_segmented_prefix(prefix: str) -> bool:
    """True when the artifact prefix's last segment is a 12-hex hash segment."""
    last_segment = PurePosixPath(prefix.rstrip("/")).name
    return bool(HASH_SEGMENT_RE.match(last_segment))


def is_sibling_snapshot_key(relative_key: str) -> bool:
    """True when a key relative to a flat prefix lives inside a {hash12}/ subtree."""
    first_segment = relative_key.split("/", 1)[0]
    return "/" in relative_key and bool(HASH_SEGMENT_RE.match(first_segment))


def parse_s3_uri(artifact_uri: str) -> tuple[str, str]:
    parsed = urlparse(artifact_uri)
    if parsed.scheme != "s3" or not parsed.netloc:
        raise ValueError(f"Expected an s3:// URI, got {artifact_uri!r}.")

    return parsed.netloc, parsed.path.lstrip("/")


def relative_key_for_artifact(prefix: str, key: str) -> str | None:
    if not prefix:
        return key

    if key == prefix:
        return PurePosixPath(key).name

    prefix_with_slash = prefix if prefix.endswith("/") else f"{prefix}/"
    if key.startswith(prefix_with_slash):
        return key[len(prefix_with_slash) :]

    return None


def safe_destination_path(root: Path, relative_key: str) -> Path:
    relative_path = PurePosixPath(relative_key)
    if relative_path.is_absolute():
        raise ValueError(f"S3 key resolves to an absolute path: {relative_key!r}")
    if any(part in {"", ".", ".."} for part in relative_path.parts):
        raise ValueError(f"S3 key contains unsafe path segments: {relative_key!r}")

    target_path = root.joinpath(*relative_path.parts).resolve()
    if not target_path.is_relative_to(root):
        raise ValueError(f"S3 key would escape the destination directory: {relative_key!r}")

    return target_path
