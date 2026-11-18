"""S3-backed artifact storage using boto3.

Reads configuration from environment variables:
    S3_BUCKET   — target bucket name (required)
    AWS_REGION  — AWS region for the bucket (required)

Object keys follow the same layout as local storage:
    with artifact_hash    → {source}/{skill_id}/{version}/{hash[:12]}/{filename}
    without artifact_hash → {source}/{skill_id}/{version}/{filename}   (legacy)

Returned URIs use the standard s3:// scheme:
    s3://{bucket}/{key}
"""

import logging
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

from storage.base import ARTIFACT_HASH_SEGMENT_LEN, ArtifactStore

load_dotenv()

logger = logging.getLogger(__name__)


class S3ArtifactStore(ArtifactStore):
    def __init__(self, bucket: str = None, region: str = None):
        self.bucket = bucket or os.environ["S3_BUCKET"]
        self.region = region or os.environ["AWS_REGION"]
        self._client = boto3.client("s3", region_name=self.region)

    def _key(self, source: str, skill_id: str, version: str, filename: str, artifact_hash: str = None) -> str:
        """Build the S3 object key, mirroring the local directory layout.

        When artifact_hash is given, a {hash[:12]} segment is inserted between the
        version and the filename so each distinct snapshot has an immutable key.
        filename may be "" to build a directory prefix (used by save_many).
        """
        parts = [source, skill_id, version]
        if artifact_hash:
            parts.append(artifact_hash[:ARTIFACT_HASH_SEGMENT_LEN])
        parts.append(filename)
        return "/".join(parts)

    def save(self, source: str, skill_id: str, version: str, content: bytes, filename: str, artifact_hash: str = None) -> str:
        """Upload artifact bytes to S3 and return its s3:// URI."""
        key = self._key(source, skill_id, version, filename, artifact_hash)
        try:
            self._client.put_object(Bucket=self.bucket, Key=key, Body=content)
            uri = f"s3://{self.bucket}/{key}"
            logger.info("Uploaded artifact: %s", uri)
            return uri
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            raise RuntimeError(
                f"S3 upload failed for key '{key}' in bucket '{self.bucket}': {code} — {exc}"
            ) from exc
        except BotoCoreError as exc:
            raise RuntimeError(f"S3 client error uploading '{key}': {exc}") from exc

    def save_many(self, source: str, skill_id: str, version: str, files: dict, artifact_hash: str = None) -> str:
        """Upload all files to S3 under a common prefix and return the s3:// directory URI.

        files is a {relative_path: bytes} mapping. Each entry is uploaded as a
        separate S3 object at {prefix}{relative_path}, where the prefix includes
        the {hash[:12]} segment when artifact_hash is given.
        """
        prefix = self._key(source, skill_id, version, "", artifact_hash)
        try:
            for relative_path, content in files.items():
                key = prefix + relative_path
                self._client.put_object(Bucket=self.bucket, Key=key, Body=content)
                logger.debug("Uploaded: s3://%s/%s", self.bucket, key)
            uri = f"s3://{self.bucket}/{prefix}"
            logger.info("Uploaded artifact directory: %s", uri)
            return uri
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            raise RuntimeError(
                f"S3 upload failed for prefix '{prefix}' in bucket '{self.bucket}': {code} — {exc}"
            ) from exc
        except BotoCoreError as exc:
            raise RuntimeError(f"S3 client error uploading to '{prefix}': {exc}") from exc

    def exists(self, uri: str) -> bool:
        """Return True if the s3:// URI resolves to an existing object."""
        if not uri.startswith("s3://"):
            return False
        without_scheme = uri[5:]
        bucket, _, key = without_scheme.partition("/")
        if not bucket or not key:
            return False
        try:
            self._client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise RuntimeError(
                f"S3 existence check failed for '{uri}': {exc}"
            ) from exc
