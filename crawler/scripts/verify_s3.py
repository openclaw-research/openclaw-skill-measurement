"""S3 backend smoke test.

Exercises S3ArtifactStore through the application's own storage abstraction:
  - save_many(): uploads a synthetic multi-file artifact and lists the prefix to confirm
  - save():      uploads a single file and checks existence via exists()
  - Cleans up all test objects on completion.

Run from the project root with the virtualenv active:
    python verify_s3.py

Requires S3_BUCKET and AWS_REGION in the environment (or .env file).
"""

import sys
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.WARNING)

from storage.s3 import S3ArtifactStore  # noqa: E402 (must load_dotenv first)

TEST_SOURCE = "_verify_test"
TEST_SKILL = "smoke-test"
TEST_VERSION = "0.0.0"
# Synthetic 64-char hex hash so the smoke test exercises the hash-segmented layout
# that production writes now use.
TEST_HASH = "0123456789abcdef" * 4
TEST_HASH_SEG = TEST_HASH[:12]

MULTI_FILES = {
    "SKILL.md": b"# Smoke test skill\n",
    "scripts/run.py": b"print('ok')\n",
    "_meta.json": b'{"name":"smoke-test"}\n',
}
SINGLE_FILE_NAME = "single.txt"
SINGLE_FILE_CONTENT = b"single file smoke test\n"


def _list_prefix(store: S3ArtifactStore, prefix: str) -> list[str]:
    """Return keys under prefix using list_objects_v2."""
    resp = store._client.list_objects_v2(Bucket=store.bucket, Prefix=prefix)
    return [obj["Key"] for obj in resp.get("Contents", [])]


def _delete_keys(store: S3ArtifactStore, keys: list[str]) -> None:
    if not keys:
        return
    store._client.delete_objects(
        Bucket=store.bucket,
        Delete={"Objects": [{"Key": k} for k in keys]},
    )


def main() -> int:
    store = S3ArtifactStore()
    print(f"Bucket: {store.bucket}  Region: {store.region}")
    failures = []

    # --- save_many ---
    print("\n[1] Testing save_many()...")
    dir_uri = store.save_many(TEST_SOURCE, TEST_SKILL, TEST_VERSION, MULTI_FILES, artifact_hash=TEST_HASH)
    # Objects land under the hash-segmented prefix.
    prefix = f"{TEST_SOURCE}/{TEST_SKILL}/{TEST_VERSION}/{TEST_HASH_SEG}/"
    keys = _list_prefix(store, prefix)
    expected_keys = {prefix + p for p in MULTI_FILES}
    missing = expected_keys - set(keys)
    if missing:
        failures.append(f"save_many: missing objects: {missing}")
        print(f"  FAIL — missing: {missing}")
    elif not dir_uri.endswith("/"):
        failures.append(f"save_many: uri missing trailing slash: {dir_uri}")
        print(f"  FAIL — uri missing trailing slash: {dir_uri}")
    else:
        print(f"  PASS  uri={dir_uri}  objects={len(keys)}")

    # --- save() ---
    print("\n[2] Testing save()...")
    single_uri = store.save(TEST_SOURCE, TEST_SKILL, TEST_VERSION, SINGLE_FILE_CONTENT, SINGLE_FILE_NAME, artifact_hash=TEST_HASH)
    if not store.exists(single_uri):
        failures.append(f"save: exists() returned False for {single_uri}")
        print(f"  FAIL — exists() returned False for {single_uri}")
    elif f"/{TEST_HASH_SEG}/" not in single_uri:
        failures.append(f"save: uri missing hash segment: {single_uri}")
        print(f"  FAIL — uri missing hash segment: {single_uri}")
    else:
        print(f"  PASS  uri={single_uri}")

    # --- cleanup ---
    # List from the top test prefix so cleanup catches everything under any segment.
    print("\n[3] Cleaning up test objects...")
    cleanup_prefix = f"{TEST_SOURCE}/"
    all_keys = _list_prefix(store, cleanup_prefix)
    _delete_keys(store, all_keys)
    remaining = _list_prefix(store, cleanup_prefix)
    if remaining:
        print(f"  WARNING: cleanup left {len(remaining)} objects")
    else:
        print(f"  Deleted {len(all_keys)} objects")

    # --- result ---
    print()
    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        return 1
    print("PASS: S3 backend verified successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
