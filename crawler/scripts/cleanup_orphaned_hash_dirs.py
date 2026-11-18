"""S3 cleanup for hash-segmented artifact prefixes orphaned by the hash migration.

After scripts/migrate_recompute_artifact_hash.py collapses the spurious
verify-crawl duplicate rows, their S3 objects — full artifact copies under
.../{version}/{hash12}/ whose only unique content was a volatile
_detail.json snapshot — are no longer referenced by any skills row.

This script is DB-driven, never parses ownership out of key strings, and
NEVER touches legacy flat-level keys:
  1. For every (source, source_id, version) group in `skills`, it lists the
     group's version prefix with Delimiter='/' and takes only the immediate
     {12-hex}/ CommonPrefixes — i.e. hash-segmented snapshot directories.
  2. A snapshot directory is ORPHANED only if its exact URI is not the
     artifact_uri of ANY surviving row (bucket-wide, not just this group's
     rows) AND its 12-hex segment does not prefix-match any surviving row's
     artifact_hash for the same group (belt-and-braces against rows whose
     hash was recomputed while their URI kept the old segment).

Modes:
  default          write a manifest (logs/orphaned_hash_dirs_manifest_<ts>.tsv)
                   listing every orphaned prefix with object counts/bytes.
                   READ-ONLY — nothing is deleted.
  --delete --manifest <path>
                   delete the objects under each prefix in a previously
                   reviewed manifest. Each prefix is RE-VALIDATED against the
                   live DB immediately before deletion; anything no longer
                   orphaned is skipped and reported. Do not run this mode
                   until the DB migration and analyzer fix are validated and
                   deletion has been explicitly approved.

Usage:
    python3 scripts/cleanup_orphaned_hash_dirs.py                      # manifest only
    python3 scripts/cleanup_orphaned_hash_dirs.py --source clawhub
    python3 scripts/cleanup_orphaned_hash_dirs.py --delete --manifest logs/orphaned_hash_dirs_manifest_x.tsv
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

import boto3
from sqlalchemy import text

from db.session import engine
from storage.base import ARTIFACT_HASH_SEGMENT_LEN

HASH_SEGMENT_RE = re.compile(r"^[0-9a-f]{%d}$" % ARTIFACT_HASH_SEGMENT_LEN)


def load_groups_and_references(source: str | None):
    """Return (groups, live_uris) from the skills table.

    groups:    {(source, source_id, version): [artifact_hash, ...]} for rows
               that still exist (any layout).
    live_uris: set of every surviving artifact_uri (normalized with trailing
               slash) — the authoritative "do not touch" set.
    """
    query = """
        SELECT source, source_id, version, artifact_hash, artifact_uri
        FROM skills WHERE artifact_uri IS NOT NULL
    """
    params = {}
    if source:
        query += " AND source = :source"
        params["source"] = source

    groups, live_uris = {}, set()
    with engine.connect() as conn:
        for row in conn.execute(text(query), params).mappings():
            key = (row["source"], row["source_id"], row["version"])
            groups.setdefault(key, []).append(row["artifact_hash"])
            uri = row["artifact_uri"]
            live_uris.add(uri if uri.endswith("/") else uri + "/")
    return groups, live_uris


def list_hash_dir_prefixes(s3_client, bucket: str, version_prefix: str) -> list[str]:
    """Immediate {12-hex}/ subdirectories of a version prefix (key form)."""
    found = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=version_prefix, Delimiter="/"):
        for common in page.get("CommonPrefixes", []):
            sub = common["Prefix"]
            segment = sub[len(version_prefix):].rstrip("/")
            if HASH_SEGMENT_RE.match(segment):
                found.append(sub)
    return found


def is_orphaned(prefix_key: str, bucket: str, group_hashes: list, live_uris: set) -> bool:
    uri = f"s3://{bucket}/{prefix_key}"
    if uri in live_uris:
        return False
    segment = prefix_key.rstrip("/").rsplit("/", 1)[-1]
    # Belt-and-braces: keep any dir whose segment matches a surviving row's
    # hash for this group, even if that row's URI points elsewhere.
    if any(h and h.startswith(segment) for h in group_hashes):
        return False
    return True


def measure_prefix(s3_client, bucket: str, prefix_key: str):
    """Return (object_count, total_bytes, keys) under a prefix."""
    count, total, keys = 0, 0, []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix_key):
        for obj in page.get("Contents", []):
            count += 1
            total += int(obj.get("Size") or 0)
            keys.append(obj["Key"])
    return count, total, keys


def build_manifest(s3_client, bucket: str, source: str | None, manifest_path: Path) -> None:
    groups, live_uris = load_groups_and_references(source)
    print(f"[manifest] {len(groups)} skill-version groups, {len(live_uris)} live artifact URIs")

    orphaned_count, orphaned_bytes = 0, 0
    started = time.monotonic()
    with open(manifest_path, "w") as manifest:
        manifest.write("prefix_uri\tsource\tsource_id\tversion\tobject_count\ttotal_bytes\n")
        for index, ((src, source_id, version), hashes) in enumerate(sorted(groups.items()), start=1):
            version_prefix = f"{src}/{source_id}/{version}/"
            for sub in list_hash_dir_prefixes(s3_client, bucket, version_prefix):
                if not is_orphaned(sub, bucket, hashes, live_uris):
                    continue
                count, total, _ = measure_prefix(s3_client, bucket, sub)
                orphaned_count += 1
                orphaned_bytes += total
                manifest.write(f"s3://{bucket}/{sub}\t{src}\t{source_id}\t{version}\t{count}\t{total}\n")
            if index % 2000 == 0:
                rate = index / (time.monotonic() - started)
                print(f"[manifest] {index}/{len(groups)} groups ({rate:.0f}/s), "
                      f"orphans so far: {orphaned_count}")

    print(f"[manifest] done: {orphaned_count} orphaned hash-dir prefixes, "
          f"{orphaned_bytes / 1e9:.2f} GB")
    print(f"[manifest] wrote {manifest_path}")
    print("Nothing was deleted. Review the manifest; deletion requires --delete --manifest "
          "and explicit approval.")


def delete_from_manifest(s3_client, bucket: str, manifest_path: Path) -> None:
    groups, live_uris = load_groups_and_references(None)

    deleted_prefixes, deleted_objects, skipped = 0, 0, 0
    with open(manifest_path) as manifest:
        header = manifest.readline()
        if not header.startswith("prefix_uri\t"):
            print("ABORT: not a manifest file produced by this script.")
            sys.exit(1)
        for line in manifest:
            prefix_uri, src, source_id, version, _count, _bytes = line.rstrip("\n").split("\t")
            prefix_key = prefix_uri[len(f"s3://{bucket}/"):]

            # Hard guard: only ever delete inside a {12-hex}/ snapshot dir.
            segment = prefix_key.rstrip("/").rsplit("/", 1)[-1]
            if not HASH_SEGMENT_RE.match(segment):
                print(f"[skip] not a hash-dir prefix, refusing: {prefix_uri}")
                skipped += 1
                continue

            # Re-validate against the live DB right before deleting.
            hashes = groups.get((src, source_id, version), [])
            if not is_orphaned(prefix_key, bucket, hashes, live_uris):
                print(f"[skip] no longer orphaned: {prefix_uri}")
                skipped += 1
                continue

            _, _, keys = measure_prefix(s3_client, bucket, prefix_key)
            for start in range(0, len(keys), 1000):
                batch = keys[start:start + 1000]
                s3_client.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": k} for k in batch], "Quiet": True},
                )
                deleted_objects += len(batch)
            deleted_prefixes += 1
            if deleted_prefixes % 1000 == 0:
                print(f"[delete] {deleted_prefixes} prefixes, {deleted_objects} objects so far")

    print(f"[delete] done: {deleted_prefixes} prefixes ({deleted_objects} objects) deleted, "
          f"{skipped} skipped")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", help="only scan this source (e.g. clawhub)")
    parser.add_argument("--delete", action="store_true",
                        help="delete prefixes listed in --manifest (requires prior approval)")
    parser.add_argument("--manifest", help="manifest file to delete from (required with --delete)")
    args = parser.parse_args()

    bucket = os.environ["S3_BUCKET"]
    region = os.environ.get("AWS_REGION", "us-east-1")
    s3_client = boto3.client("s3", region_name=region)

    if args.delete:
        if not args.manifest:
            print("ABORT: --delete requires --manifest <reviewed manifest file>.")
            sys.exit(1)
        delete_from_manifest(s3_client, bucket, Path(args.manifest))
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report_dir = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "logs"
    report_dir.mkdir(exist_ok=True)
    build_manifest(s3_client, bucket, args.source, report_dir / f"orphaned_hash_dirs_manifest_{timestamp}.tsv")


if __name__ == "__main__":
    main()
