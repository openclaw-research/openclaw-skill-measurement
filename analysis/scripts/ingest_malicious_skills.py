"""Ingest confirmed malicious skills from the openclaw/skills GitHub archive into S3 and the DB.

These are the 8 IOC skills confirmed malicious by Snyk/InvariantLabs researchers
(arxiv:2605.28588, February 2026) that are preserved in the openclaw/skills GitHub
archive even though they were removed from the live ClawHub marketplace.

What this script does:
    1. Fetches each malicious skill directory from the openclaw/skills GitHub archive
       via the GitHub Contents API (no cloning required).
    2. Computes artifact_hash the same way the crawler does (SHA-256 over sorted
       filename+content pairs, excluding _detail.json).
    3. Uploads files to S3 under source='snyk-toxicskills' using the same
       hash-segmented layout as the crawler.
    4. Upserts a row into the skills table (same schema as crawler-produced rows).
    5. Inserts a row into the ground_truth_labels table for each ingested skill.

The ground_truth_labels table is created by this script if it does not exist.
All other tables (skills, crawl_runs) are crawler-owned and already exist.

Usage (run from openclaw-skill-analysis repo root, with SSH tunnel running):
    python scripts/ingest_malicious_skills.py --dry-run
    python scripts/ingest_malicious_skills.py

S3 access requires AWS credentials (run from the VM where the IAM role is active):
    python scripts/ingest_malicious_skills.py

Environment variables (from .env):
    DATABASE_URL       PostgreSQL connection string
    S3_BUCKET          S3 bucket name (default: openclaw-skill-artifacts)
    AWS_REGION         AWS region (default: us-east-1)

Ground truth label fields:
    label              'malicious'
    label_source       'snyk-toxicskills-ioc'
    confidence         'confirmed' (human-verified by named researchers)
    attack_types       list of known attack patterns for each skill
    notes              citation and evidence summary
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import requests
from dotenv import load_dotenv
from sqlalchemy import text

# Make the project root importable when run from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import get_settings
from db.session import build_engine, build_session_factory

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Confirmed malicious skills — IOC list from Snyk/InvariantLabs
# arxiv:2605.28588 section 4.2 "Live Threats: Malicious Skills Still Available"
# Human-confirmed by named researchers Luca Beurer-Kellner et al., February 2026.
# ---------------------------------------------------------------------------

MALICIOUS_SKILLS = [
    {
        "author": "snyk-labs",
        "slug": "vercel-skill",
        "github_path": ".agents/skills/vercel",
        "attack_types": ["data_exfiltration", "prompt_injection", "social_engineering"],
        "notes": (
            "Fake Vercel skill. Exfiltrates host uname -a to pastebin.com via SKILL.md "
            "prompt injection. PoC created by Snyk Labs. "
            "Confirmed malicious by Snyk researchers (arxiv:2605.28588, "
            "snyk-labs/toxicskills-goof)."
        ),
    },
    {
        "author": "snyk-labs",
        "slug": "google-skill",
        "github_path": ".agents/skills/google",
        "attack_types": ["prompt_injection", "credential_theft"],
        "notes": (
            "Fake Google skill from aztr0nutzs/NET_NiNjA.v1.2. "
            "Confirmed malicious by Snyk researchers (arxiv:2605.28588, "
            "snyk-labs/toxicskills-goof)."
        ),
    },
]

# GitHub archive base URL — public, no auth required for public repos
GITHUB_API_BASE = "https://api.github.com"
GITHUB_REPO = "snyk-labs/toxicskills-goof"
GITHUB_BRANCH = "main"

# S3 layout constants (must match crawler)
ARTIFACT_HASH_SEGMENT_LEN = 12
SOURCE_NAME = "snyk-toxicskills"


# ---------------------------------------------------------------------------
# GitHub fetching
# ---------------------------------------------------------------------------


def fetch_skill_files(author: str, slug: str, session: requests.Session, github_path: str | None = None) -> dict[str, bytes]:
    dir_path = github_path if github_path else f"skills/{author}/{slug}"
    url = f"{GITHUB_API_BASE}/repos/{GITHUB_REPO}/contents/{dir_path}"
    params = {"ref": GITHUB_BRANCH}

    logger.info("Fetching skill directory: %s", dir_path)
    response = session.get(url, params=params, timeout=15)
    response.raise_for_status()

    entries = response.json()
    if not isinstance(entries, list):
        raise ValueError(f"Expected a directory listing for {dir_path}, got: {type(entries)}")

    files: dict[str, bytes] = {}
    for entry in entries:
        if entry["type"] != "file":
            continue
        file_name = entry["name"]
        download_url = entry["download_url"]
        logger.debug("Fetching file: %s", file_name)
        file_resp = session.get(download_url, timeout=15)
        file_resp.raise_for_status()
        files[file_name] = file_resp.content
        time.sleep(0.1)  # gentle rate limiting

    if not files:
        raise ValueError(f"No files found in {dir_path}")

    logger.info("Fetched %d files for %s/%s", len(files), author, slug)
    return files


# ---------------------------------------------------------------------------
# Hashing (matches pipeline.py compute_artifact_hash)
# ---------------------------------------------------------------------------


HASH_EXCLUDED_FILES = frozenset({"_detail.json"})


def compute_artifact_hash(files: dict[str, bytes]) -> str:
    """SHA-256 over sorted (filename + content) pairs, excluding _detail.json.

    Identical logic to pipeline.py compute_artifact_hash() with
    exclude=frozenset({'_detail.json'}).
    """
    h = hashlib.sha256()
    for name in sorted(files.keys()):
        if name in HASH_EXCLUDED_FILES:
            continue
        h.update(name.encode())
        h.update(files[name])
    return h.hexdigest()


# ---------------------------------------------------------------------------
# S3 upload (matches storage/s3.py save_many)
# ---------------------------------------------------------------------------


def upload_to_s3(
    client,
    bucket: str,
    source: str,
    skill_id: str,
    version: str,
    files: dict[str, bytes],
    artifact_hash: str,
) -> str:
    """Upload skill files to S3 under the hash-segmented prefix.

    Key layout: {source}/{skill_id}/{version}/{hash[:12]}/{filename}
    Returns the s3:// directory URI (with trailing slash).
    """
    hash_segment = artifact_hash[:ARTIFACT_HASH_SEGMENT_LEN]
    prefix = f"{source}/{skill_id}/{version}/{hash_segment}/"

    for relative_path, content in files.items():
        key = prefix + relative_path
        client.put_object(Bucket=bucket, Key=key, Body=content)
        logger.debug("Uploaded: s3://%s/%s", bucket, key)

    uri = f"s3://{bucket}/{prefix}"
    logger.info("Uploaded artifact directory: %s", uri)
    return uri


# ---------------------------------------------------------------------------
# DB operations
# ---------------------------------------------------------------------------


def ensure_ground_truth_table(conn) -> None:
    """Create ground_truth_labels table if it does not exist."""
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ground_truth_labels (
            id              BIGSERIAL PRIMARY KEY,
            skill_id        BIGINT REFERENCES skills(id) ON DELETE CASCADE,
            source_id       TEXT NOT NULL,
            source          TEXT NOT NULL,
            label           TEXT NOT NULL,
            label_source    TEXT NOT NULL,
            confidence      TEXT NOT NULL,
            attack_types    TEXT[],
            notes           TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (source_id, source, label_source)
        )
    """))
    conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_ground_truth_labels_skill_id
        ON ground_truth_labels (skill_id)
    """))
    conn.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_ground_truth_labels_label
        ON ground_truth_labels (label)
    """))
    logger.info("ground_truth_labels table ready")


def upsert_skill(conn, skill_data: dict[str, Any], crawl_run_id: int) -> int:
    """Insert or update a skills row. Returns the skill id."""
    now = datetime.now(timezone.utc)

    # Check if this exact (source, source_id, version, artifact_hash) exists
    existing = conn.execute(text("""
        SELECT id FROM skills
        WHERE source = :source
          AND source_id = :source_id
          AND version = :version
          AND artifact_hash = :artifact_hash
        LIMIT 1
    """), {
        "source": skill_data["source"],
        "source_id": skill_data["source_id"],
        "version": skill_data["version"],
        "artifact_hash": skill_data["artifact_hash"],
    }).fetchone()

    if existing:
        conn.execute(text("""
            UPDATE skills SET
                artifact_uri       = :artifact_uri,
                last_crawl_run_id  = :crawl_run_id,
                last_seen_at       = :now
            WHERE id = :id
        """), {
            "artifact_uri": skill_data["artifact_uri"],
            "crawl_run_id": crawl_run_id,
            "now": now,
            "id": existing.id,
        })
        logger.info("Updated existing skills row id=%d for %s/%s",
                    existing.id, skill_data["source_id"], skill_data["version"])
        return existing.id

    result = conn.execute(text("""
        INSERT INTO skills (
            source, source_id, source_url, name, version,
            description, author, artifact_uri, artifact_hash,
            first_crawl_run_id, last_crawl_run_id,
            first_seen_at, last_seen_at, metadata
        ) VALUES (
            :source, :source_id, :source_url, :name, :version,
            :description, :author, :artifact_uri, :artifact_hash,
            :crawl_run_id, :crawl_run_id,
            :now, :now, :metadata
        )
        RETURNING id
    """), {
        **skill_data,
        "crawl_run_id": crawl_run_id,
        "now": now,
        "metadata": json.dumps(skill_data.get("metadata_", {})),
    })
    skill_id = result.fetchone().id
    logger.info("Inserted new skills row id=%d for %s/%s",
                skill_id, skill_data["source_id"], skill_data["version"])
    return skill_id


def upsert_ground_truth(conn, skill_id: int, source_id: str, attack_types: list[str], notes: str) -> None:
    """Insert or update a ground_truth_labels row."""
    conn.execute(text("""
        INSERT INTO ground_truth_labels (
            skill_id, source_id, source, label, label_source,
            confidence, attack_types, notes
        ) VALUES (
            :skill_id, :source_id, :source, :label, :label_source,
            :confidence, :attack_types, :notes
        )
        ON CONFLICT (source_id, source, label_source)
        DO UPDATE SET
            skill_id     = EXCLUDED.skill_id,
            attack_types = EXCLUDED.attack_types,
            notes        = EXCLUDED.notes
    """), {
        "skill_id": skill_id,
        "source_id": source_id,
        "source": SOURCE_NAME,
        "label": "malicious",
        "label_source": "snyk-toxicskills-ioc",
        "confidence": "confirmed",
        "attack_types": attack_types,
        "notes": notes,
    })
    logger.info("Upserted ground_truth_labels for source_id=%s", source_id)


def create_crawl_run(conn) -> int:
    """Create a crawl_runs row for this ingestion and return its id."""
    now = datetime.now(timezone.utc)
    result = conn.execute(text("""
        INSERT INTO crawl_runs (source, started_at, status)
        VALUES (:source, :now, 'running')
        RETURNING id
    """), {"source": SOURCE_NAME, "now": now})
    run_id = result.fetchone().id
    logger.info("Created crawl_run id=%d for source=%s", run_id, SOURCE_NAME)
    return run_id


def finish_crawl_run(conn, run_id: int, stats: dict[str, Any]) -> None:
    """Mark the crawl_run as success or partial_success."""
    failures = stats.get("failed", 0)
    total = stats.get("total", 0)
    status = "success"
    if total == 0 or (failures / max(total, 1)) >= 0.05:
        status = "partial_success" if failures > 0 else "success"
    if failures == total and total > 0:
        status = "failed"

    conn.execute(text("""
        UPDATE crawl_runs SET
            status      = :status,
            finished_at = :now,
            stats       = :stats
        WHERE id = :id
    """), {
        "status": status,
        "now": datetime.now(timezone.utc),
        "stats": json.dumps(stats),
        "id": run_id,
    })
    logger.info("Finished crawl_run id=%d status=%s stats=%s", run_id, status, stats)


# ---------------------------------------------------------------------------
# Main ingestion logic
# ---------------------------------------------------------------------------


def ingest_skill(
    skill_def: dict[str, Any],
    gh_session: requests.Session,
    s3_client,
    s3_bucket: str,
    db_conn,
    crawl_run_id: int,
    dry_run: bool,
) -> bool:
    """Fetch, upload, and register one malicious skill. Returns True on success."""
    author = skill_def["author"]
    slug = skill_def["slug"]
    attack_types = skill_def["attack_types"]
    notes = skill_def["notes"]

    logger.info("--- Processing %s/%s ---", author, slug)

    try:
        files = fetch_skill_files(author, slug, gh_session, skill_def.get("github_path"))
    except requests.HTTPError as exc:
        if exc.response.status_code == 404:
            logger.warning("Skill %s/%s not found in GitHub archive (404) — may have been removed",
                           author, slug)
        else:
            logger.error("HTTP error fetching %s/%s: %s", author, slug, exc)
        return False
    except Exception as exc:
        logger.error("Error fetching %s/%s: %s", author, slug, exc)
        return False

    artifact_hash = compute_artifact_hash(files)
    version = "1.0.0"  # ClawHub IOC skills used a single version; default to 1.0.0

    # Try to extract version from _meta.json if present
    if "_meta.json" in files:
        try:
            meta = json.loads(files["_meta.json"].decode("utf-8", errors="ignore"))
            version = meta.get("version") or version
        except Exception:
            pass

    logger.info("artifact_hash=%s files=%d version=%s", artifact_hash[:16], len(files), version)

    if dry_run:
        logger.info("[dry-run] Would upload %d files for %s/%s (hash=%s)",
                    len(files), author, slug, artifact_hash[:16])
        logger.info("[dry-run] Would insert skills row: source=%s source_id=%s version=%s",
                    SOURCE_NAME, slug, version)
        logger.info("[dry-run] Would insert ground_truth_labels row: label=malicious confidence=confirmed")
        return True

    # Upload to S3
    try:
        artifact_uri = upload_to_s3(
            client=s3_client,
            bucket=s3_bucket,
            source=SOURCE_NAME,
            skill_id=slug,
            version=version,
            files=files,
            artifact_hash=artifact_hash,
        )
    except Exception as exc:
        logger.error("S3 upload failed for %s/%s: %s", author, slug, exc)
        return False

    # Upsert skills row
    skill_data = {
        "source": SOURCE_NAME,
        "source_id": slug,
        "source_url": f"https://github.com/{GITHUB_REPO}/tree/{GITHUB_BRANCH}/skills/{author}/{slug}",
        "name": slug,
        "version": version,
        "description": f"Confirmed malicious skill from {author} (Snyk ToxicSkills IOC)",
        "author": author,
        "artifact_uri": artifact_uri,
        "artifact_hash": artifact_hash,
        "metadata_": {
            "original_author": author,
            "ground_truth_label": "malicious",
            "label_source": "snyk-toxicskills-ioc",
            "attack_types": attack_types,
            "github_archive_path": f"skills/{author}/{slug}",
        },
    }

    try:
        skill_id = upsert_skill(db_conn, skill_data, crawl_run_id)
        upsert_ground_truth(db_conn, skill_id, slug, attack_types, notes)
        db_conn.commit()
    except Exception as exc:
        logger.error("DB error for %s/%s: %s", author, slug, exc)
        db_conn.rollback()
        return False

    logger.info("Successfully ingested %s/%s → skills.id=%d artifact_uri=%s",
                author, slug, skill_id, artifact_uri)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest confirmed malicious skills from the openclaw/skills GitHub archive "
            "into S3 and the DB as source='snyk-toxicskills' with ground truth labels."
        )
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch from GitHub and log what would be done, but make no S3 or DB writes",
    )
    parser.add_argument(
        "--slug", default=None,
        help="Ingest only this specific slug (default: all 8 IOC skills)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    settings = get_settings()
    engine = build_engine(settings)
    session_factory = build_session_factory(engine)

    # Filter to a specific slug if requested
    skills_to_ingest = MALICIOUS_SKILLS
    if args.slug:
        skills_to_ingest = [s for s in MALICIOUS_SKILLS if s["slug"] == args.slug]
        if not skills_to_ingest:
            print(f"Unknown slug '{args.slug}'. Available: {[s['slug'] for s in MALICIOUS_SKILLS]}",
                  file=sys.stderr)
            return 1

    # GitHub session
    gh_session = requests.Session()
    gh_session.headers["User-Agent"] = "openclaw-skill-analysis/0.1"
    gh_session.headers["Accept"] = "application/vnd.github+json"

    # S3 client (only needed for non-dry-run)
    s3_client = None
    if not args.dry_run:
        s3_client = boto3.client("s3", region_name=settings.aws_region)

    succeeded = 0
    failed = 0

    with session_factory() as session:
        conn = session.connection()

        # Ensure ground_truth_labels table exists
        ensure_ground_truth_table(conn)
        conn.commit()

        # Create a crawl_run row
        if not args.dry_run:
            crawl_run_id = create_crawl_run(conn)
            conn.commit()
        else:
            crawl_run_id = -1
            logger.info("[dry-run] Skipping crawl_run creation")

        for skill_def in skills_to_ingest:
            ok = ingest_skill(
                skill_def=skill_def,
                gh_session=gh_session,
                s3_client=s3_client,
                s3_bucket=settings.s3_bucket,
                db_conn=conn,
                crawl_run_id=crawl_run_id,
                dry_run=args.dry_run,
            )
            if ok:
                succeeded += 1
            else:
                failed += 1

        if not args.dry_run:
            stats = {
                "total": len(skills_to_ingest),
                "succeeded": succeeded,
                "failed": failed,
                "source": SOURCE_NAME,
                "label": "malicious",
                "label_source": "snyk-toxicskills-ioc",
            }
            finish_crawl_run(conn, crawl_run_id, stats)
            conn.commit()

    print(f"\nIngestion {'[DRY RUN] ' if args.dry_run else ''}complete:")
    print(f"  Succeeded: {succeeded}/{len(skills_to_ingest)}")
    print(f"  Failed:    {failed}/{len(skills_to_ingest)}")
    if not args.dry_run and succeeded > 0:
        print(f"\nNext steps:")
        print(f"  1. Run static analysis:  python cli.py analyze-static")
        print(f"     (picks up new source='snyk-toxicskills' skills automatically)")
        print(f"  2. Query ground truth:")
        print(f"     SELECT s.source_id, ar.risk_level, g.label")
        print(f"     FROM ground_truth_labels g")
        print(f"     JOIN skills s ON g.skill_id = s.id")
        print(f"     JOIN analysis_results ar ON ar.skill_id = s.id")
        print(f"     WHERE g.label_source = 'snyk-toxicskills-ioc';")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())