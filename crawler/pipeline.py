"""Crawl pipeline orchestration.

run_crawl() — full crawl execution:
    1. Open a DB session and create a crawl_run row.
    2. Iterate over all skills yielded by source.discover() (metadata stubs, no ZIP).
    3. For each skill:
       - If (source, slug, version) already in DB and not --verify-existing:
         touch timestamps on all hash rows, skip artifact download.
       - Otherwise: call source.fetch_artifact(), hash the files, upsert.
         upsert() matches on the 4-tuple (source, slug, version, hash):
         existing hash → updates last_seen_at; new hash → inserts new row.
         Historical hash rows are never deleted (they are mutation evidence).
    4. Collect per-skill errors without aborting the whole run.
    5. Mark the crawl_run as success/failed with a stats summary.

run_backfill() — re-fetch full artifacts for skills already in the DB:
    1. Read existing skill rows for the given source.
    2. For each row, re-download the ZIP artifact and rebuild the artifact directory.
    3. Skip rows whose hash is unchanged (unless force=True).
    4. Update artifact_uri, artifact_hash, last_seen_at in-place (no new rows).

Per-skill errors are captured in stats["error_details"]; they do not raise.
Errors that affect the whole session (e.g. DB connection failure) propagate
after a rollback.

In dry_run mode, discovery and logging proceed normally but no artifacts are
saved and no DB rows are written. run_id is None in the returned dict.
"""

import hashlib
import logging
import time
from datetime import datetime, timezone

from db.models import Skill
from db.repository import CrawlRunRepository, SkillRepository
from db.session import SessionLocal
from sources.base import BaseSource, CaptureLimitExceeded
from storage.base import ArtifactStore

logger = logging.getLogger(__name__)

# Per-skill failure rate at or above this threshold downgrades a run from
# 'success' to 'partial_success'. Below it, individual skill failures are
# considered acceptable noise.
_PARTIAL_SUCCESS_FAILURE_RATE = 0.05


def compute_artifact_hash(files: dict, exclude: frozenset = frozenset()) -> str:
    """Return the deterministic SHA-256 hex digest over a {path: bytes} artifact mapping.

    Hashes sorted (filename + content) pairs, so a multi-file artifact hashes
    identically regardless of dict iteration order. This is the canonical artifact
    identity used for dedup and mutation detection, shared by the crawl and backfill
    paths so the two can never drift.

    exclude (normally the source's hash_excluded_files) names collector-injected
    files with volatile content (e.g. ClawHub's _detail.json) that must not
    perturb identity — they are stored but not hashed. Real skill files are never
    excluded, so genuine content changes still produce a new hash.
    """
    h = hashlib.sha256()
    for name in sorted(files.keys()):
        if name in exclude:
            continue
        h.update(name.encode())
        h.update(files[name])
    return h.hexdigest()


def _compute_run_status(
    total_seen: int,
    failures: list,
    *,
    stopped_early: bool = False,
    discovery_errors: int = 0,
) -> str:
    """Return the crawl run status string based on completion and failure rate.

    failed:          pagination stopped early, process crash, or zero skills attempted
    partial_success: completed end-to-end but >= 5% of attempted skills failed
    success:         completed end-to-end with acceptable per-skill failure rate

    discovery_errors counts per-slug failures that occurred inside discover() (e.g.
    detail-fetch 503/409). They are invisible to the pipeline loop but represent real
    failures and must be included in both the numerator and denominator of the rate.
    """
    total_attempted = total_seen + discovery_errors
    if stopped_early or total_attempted == 0:
        return "failed"
    total_failures = len(failures) + discovery_errors
    if total_failures / total_attempted >= _PARTIAL_SUCCESS_FAILURE_RATE:
        return "partial_success"
    return "success"


def _needs_artifact_fetch(existing, discovered_revision, verify_existing: bool) -> bool:
    """Decide whether to (re)download an artifact for a discovered skill.

    Fetch when:
        - there is no existing row, or
        - verify_existing is set (force re-check), or
        - the existing row is a metadata-only stub (no artifact_hash yet), or
        - the discovered revision differs from the stored one (the source moved).

    Skip (touch timestamps only) when an artifact is already stored at the same
    revision. For sources without a revision concept (e.g. ClawHub, where both
    revisions are None), the comparison is None == None, preserving the original
    version-keyed behaviour exactly.
    """
    if existing is None or verify_existing:
        return True
    if existing.artifact_hash is None:
        return True
    return existing.revision != discovered_revision


def run_crawl(
    source: BaseSource,
    store: ArtifactStore,
    *,
    dry_run: bool = False,
    verify_existing: bool = False,
    metadata_only: bool = False,
) -> dict:
    """Run a full crawl for the given source and artifact store.

    Args:
        source:          A BaseSource implementation that yields SkillMetadata stubs.
                         The source's fetch_artifact() is called only when needed.
        store:           An ArtifactStore implementation (local or S3).
        dry_run:         If True, skip all writes. Useful for validating discovery.
        verify_existing: If True, re-download artifacts for known (source_id, version) pairs
                         and insert a new DB row if the hash has changed. Historical rows
                         with older hashes are preserved as mutation evidence.
                         Recommended to run weekly; see README for details.
        metadata_only:   If True, persist a metadata stub per discovered skill but never
                         download or store its artifact (artifact_uri/artifact_hash stay as
                         whatever an existing row had, else NULL). Useful for fast inventory
                         passes or legally-sensitive sources. Mutually exclusive with
                         verify_existing; dry_run takes precedence over both.

    Returns:
        A dict with:
            run_id:  The CrawlRun PK, or None in dry_run mode.
            stats:   skills_seen, skills_inserted, skills_updated, artifacts_downloaded,
                     artifacts_skipped, failures, elapsed_seconds,
                     and optionally error_details, dry_run=True, metadata_only=True.
    """
    session = SessionLocal()
    start = time.monotonic()
    run = None  # kept outside try so the except block can finalize it on crash

    try:
        crawl_repo = CrawlRunRepository(session)
        skill_repo = SkillRepository(session)

        if dry_run:
            logger.info("Dry-run mode active — no DB or artifact writes will be made")
            run_id = None
        else:
            run = crawl_repo.create(source=source.source_name)
            session.commit()
            run_id = run.id

        skills_seen = 0
        skills_inserted = 0
        skills_updated = 0
        artifacts_downloaded = 0
        artifacts_skipped = 0
        capture_limited = 0   # skills recorded as stubs because a hard cap was exceeded
        near_limit = 0        # skills captured but flagged as near a cap
        failures = []

        for skill in source.discover():
            skills_seen += 1
            try:
                if dry_run:
                    logger.info("[dry-run] %s  v%s  (%s)", skill.name, skill.version, skill.source_id)
                    continue

                # Check whether this (source, slug, version) is already collected.
                existing_version = skill_repo.find_by_version(
                    source.source_name, skill.source_id, skill.version
                )

                if metadata_only:
                    # Persist/refresh a stub only — never fetch or store an artifact.
                    # If a row already exists, refresh it in place (match on its current
                    # hash); otherwise insert a NULL-hash stub.
                    skill_repo.upsert(
                        source=source.source_name,
                        source_id=skill.source_id,
                        source_url=skill.source_url,
                        name=skill.name,
                        version=skill.version,
                        revision=skill.revision,
                        description=skill.description,
                        author=skill.author,
                        license=skill.license,
                        artifact_uri=existing_version.artifact_uri if existing_version else None,
                        artifact_hash=existing_version.artifact_hash if existing_version else None,
                        crawl_run_id=run_id,
                        metadata=skill.extra or None,
                    )
                    session.commit()
                    if existing_version:
                        skills_updated += 1
                    else:
                        skills_inserted += 1
                    artifacts_skipped += 1
                    logger.info("[metadata-only] %s  v%s  (%s)", skill.name, skill.version, skill.source_id)
                    continue

                if existing_version and not _needs_artifact_fetch(
                    existing_version, skill.revision, verify_existing
                ):
                    # Already have this artifact at this revision — update timestamps on
                    # all hash variants, skip the (expensive) download.
                    skill_repo.touch(source.source_name, skill.source_id, skill.version, run_id)
                    session.commit()
                    skills_updated += 1
                    artifacts_skipped += 1
                    if artifacts_skipped % 500 == 0:
                        logger.info("[seen] %d skills skipped so far", artifacts_skipped)
                    continue

                if existing_version and existing_version.revision != skill.revision:
                    logger.info(
                        "[revision-changed] %s  %s -> %s  (re-fetching)",
                        skill.source_id,
                        (existing_version.revision or "none")[:12],
                        (skill.revision or "none")[:12],
                    )

                # Download artifact: new skill, or verify_existing re-checking a known version.
                try:
                    artifacts = source.fetch_artifact(
                        skill.source_id, skill.version, detail=skill.raw_detail
                    )
                except CaptureLimitExceeded as exc:
                    # Observed-but-not-captured: record a metadata-only stub (no partial
                    # artifact) so the skill's existence and the reason are queryable.
                    cap_meta = {
                        "capture_status": "limit_exceeded",
                        "limit_exceeded": exc.limit,
                        "observed_size": exc.observed,
                        "capture_error": str(exc),
                    }
                    skill_repo.upsert(
                        source=source.source_name,
                        source_id=skill.source_id,
                        source_url=skill.source_url,
                        name=skill.name,
                        version=skill.version,
                        revision=skill.revision,
                        description=skill.description,
                        author=skill.author,
                        license=skill.license,
                        artifact_uri=None,
                        artifact_hash=None,
                        crawl_run_id=run_id,
                        metadata={**(skill.extra or {}), **cap_meta},
                    )
                    session.commit()
                    capture_limited += 1
                    if existing_version:
                        skills_updated += 1
                    else:
                        skills_inserted += 1
                    logger.warning("[limit-exceeded] %s  (%s)", skill.source_id, exc)
                    continue

                artifacts_downloaded += 1

                # Optional near-cap warning flags, merged into the persisted metadata.
                cap_meta = source.capture_metadata(artifacts)
                if cap_meta:
                    near_limit += 1
                    logger.warning(
                        "[near-limit] %s  (%s)", skill.source_id, ",".join(cap_meta.get("capture_warnings", []))
                    )
                skill_metadata = {**(skill.extra or {}), **cap_meta} or None

                artifact_hash = compute_artifact_hash(artifacts, exclude=source.hash_excluded_files)

                # Check if this exact hash is already in DB (may differ from existing_version.hash).
                existing_hash = (
                    session.query(Skill)
                    .filter_by(
                        source=source.source_name,
                        source_id=skill.source_id,
                        version=skill.version,
                        artifact_hash=artifact_hash,
                    )
                    .first()
                )

                if existing_hash:
                    # Hash already known — reuse stored URI, no S3 upload needed.
                    artifact_uri = existing_hash.artifact_uri
                else:
                    artifact_uri = store.save_many(
                        source=source.source_name,
                        skill_id=skill.source_id,
                        version=skill.version,
                        files=artifacts,
                        artifact_hash=artifact_hash,
                    )

                # upsert() matches on the 4-tuple (source, source_id, version, artifact_hash):
                #   - existing hash row → updates last_seen_at on that row, other hash rows untouched
                #   - new hash → inserts a new row, preserving historical hash rows
                skill_repo.upsert(
                    source=source.source_name,
                    source_id=skill.source_id,
                    source_url=skill.source_url,
                    name=skill.name,
                    version=skill.version,
                    revision=skill.revision,
                    description=skill.description,
                    author=skill.author,
                    license=skill.license,
                    artifact_uri=artifact_uri,
                    artifact_hash=artifact_hash,
                    crawl_run_id=run_id,
                    metadata=skill_metadata,
                )
                session.commit()

                if existing_hash:
                    skills_updated += 1
                    if verify_existing:
                        logger.debug("[verify-unchanged] %s  v%s", skill.name, skill.version)
                    else:
                        logger.info("[updated] %s  v%s  (%s)", skill.name, skill.version, skill.source_id)
                else:
                    skills_inserted += 1
                    if verify_existing and existing_version:
                        logger.info(
                            "[verify-new-hash] %s  v%s  (new snapshot inserted)",
                            skill.name, skill.version,
                        )
                    else:
                        logger.info("[inserted] %s  v%s  (%s)", skill.name, skill.version, skill.source_id)

            except Exception as exc:
                session.rollback()
                logger.error("Error processing '%s': %s", skill.source_id, exc)
                failures.append({"skill_id": skill.source_id, "error": str(exc)})

        elapsed = round(time.monotonic() - start, 2)
        pagination_stopped_early = getattr(source, "pagination_stopped_early", False)
        # discovery_errors: per-slug failures swallowed inside discover() that never
        # reached the pipeline loop (e.g. detail-fetch 503/409). Tracked on the source
        # so they can be reflected in stats and the failure-rate threshold.
        discovery_errors = getattr(source, "discovery_errors", 0)

        stats = {
            "skills_seen": skills_seen,
            "skills_inserted": skills_inserted,
            "skills_updated": skills_updated,
            "artifacts_downloaded": artifacts_downloaded,
            "artifacts_skipped": artifacts_skipped,
            "failures": len(failures),
            "discovery_errors": discovery_errors,
            "elapsed_seconds": elapsed,
        }
        if capture_limited:
            stats["capture_limited"] = capture_limited
        if near_limit:
            stats["near_limit"] = near_limit
        if failures:
            stats["error_details"] = failures
        if pagination_stopped_early:
            stats["pagination_stopped_early"] = True
        pagination_stop_reason = getattr(source, "pagination_stop_reason", "unknown")
        stats["pagination_stop_reason"] = pagination_stop_reason
        if dry_run:
            stats["dry_run"] = True
        if metadata_only:
            stats["metadata_only"] = True

        if not dry_run:
            # Warn if catalog coverage dropped significantly vs the last successful run.
            # A drop > 10% likely means the listing API returned a premature null cursor
            # under load rather than serving the full catalog. pagination_stopped_early
            # only fires when _fetch_page() raises; a premature null cursor is silent.
            if not pagination_stopped_early:
                prev_seen = crawl_repo.last_successful_skills_seen(source.source_name)
                total_attempted = skills_seen + discovery_errors
                if prev_seen and prev_seen > 0:
                    drop = (prev_seen - total_attempted) / prev_seen
                    if drop > 0.10:
                        logger.warning(
                            "Catalog coverage drop: %d skills attempted this run vs %d in "
                            "last successful run (%.0f%% drop) — listing API may have "
                            "returned a premature end-of-catalog under load",
                            total_attempted, prev_seen, drop * 100,
                        )

            run_status = _compute_run_status(
                skills_seen, failures,
                stopped_early=pagination_stopped_early,
                discovery_errors=discovery_errors,
            )
            crawl_repo.finish(run, status=run_status, stats=stats)
            session.commit()

        return {"run_id": run_id, "stats": stats}

    except Exception:
        session.rollback()
        if not dry_run and run is not None:
            try:
                run.status = "failed"
                run.finished_at = datetime.now(timezone.utc)
                session.commit()
            except Exception:
                pass
        raise
    finally:
        session.close()


def run_backfill(source: BaseSource, store: ArtifactStore, *, dry_run: bool = False, force: bool = False, limit: int = None) -> dict:
    """Re-fetch full artifacts for existing DB skills and update artifact_uri/hash.

    Args:
        source:   A BaseSource implementation. Artifacts are re-fetched through the
                  public fetch_artifact() contract, so backfill works for any source.
        store:    An ArtifactStore implementation (local or S3).
        dry_run:  If True, log what would change but make no writes.
        force:    If True, re-download and re-store even when the hash is unchanged.
        limit:    Process at most this many skill rows. None = no limit.

    Returns:
        A dict with:
            run_id:  The CrawlRun PK, or None in dry_run mode.
            stats:   backfilled, skipped, errors, elapsed_seconds,
                     and optionally error_details and dry_run=True.
    """
    session = SessionLocal()
    start = time.monotonic()
    run = None  # kept outside try so the except block can finalize it on crash

    try:
        crawl_repo = CrawlRunRepository(session)
        skill_repo = SkillRepository(session)

        if dry_run:
            logger.info("Backfill dry-run mode — no DB or artifact writes will be made")
            run_id = None
        else:
            run = crawl_repo.create(source=source.source_name)
            session.commit()
            run_id = run.id

        rows = skill_repo.list_by_source(source.source_name)
        if limit is not None:
            rows = rows[:limit]

        backfilled = 0
        skipped = 0
        errors = []

        for row in rows:
            try:
                # Use the public source contract — fetch_artifact() rebuilds the full
                # artifact directory (including any source-specific extras like
                # ClawHub's _detail.json) without the pipeline reaching into source
                # internals. Passing detail=None lets the source fetch it as needed.
                artifacts = source.fetch_artifact(row.source_id, row.version)
                new_hash = compute_artifact_hash(artifacts, exclude=source.hash_excluded_files)

                if new_hash == row.artifact_hash and not force:
                    logger.debug("[skip] %s  v%s  (hash unchanged)", row.name, row.version)
                    skipped += 1
                    continue

                if dry_run:
                    logger.info(
                        "[dry-run backfill] %s  v%s  (%s files)",
                        row.name, row.version, len(artifacts),
                    )
                    backfilled += 1
                    continue

                artifact_uri = store.save_many(
                    source=source.source_name,
                    skill_id=row.source_id,
                    version=row.version,
                    files=artifacts,
                    artifact_hash=new_hash,
                )
                skill_repo.update_artifact_content(
                    source=source.source_name,
                    source_id=row.source_id,
                    version=row.version,
                    artifact_uri=artifact_uri,
                    artifact_hash=new_hash,
                    crawl_run_id=run_id,
                )
                session.commit()
                backfilled += 1
                logger.info("[backfilled] %s  v%s  (%s)", row.name, row.version, row.source_id)

            except Exception as exc:
                session.rollback()
                logger.error("Error backfilling '%s': %s", row.source_id, exc)
                errors.append({"skill_id": row.source_id, "error": str(exc)})

        elapsed = round(time.monotonic() - start, 2)

        stats = {
            "backfilled": backfilled,
            "skipped": skipped,
            "errors": len(errors),
            "elapsed_seconds": elapsed,
        }
        if errors:
            stats["error_details"] = errors
        if dry_run:
            stats["dry_run"] = True

        if not dry_run:
            total_rows = backfilled + skipped + len(errors)
            run_status = _compute_run_status(total_rows, errors)
            crawl_repo.finish(run, status=run_status, stats=stats)
            session.commit()

        return {"run_id": run_id, "stats": stats}

    except Exception:
        session.rollback()
        if not dry_run and run is not None:
            try:
                run.status = "failed"
                run.finished_at = datetime.now(timezone.utc)
                session.commit()
            except Exception:
                pass
        raise
    finally:
        session.close()
