"""Repository classes for database access.

Each repository wraps a SQLAlchemy session and exposes focused methods
for one table. Callers are responsible for calling session.commit() —
repositories only flush to make auto-generated IDs available within
the same transaction.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from db.models import CrawlRun, Skill


class CrawlRunRepository:
    """Manages crawl_runs rows — one per crawl execution."""

    def __init__(self, session: Session):
        self.session = session

    def create(self, source: str) -> CrawlRun:
        """Insert a new crawl run with status='running' and return it."""
        run = CrawlRun(source=source, status="running")
        self.session.add(run)
        self.session.flush()
        return run

    def finish(self, run: CrawlRun, *, status: str, stats: dict = None, error: str = None) -> None:
        """Mark a crawl run as completed, recording final stats and timestamp.

        status must be one of: 'success', 'partial_success', 'failed'.
        """
        run.status = status
        run.finished_at = datetime.now(timezone.utc)
        run.stats = stats
        run.error_message = error
        self.session.flush()

    def last_successful_skills_seen(self, source: str) -> "int | None":
        """Return total skills attempted in the most recent completed run for this source.

        Returns skills_seen + discovery_errors so the caller can compare against the
        current run's total_attempted on an equal footing. Considers both 'success' and
        'partial_success' runs — both completed full pagination. Returns None if no
        completed run exists yet.
        """
        last = (
            self.session.query(CrawlRun)
            .filter(
                CrawlRun.source == source,
                CrawlRun.status.in_(["success", "partial_success"]),
            )
            .order_by(CrawlRun.id.desc())
            .first()
        )
        if last is None or not last.stats:
            return None
        seen = last.stats.get("skills_seen", 0) or 0
        discovery = last.stats.get("discovery_errors", 0) or 0
        return seen + discovery


class SkillRepository:
    """Manages skills rows — one per unique skill snapshot."""

    def __init__(self, session: Session):
        self.session = session

    def upsert(
        self,
        *,
        source: str,
        source_id: str,
        source_url: str = None,
        name: str,
        version: str = "unversioned",
        revision: str = None,
        description: str = None,
        author: str = None,
        license: str = None,
        artifact_uri: str = None,
        artifact_hash: str = None,
        crawl_run_id: int,
        metadata: dict = None,
    ) -> Skill:
        """Insert a new skill row or update an existing one.

        Match key: (source, source_id, version, artifact_hash) — mirrors the
        uq_skill_version unique constraint. `revision` is persisted but is not part
        of the match key. A match means the exact same artifact was seen before; we
        update mutable fields and last_seen_at in that case.
        """
        existing = (
            self.session.query(Skill)
            .filter_by(source=source, source_id=source_id, version=version, artifact_hash=artifact_hash)
            .first()
        )

        if existing:
            existing.source_url = source_url
            existing.name = name
            existing.revision = revision
            existing.description = description
            existing.author = author
            existing.license = license
            existing.artifact_uri = artifact_uri
            existing.last_crawl_run_id = crawl_run_id
            existing.last_seen_at = datetime.now(timezone.utc)
            existing.metadata_ = metadata
            self.session.flush()
            return existing

        skill = Skill(
            source=source,
            source_id=source_id,
            source_url=source_url,
            name=name,
            version=version,
            revision=revision,
            description=description,
            author=author,
            license=license,
            artifact_uri=artifact_uri,
            artifact_hash=artifact_hash,
            first_crawl_run_id=crawl_run_id,
            last_crawl_run_id=crawl_run_id,
            metadata_=metadata,
        )
        self.session.add(skill)
        self.session.flush()
        return skill

    def find_by_version(self, source: str, source_id: str, version: str) -> "Skill | None":
        """Return the most recent row for (source, source_id, version), or None.

        Multiple rows may exist for the same (source, source_id, version) with
        different artifact hashes — this returns the one with the highest id.
        """
        return (
            self.session.query(Skill)
            .filter_by(source=source, source_id=source_id, version=version)
            .order_by(Skill.id.desc())
            .first()
        )

    def touch(self, source: str, source_id: str, version: str, crawl_run_id: int) -> None:
        """Update last_seen_at and last_crawl_run_id for all rows matching (source, source_id, version).

        Covers all hash variants so that every historical snapshot for a version gets
        a current last_seen_at when the version is observed in a crawl.
        Caller must commit.
        """
        self.session.query(Skill).filter_by(
            source=source, source_id=source_id, version=version
        ).update(
            {"last_seen_at": datetime.now(timezone.utc), "last_crawl_run_id": crawl_run_id},
            synchronize_session=False,
        )
        self.session.flush()

    def list_by_source(self, source: str) -> list:
        """Return all skill rows for a given source, ordered by id."""
        return (
            self.session.query(Skill)
            .filter_by(source=source)
            .order_by(Skill.id)
            .all()
        )

    def update_artifact_content(
        self,
        *,
        source: str,
        source_id: str,
        version: str,
        artifact_uri: str,
        artifact_hash: str,
        crawl_run_id: int,
    ) -> bool:
        """Update artifact_uri and artifact_hash for an existing skill row in-place.

        Matches on (source, source_id, version) — ignores the current hash so
        this works for backfill even when the hash has changed.

        Edge case: a fresh crawl may have already inserted a row with the target
        hash before the backfill runs. In that case, all stale rows for the same
        (source, source_id, version) are deleted and the surviving row is kept as-is.
        Returns True if any matching row existed, False if none was found.
        Caller must commit.
        """
        rows = (
            self.session.query(Skill)
            .filter_by(source=source, source_id=source_id, version=version)
            .order_by(Skill.id)
            .all()
        )
        if not rows:
            return False

        # If the target hash already exists in one of the rows, keep that row,
        # refresh its tracking fields, and delete all other stale rows.
        target = next((r for r in rows if r.artifact_hash == artifact_hash), None)
        if target:
            for stale in rows:
                if stale.id != target.id:
                    self.session.delete(stale)
            target.artifact_uri = artifact_uri
            target.last_seen_at = datetime.now(timezone.utc)
            target.last_crawl_run_id = crawl_run_id
            self.session.flush()
            return True

        # Normal case: update the newest row in-place; delete any older duplicates.
        row = rows[-1]
        for stale in rows[:-1]:
            self.session.delete(stale)
        row.artifact_uri = artifact_uri
        row.artifact_hash = artifact_hash
        row.last_seen_at = datetime.now(timezone.utc)
        row.last_crawl_run_id = crawl_run_id
        self.session.flush()
        return True
