"""ORM models for the skill collection system.

Two tables:
    crawl_runs  — one row per crawl execution (tracks status and stats)
    skills      — one row per collected skill snapshot (upserted each run)

These models are intentionally kept Alembic-compatible: all schema
changes should go through migrations rather than touching create_all().
"""

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, CheckConstraint, Column, ForeignKey,
    Index, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.types import TIMESTAMP


class Base(DeclarativeBase):
    pass


def _now():
    """Return the current UTC time (used as a column default)."""
    return datetime.now(timezone.utc)


class CrawlRun(Base):
    """Records a single crawl execution for one source.

    Created at the start of each run with status='running'.
    Updated to 'success' or 'failed' once the run completes.
    The stats JSONB column holds a summary dict (discovered/inserted/updated/errors).
    """
    __tablename__ = "crawl_runs"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    source = Column(Text, nullable=False)
    started_at = Column(TIMESTAMP(timezone=True), default=_now, nullable=False)
    finished_at = Column(TIMESTAMP(timezone=True), nullable=True)
    status = Column(Text, nullable=False, default="running")
    stats = Column(JSONB, nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'success', 'partial_success', 'failed')",
            name="ck_crawl_runs_status",
        ),
    )


class Skill(Base):
    """Represents one collected skill snapshot.

    A skill is uniquely identified by (source, source_id, version, artifact_hash).
    The same skill re-discovered in a later run updates last_seen_at rather than
    inserting a duplicate row. `revision` is tracked but deliberately excluded from
    the uniqueness key (see the column comment).

    artifact_uri points to the stored file (local path or s3:// URI).
    artifact_hash (SHA-256) enables cross-source deduplication.
    metadata_ stores flexible source-specific fields as JSONB; the Python attribute
    is named metadata_ to avoid shadowing SQLAlchemy's reserved Base.metadata.
    """
    __tablename__ = "skills"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    source = Column(Text, nullable=False)       # e.g. 'openclaw', 'github'
    source_id = Column(Text, nullable=False)    # unique ID within that source
    source_url = Column(Text, nullable=True)    # original page/repo URL

    name = Column(Text, nullable=False)
    version = Column(Text, nullable=False, default="unversioned")

    # Source-specific immutable/semi-immutable revision pointer: git commit SHA,
    # tag target SHA, branch HEAD SHA, package digest, etc. Distinct from the
    # human `version` string. Nullable — sources that expose only a semantic
    # version (e.g. ClawHub) leave this NULL. Intentionally NOT part of the
    # uniqueness key: byte identity is already captured by artifact_hash.
    revision = Column(Text, nullable=True)

    description = Column(Text, nullable=True)
    author = Column(Text, nullable=True)
    license = Column(Text, nullable=True)

    artifact_uri = Column(Text, nullable=True)   # local path or s3:// URI
    artifact_hash = Column(Text, nullable=True)  # SHA-256 hex digest

    first_crawl_run_id = Column(BigInteger, ForeignKey("crawl_runs.id"), nullable=True)
    last_crawl_run_id = Column(BigInteger, ForeignKey("crawl_runs.id"), nullable=True)

    first_seen_at = Column(TIMESTAMP(timezone=True), default=_now, nullable=False)
    last_seen_at = Column(TIMESTAMP(timezone=True), default=_now, onupdate=_now, nullable=False)

    # Column is named "metadata" in the DB; Python attribute uses metadata_ to avoid
    # shadowing SQLAlchemy's DeclarativeBase.metadata class attribute.
    metadata_ = Column("metadata", JSONB, nullable=True)

    __table_args__ = (
        UniqueConstraint("source", "source_id", "version", "artifact_hash", name="uq_skill_version"),
        Index("idx_skills_source", "source"),
        # Hash index: btree rejects name values > ~2704 bytes; hash has no size limit
        # and supports the equality lookups this index exists for.
        Index("idx_skills_name", "name", postgresql_using="hash"),
        Index("idx_skills_artifact_hash", "artifact_hash"),
        Index("idx_skills_revision", "revision"),
        Index("idx_skills_last_seen", "last_seen_at"),
    )
