from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Skill(Base):
    __tablename__ = "skills"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text)
    source_id: Mapped[str] = mapped_column(Text)
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text)
    artifact_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_hash: Mapped[str | None] = mapped_column(Text, nullable=True)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    __table_args__ = (
        Index("idx_analysis_runs_analyzer", "analyzer_name", "analyzer_version"),
        Index("idx_analysis_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analyzer_name: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["AnalysisResult"]] = relationship(back_populates="analysis_run")


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    __table_args__ = (
        Index("idx_analysis_results_skill_id", "skill_id"),
        Index("idx_analysis_results_run_id", "analysis_run_id"),
        Index("idx_analysis_results_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    skill_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("skills.id", ondelete="RESTRICT"), nullable=False
    )
    analysis_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    artifact_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzer_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzer_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis_run: Mapped[AnalysisRun] = relationship(back_populates="results")
    findings: Mapped[list["AnalysisFinding"]] = relationship(back_populates="analysis_result")


class AnalysisFinding(Base):
    __tablename__ = "analysis_findings"
    __table_args__ = (
        Index("idx_analysis_findings_result_id", "analysis_result_id"),
        Index("idx_analysis_findings_category", "category"),
        Index("idx_analysis_findings_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analysis_result_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("analysis_results.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis_result: Mapped[AnalysisResult] = relationship(back_populates="findings")


ANALYSIS_TABLES = (
    AnalysisRun.__table__,
    AnalysisResult.__table__,
    AnalysisFinding.__table__,
)
