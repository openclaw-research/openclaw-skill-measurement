from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Index, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models import Base


class DynamicAnalysisRun(Base):
    __tablename__ = "dynamic_analysis_runs"
    __table_args__ = (
        Index("idx_dynamic_runs_analyzer", "analyzer_name", "analyzer_version"),
        Index("idx_dynamic_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analyzer_name: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(Text, nullable=False)
    n_selected: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    config_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    results: Mapped[list["DynamicAnalysisResult"]] = relationship(
        back_populates="dynamic_analysis_run"
    )


class DynamicAnalysisResult(Base):
    __tablename__ = "dynamic_analysis_results"
    __table_args__ = (
        Index("idx_dynamic_results_skill_id", "skill_id"),
        Index("idx_dynamic_results_run_id", "dynamic_analysis_run_id"),
        Index("idx_dynamic_results_verdict", "verdict"),
        Index("idx_dynamic_results_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    skill_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("skills.id", ondelete="RESTRICT"), nullable=False
    )
    dynamic_analysis_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("dynamic_analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    static_result_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("analysis_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    llm_result_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("llm_analysis_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    analyzer_name: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    verdict_reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Observed runtime events
    syscall_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    executables_run: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default="[]")
    exit_codes: Mapped[list[int]] = mapped_column(JSONB, nullable=False, server_default="[]")
    network_calls: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default="[]")
    credential_paths_read: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    sensitive_writes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    exfiltration_domains: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )
    reverse_shell_processes: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, server_default="[]"
    )

    # LLM interpretation
    llm_purpose_fit: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_prior_agreement: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_unexecuted_risk: Mapped[str | None] = mapped_column(Text, nullable=True)
    llm_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_analysis_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Full result for research queries
    result_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    dynamic_analysis_run: Mapped[DynamicAnalysisRun] = relationship(
        back_populates="results"
    )


DYNAMIC_TABLES = (
    DynamicAnalysisRun.__table__,
    DynamicAnalysisResult.__table__,
)