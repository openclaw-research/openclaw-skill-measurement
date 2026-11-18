from __future__ import annotations

from db.models import Base
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, Boolean, ForeignKey, Integer, Index, Float, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import  Mapped, mapped_column, relationship


class LLMAnalysisRun(Base):
    __tablename__ = "llm_analysis_runs"
    __table_args__ = (
        Index("idx_llm_analysis_runs_analyzer", "analyzer_name", "analyzer_version"),
        Index("idx_llm_analysis_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    analyzer_name: Mapped[str] = mapped_column(Text, nullable=False)
    analyzer_version: Mapped[str] = mapped_column(Text, nullable=False)
    n_selected: Mapped[int | None] = mapped_column(Integer, nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    results: Mapped[list["LLMAnalysisResult"]] = relationship(back_populates="llm_analysis_run")


class LLMAnalysisResult(Base):
    __tablename__ = "llm_analysis_results"
    __table_args__ = (
        Index("idx_llm_analysis_results_skill_id", "skill_id"),
        Index("idx_llm_analysis_results_run_id", "llm_analysis_run_id"),
        Index("idx_llm_analysis_results_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    skill_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("skills.id", ondelete="RESTRICT"), nullable=False
    )
    llm_analysis_run_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("llm_analysis_runs.id", ondelete="CASCADE"), nullable=False
    )
    rule_based_result_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("analysis_results.id", ondelete="CASCADE"), nullable=False
    )
    artifact_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzer_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    analyzer_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    rule_based_risk_level: Mapped[str] = mapped_column(Text, nullable=False) 
    confidence: Mapped[float] = mapped_column(Float, nullable=False) 
    explanation : Mapped[str | None] = mapped_column(Text, nullable=True)
    false_positives_json : Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    human_escalation: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    llm_analysis_run: Mapped[LLMAnalysisRun] = relationship(back_populates="results")
    findings: Mapped[list["LLMAnalysisFinding"]] = relationship(back_populates="analysis_result")


class LLMAnalysisFinding(Base):
    __tablename__ = "llm_analysis_findings"
    __table_args__ = (
        Index("idx_llm_analysis_findings_result_id", "llm_analysis_result_id"),
        Index("idx_llm_analysis_findings_category", "category"),
        Index("idx_llm_analysis_findings_severity", "severity"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    llm_analysis_result_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("llm_analysis_results.id", ondelete="CASCADE"), nullable=False
    )
    category: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    analysis_result: Mapped[LLMAnalysisResult] = relationship(back_populates="findings")


LLM_ANALYSIS_TABLES = (
    LLMAnalysisRun.__table__,
    LLMAnalysisResult.__table__,
    LLMAnalysisFinding.__table__,
)
