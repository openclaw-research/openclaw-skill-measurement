from __future__ import annotations

from db.models import AnalysisResult
from db.llm_models import (
    Base,
    LLM_ANALYSIS_TABLES,
    LLMAnalysisFinding,
    LLMAnalysisResult,
    LLMAnalysisRun,
)

from llm_config import (
    RELIABLE_STATIC_ANALYZER_NAME,
    RELIABLE_STATIC_ANALYZER_VERSION,
)
from datetime import datetime, timedelta, timezone

from sqlalchemy import Engine, desc, func, select, update, Integer, cast
from sqlalchemy.orm import Session

from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def create_llm_tables(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine, tables=LLM_ANALYSIS_TABLES)


class LLMAnalysisRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_run(
        self,
        analyzer_name: str,
        analyzer_version: str,
        config_json: dict[str, Any] | None = None,
    ) -> LLMAnalysisRun:
        run = LLMAnalysisRun(
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            status="running",
            started_at=utc_now(),
            config_json=config_json,
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_run(
        self, analysis_run_id: int, status: str, error_message: str | None = None
    ) -> None:
        self.session.execute(
            update(LLMAnalysisRun)
            .where(LLMAnalysisRun.id == analysis_run_id)
            .values(status=status, finished_at=utc_now(), error_message=error_message)
        )

    def select_skill_by_risk_level(
        self,
        risk_level,
        analyzer_name: str = RELIABLE_STATIC_ANALYZER_NAME,
        analyzer_version: str = RELIABLE_STATIC_ANALYZER_VERSION,
        skill_id: int | None = None,
        limit: int | None = None,
    ) -> list[AnalysisResult]:
        # self.logger.debug("DEBUG -> AnalysisResult table for risk_level : {AnalysisResult}")
        latest_run_id = (
            select(func.max(AnalysisResult.analysis_run_id))
            .where(AnalysisResult.analyzer_name == analyzer_name)
            .where(AnalysisResult.analyzer_version == analyzer_version)
            .where(AnalysisResult.status == "success")
            .scalar_subquery()
        )

        query = (
            select(AnalysisResult)
            .where(AnalysisResult.analyzer_name == analyzer_name)
            .where(AnalysisResult.analyzer_version == analyzer_version)
            .where(AnalysisResult.analysis_run_id == latest_run_id)
            .where(AnalysisResult.status == "success")
            .where(AnalysisResult.risk_level.in_(risk_level))
            .order_by(AnalysisResult.skill_id)
        )

        if skill_id is not None:
            query = query.where(AnalysisResult.skill_id == skill_id)
        if limit is not None:
            query = query.limit(limit)

        return list(self.session.scalars(query))

    def set_expected_count(self, run_id: int, n_selected: int) -> None:
        self.session.execute(
            update(LLMAnalysisRun)
            .where(LLMAnalysisRun.id == run_id)
            .values(n_selected=n_selected)
        )
        
    def touch_heartbeat(self, run_id: int) -> None:
        self.session.execute(
            update(LLMAnalysisRun)
            .where(LLMAnalysisRun.id == run_id)
            .values(heartbeat_at=func.now())
        )

    def try_reconcile(self, run: LLMAnalysisRun, stale_after: timedelta = timedelta(minutes=30)) -> bool:
        """Returns True if this run was actually complete and has now been closed out."""
        if run.n_selected is None:
            return False
        done = self.count_results_for_run(run.id)
        if done >= run.n_selected:
            self.finish_run(run.id, "success")
            return True
        if self._is_stale(run, stale_after):
            done = done if run.n_selected is not None else 0
            self.finish_run(
                run.id, "failed",
                f"crashed: no heartbeat for over {stale_after}, "
                f"{done}/{run.n_selected if run.n_selected is not None else '?'} done",
            )
            return True
        return False

    def _is_stale(self, run: LLMAnalysisRun, stale_after: timedelta) -> bool:
        now = datetime.now(timezone.utc)
        last_seen = run.heartbeat_at or run.started_at
        return (now - last_seen) > stale_after
    
    def get_running_runs(
        self, analyzer_name: str, analyzer_version: str
    ) -> list[LLMAnalysisRun]:
        return list(
            self.session.scalars(
                select(LLMAnalysisRun).where(
                    LLMAnalysisRun.analyzer_name == analyzer_name,
                    LLMAnalysisRun.analyzer_version == analyzer_version,
                    LLMAnalysisRun.status == "running",
                )
            )
        )

    def count_results_for_run(self, run_id: int) -> int:
        return (
            self.session.scalar(
                select(func.count(LLMAnalysisResult.id)).where(
                    LLMAnalysisResult.llm_analysis_run_id == run_id
                )
            )
            or 0
        )

    # def has_successful_result(
    #     self,
    #     skill_id: int,
    #     artifact_hash: str | None,
    #     analyzer_name: str,
    #     analyzer_version: str,
    # ) -> bool:
    #     query = (
    #         select(LLMAnalysisResult.id)
    #         .where(
    #             LLMAnalysisResult.skill_id == skill_id,
    #             LLMAnalysisResult.status == "success",
    #             LLMAnalysisResult.analyzer_name == analyzer_name,
    #             LLMAnalysisResult.analyzer_version == analyzer_version,
    #         )
    #         .limit(1)
    #     )
    #     if artifact_hash is None:
    #         query = query.where(LLMAnalysisResult.artifact_hash.is_(None))
    #     else:
    #         query = query.where(LLMAnalysisResult.artifact_hash == artifact_hash)

    #     return self.session.scalar(query) is not None

    def get_successful_result(
        self,
        skill_id: int,
        artifact_hash: str,
        analyzer_name: str,
        analyzer_version: str,
    ) -> LLMAnalysisResult | None:
        return self.session.scalar(
            select(LLMAnalysisResult)
            .where(
                LLMAnalysisResult.skill_id == skill_id,
                LLMAnalysisResult.artifact_hash == artifact_hash,
                LLMAnalysisResult.analyzer_name == analyzer_name,
                LLMAnalysisResult.analyzer_version == analyzer_version,
                LLMAnalysisResult.status == "success",
            )
            .order_by(LLMAnalysisResult.created_at.desc())
        )

    def create_result(
        self,
        skill_id: int,
        llm_analysis_run_id: int,
        status: str,
        risk_level: str,
        confidence: float,
        explanation: str | None,
        false_positives_json: dict[str, Any],
        rule_based_risk_level: str,
        rule_based_result_id: int,
        result_json: dict[str, Any],
        human_escalation: bool = False,
        findings: list[dict[str, Any]] | None = None,
        artifact_hash: str | None = None,
        analyzer_name: str | None = None,
        analyzer_version: str | None = None,
    ) -> LLMAnalysisResult:
        result = LLMAnalysisResult(
            skill_id=skill_id,
            llm_analysis_run_id=llm_analysis_run_id,
            artifact_hash=artifact_hash,
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            status=status,
            risk_level=risk_level,
            confidence=confidence,
            explanation=explanation,
            false_positives_json=false_positives_json,
            rule_based_risk_level=rule_based_risk_level,
            rule_based_result_id=rule_based_result_id,
            result_json=result_json,
            human_escalation=human_escalation,
            created_at=utc_now(),
        )
        self.session.add(result)
        self.session.flush()

        for finding in findings or []:
            self.session.add(
                LLMAnalysisFinding(
                    llm_analysis_result_id=result.id,
                    category=finding["category"],
                    severity=finding["severity"],
                    title=finding["title"],
                    description=finding["description"],
                    evidence_json=finding.get("evidence_json"),
                    created_at=utc_now(),
                )
            )

        return result

    def attach_skipped_result(
        self, run_id: int, skill_id: int, existing: LLMAnalysisResult
    ) -> LLMAnalysisResult:
        skipped = LLMAnalysisResult(
            skill_id=skill_id,
            llm_analysis_run_id=run_id,
            rule_based_result_id=existing.rule_based_result_id,
            artifact_hash=existing.artifact_hash,
            analyzer_name=existing.analyzer_name,
            analyzer_version=existing.analyzer_version,
            status="skipped",  
            risk_level=existing.risk_level,
            rule_based_risk_level=existing.rule_based_risk_level,
            confidence=existing.confidence,
            explanation=existing.explanation,
            false_positives_json=existing.false_positives_json,
            result_json=existing.result_json,
            human_escalation=existing.human_escalation,
        )
        self.session.add(skipped)
        self.session.flush()
        return skipped

    def findings_by_category(self) -> list[tuple[str, int]]:
        query = (
            select(LLMAnalysisFinding.category, func.count(LLMAnalysisFinding.id))
            .group_by(LLMAnalysisFinding.category)
            .order_by(LLMAnalysisFinding.category)
        )
        return [(category, count) for category, count in self.session.execute(query)]

    def findings_by_severity(self) -> list[tuple[str, int]]:
        query = (
            select(LLMAnalysisFinding.severity, func.count(LLMAnalysisFinding.id))
            .group_by(LLMAnalysisFinding.severity)
            .order_by(LLMAnalysisFinding.severity)
        )
        return [(severity, count) for severity, count in self.session.execute(query)]

    def latest_run_summary(self) -> dict[str, Any] | None:
        run = self.session.scalars(
            select(LLMAnalysisRun).order_by(desc(LLMAnalysisRun.id)).limit(1)
        ).first()
        if run is None:
            return None

        result_counts = {
            status: count
            for status, count in self.session.execute(
                select(LLMAnalysisResult.status, func.count(LLMAnalysisResult.id))
                .where(LLMAnalysisResult.llm_analysis_run_id == run.id)
                .group_by(LLMAnalysisResult.status)
            )
        }
        return {
            "id": run.id,
            "analyzer_name": run.analyzer_name,
            "analyzer_version": run.analyzer_version,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "result_counts": result_counts,
            "error_message": run.error_message,
        }

    def findings(
        self, severity: str | None = None, limit: int = 50
    ) -> list[LLMAnalysisFinding]:
        query = (
            select(LLMAnalysisFinding)
            .order_by(desc(LLMAnalysisFinding.id))
            .limit(limit)
        )
        if severity is not None:
            query = query.where(LLMAnalysisFinding.severity == severity)
        return list(self.session.scalars(query))
