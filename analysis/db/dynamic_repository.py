from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import desc, func, select, update
from sqlalchemy.orm import Session

from db.dynamic_models import DynamicAnalysisResult, DynamicAnalysisRun
from db.models import Skill
from db.llm_models import LLMAnalysisResult


def utc_now() -> datetime:
    return datetime.now(UTC)


class DynamicAnalysisRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_run(
        self,
        analyzer_name: str,
        analyzer_version: str,
        config_json: dict[str, Any] | None = None,
    ) -> DynamicAnalysisRun:
        run = DynamicAnalysisRun(
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
        self,
        run_id: int,
        status: str,
        error_message: str | None = None,
    ) -> None:
        self.session.execute(
            update(DynamicAnalysisRun)
            .where(DynamicAnalysisRun.id == run_id)
            .values(status=status, finished_at=utc_now(), error_message=error_message)
        )

    def set_expected_count(self, run_id: int, n_selected: int) -> None:
        self.session.execute(
            update(DynamicAnalysisRun)
            .where(DynamicAnalysisRun.id == run_id)
            .values(n_selected=n_selected)
        )

    def has_successful_result(
        self,
        skill_id: int,
        analyzer_name: str,
        analyzer_version: str,
    ) -> bool:
        """Return True if this skill already has a successful dynamic result."""
        query = (
            select(DynamicAnalysisResult.id)
            .where(
                DynamicAnalysisResult.skill_id == skill_id,
                DynamicAnalysisResult.status == "success",
                DynamicAnalysisResult.analyzer_name == analyzer_name,
                DynamicAnalysisResult.analyzer_version == analyzer_version,
            )
            .limit(1)
        )
        return self.session.scalar(query) is not None

    def select_qualified_skills(
        self,
        analyzer_name: str,
        analyzer_version: str,
        limit: int | None = None,
        force: bool = False,
    ) -> list[Any]:
        """Select LLM-confirmed critical/high skills with .sh files for dynamic analysis."""
        from sqlalchemy import and_, or_
        from db.models import AnalysisResult
        from db.llm_models import LLMAnalysisResult

        from sqlalchemy import func, case
        import sqlalchemy as sa

        # Use ROW_NUMBER() subquery instead of DISTINCT ON to allow
        # arbitrary ordering (shell-only skills first)
        has_other_code = sa.cast(
            case(
                (
                    AnalysisResult.result_json["extension_counts"].has_key(".py")
                    | AnalysisResult.result_json["extension_counts"].has_key(".js")
                    | AnalysisResult.result_json["extension_counts"].has_key(".ts"),
                    1,
                ),
                else_=0,
            ),
            sa.Integer,
        )

        row_number = func.row_number().over(
            partition_by=Skill.id,
            order_by=AnalysisResult.id.desc(),
        ).label("rn")

        subq = (
            select(
                Skill.id.label("skill_id"),
                Skill.artifact_uri,
                Skill.artifact_hash,
                Skill.source_id,
                AnalysisResult.id.label("static_result_id"),
                AnalysisResult.risk_level.label("static_risk"),
                LLMAnalysisResult.id.label("llm_result_id"),
                LLMAnalysisResult.risk_level.label("llm_risk"),
                LLMAnalysisResult.explanation.label("llm_explanation"),
                LLMAnalysisResult.human_escalation.label("human_escalation"),
                has_other_code.label("has_other_code"),
                row_number,
            )
            .select_from(Skill)
            .join(AnalysisResult, AnalysisResult.skill_id == Skill.id)
            .join(
                LLMAnalysisResult,
                LLMAnalysisResult.rule_based_result_id == AnalysisResult.id,
            )
            .where(LLMAnalysisResult.status == "success")
            .where(
                or_(
                    LLMAnalysisResult.risk_level.in_(["critical", "high"]),
                    LLMAnalysisResult.human_escalation == True,
                )
            )
            .where(
                AnalysisResult.result_json["extension_counts"].has_key(".sh")
            )
            .where(Skill.artifact_uri.is_not(None))
        ).subquery()

        query = (
            select(
                subq.c.skill_id,
                subq.c.artifact_uri,
                subq.c.artifact_hash,
                subq.c.source_id,
                subq.c.static_result_id,
                subq.c.static_risk,
                subq.c.llm_result_id,
                subq.c.llm_risk,
                subq.c.llm_explanation,
                subq.c.human_escalation,
            )
            .where(subq.c.rn == 1)
            .order_by(subq.c.has_other_code.asc(), subq.c.skill_id.asc())
        )

        if not force:
            already_analyzed = (
                select(DynamicAnalysisResult.skill_id)
                .where(
                    DynamicAnalysisResult.analyzer_name == analyzer_name,
                    DynamicAnalysisResult.analyzer_version == analyzer_version,
                    DynamicAnalysisResult.status == "success",
                    DynamicAnalysisResult.artifact_hash == Skill.artifact_hash,
                )
                .correlate(Skill)
                .exists()
            )
            query = query.where(~already_analyzed)

        if limit is not None:
            query = query.limit(limit)

        return list(self.session.execute(query))

    def create_result(
        self,
        skill_id: int,
        dynamic_analysis_run_id: int,
        status: str,
        verdict: str,
        verdict_reason: str,
        syscall_count: int,
        executables_run: list[str],
        exit_codes: list[int],
        network_calls: list[str],
        credential_paths_read: list[str],
        sensitive_writes: list[str],
        exfiltration_domains: list[str],
        reverse_shell_processes: list[str],
        result_json: dict[str, Any],
        static_result_id: int | None = None,
        llm_result_id: int | None = None,
        artifact_hash: str | None = None,
        analyzer_name: str | None = None,
        analyzer_version: str | None = None,
        llm_purpose_fit: str | None = None,
        llm_prior_agreement: str | None = None,
        llm_unexecuted_risk: str | None = None,
        llm_confidence: float | None = None,
        llm_analysis_notes: str | None = None,
    ) -> DynamicAnalysisResult:
        result = DynamicAnalysisResult(
            skill_id=skill_id,
            dynamic_analysis_run_id=dynamic_analysis_run_id,
            static_result_id=static_result_id,
            llm_result_id=llm_result_id,
            artifact_hash=artifact_hash,
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            status=status,
            verdict=verdict,
            verdict_reason=verdict_reason,
            syscall_count=syscall_count,
            executables_run=executables_run,
            exit_codes=exit_codes,
            network_calls=network_calls,
            credential_paths_read=credential_paths_read,
            sensitive_writes=sensitive_writes,
            exfiltration_domains=exfiltration_domains,
            reverse_shell_processes=reverse_shell_processes,
            llm_purpose_fit=llm_purpose_fit,
            llm_prior_agreement=llm_prior_agreement,
            llm_unexecuted_risk=llm_unexecuted_risk,
            llm_confidence=llm_confidence,
            llm_analysis_notes=llm_analysis_notes,
            result_json=result_json,
            created_at=utc_now(),
        )
        self.session.add(result)
        self.session.flush()
        return result

    def count_results_for_run(self, run_id: int) -> int:
        return (
            self.session.scalar(
                select(func.count(DynamicAnalysisResult.id)).where(
                    DynamicAnalysisResult.dynamic_analysis_run_id == run_id
                )
            )
            or 0
        )

    def results_by_verdict(self, run_id: int) -> list[tuple[str, int]]:
        query = (
            select(DynamicAnalysisResult.verdict, func.count(DynamicAnalysisResult.id))
            .where(DynamicAnalysisResult.dynamic_analysis_run_id == run_id)
            .group_by(DynamicAnalysisResult.verdict)
            .order_by(DynamicAnalysisResult.verdict)
        )
        return [(verdict, count) for verdict, count in self.session.execute(query)]

    def latest_run_summary(self) -> dict[str, Any] | None:
        run = self.session.scalars(
            select(DynamicAnalysisRun)
            .order_by(desc(DynamicAnalysisRun.id))
            .limit(1)
        ).first()
        if run is None:
            return None

        result_counts = {
            status: count
            for status, count in self.session.execute(
                select(DynamicAnalysisResult.status, func.count(DynamicAnalysisResult.id))
                .where(DynamicAnalysisResult.dynamic_analysis_run_id == run.id)
                .group_by(DynamicAnalysisResult.status)
            )
        }
        verdict_counts = {
            verdict: count
            for verdict, count in self.session.execute(
                select(DynamicAnalysisResult.verdict, func.count(DynamicAnalysisResult.id))
                .where(DynamicAnalysisResult.dynamic_analysis_run_id == run.id)
                .group_by(DynamicAnalysisResult.verdict)
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
            "verdict_counts": verdict_counts,
            "error_message": run.error_message,
        }