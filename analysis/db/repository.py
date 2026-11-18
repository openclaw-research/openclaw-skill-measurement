from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Engine, desc, func, inspect, select, text, update
from sqlalchemy.orm import Session

from db.models import (
    ANALYSIS_TABLES,
    AnalysisFinding,
    AnalysisResult,
    AnalysisRun,
    Base,
    Skill,
)


REQUIRED_SKILL_COLUMNS = {
    "id",
    "source",
    "source_id",
    "version",
    "artifact_uri",
    "artifact_hash",
    "name",
}


class SchemaError(RuntimeError):
    pass


def utc_now() -> datetime:
    return datetime.now(UTC)


def inspect_skills_schema(engine: Engine) -> dict[str, Any]:
    inspector = inspect(engine)
    if not inspector.has_table("skills"):
        raise SchemaError("The existing skills table was not found.")

    columns = {column["name"]: column for column in inspector.get_columns("skills")}
    missing = sorted(REQUIRED_SKILL_COLUMNS.difference(columns))
    if missing:
        raise SchemaError(f"The skills table is missing required columns: {', '.join(missing)}")

    primary_key = inspector.get_pk_constraint("skills").get("constrained_columns") or []
    if primary_key != ["id"]:
        raise SchemaError(f"Expected skills primary key to be id, found: {primary_key}")

    return {
        "primary_key": primary_key,
        "columns": {name: str(columns[name]["type"]) for name in sorted(REQUIRED_SKILL_COLUMNS)},
    }


def missing_analysis_tables(engine: Engine) -> list[str]:
    inspector = inspect(engine)
    return [table.name for table in ANALYSIS_TABLES if not inspector.has_table(table.name)]


def create_analysis_tables(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine, tables=ANALYSIS_TABLES)
    ensure_analysis_result_identity_columns(engine)
    backfill_analysis_result_identity(engine)


def ensure_analysis_result_identity_columns(engine: Engine) -> None:
    statements = (
        "alter table analysis_results add column if not exists artifact_hash text",
        "alter table analysis_results add column if not exists analyzer_name text",
        "alter table analysis_results add column if not exists analyzer_version text",
    )
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def backfill_analysis_result_identity(engine: Engine) -> int:
    statement = text(
        """
        update analysis_results as result
        set
            artifact_hash = coalesce(
                result.artifact_hash,
                result.result_json #>> '{artifact,hash}',
                skill.artifact_hash
            ),
            analyzer_name = coalesce(result.analyzer_name, run.analyzer_name),
            analyzer_version = coalesce(result.analyzer_version, run.analyzer_version)
        from analysis_runs as run, skills as skill
        where result.analysis_run_id = run.id
          and result.skill_id = skill.id
          and (
              result.artifact_hash is null
              or result.analyzer_name is null
              or result.analyzer_version is null
          )
        """
    )
    with engine.begin() as connection:
        result = connection.execute(statement)
        return result.rowcount or 0


class AnalysisRepository:
    def __init__(self, session: Session):
        self.session = session

    def create_run(
        self,
        analyzer_name: str,
        analyzer_version: str,
        config_json: dict[str, Any] | None = None,
    ) -> AnalysisRun:
        run = AnalysisRun(
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            status="running",
            started_at=utc_now(),
            config_json=config_json,
        )
        self.session.add(run)
        self.session.flush()
        return run

    def finish_run(self, analysis_run_id: int, status: str, error_message: str | None = None) -> None:
        self.session.execute(
            update(AnalysisRun)
            .where(AnalysisRun.id == analysis_run_id)
            .values(status=status, finished_at=utc_now(), error_message=error_message)
        )

    def select_skills(
        self,
        analyzer_name: str,
        analyzer_version: str,
        limit: int | None = None,
        skill_id: int | None = None,
        force: bool = False,
    ) -> list[Skill]:
        query = select(Skill).where(Skill.artifact_uri.is_not(None)).order_by(Skill.id)

        if skill_id is not None:
            query = query.where(Skill.id == skill_id)

        if not force:
            successful_result_exists = (
                select(AnalysisResult.id)
                .where(
                    AnalysisResult.skill_id == Skill.id,
                    AnalysisResult.artifact_hash.is_not_distinct_from(Skill.artifact_hash),
                    AnalysisResult.status == "success",
                    AnalysisResult.analyzer_name == analyzer_name,
                    AnalysisResult.analyzer_version == analyzer_version,
                )
                .exists()
            )
            query = query.where(~successful_result_exists)

        if limit is not None:
            query = query.limit(limit)

        return list(self.session.scalars(query))

    def select_candidate_skills(
        self,
        limit: int | None = None,
        skill_id: int | None = None,
    ) -> list[Skill]:
        query = select(Skill).where(Skill.artifact_uri.is_not(None)).order_by(Skill.id)

        if skill_id is not None:
            query = query.where(Skill.id == skill_id)

        if limit is not None:
            query = query.limit(limit)

        return list(self.session.scalars(query))
    
    def find_sibling_skill_ids(
        self,
        skill_id: int,
        source: str,
        source_id: str,
        version: str,
        artifact_hash: str | None,
    ) -> list[int]:
        """Return IDs of skills sharing (source, source_id, version) but a different
        artifact_hash. These are candidate sibling snapshots that may differ only by
        collector-generated metadata files such as skill-card.md."""
        query = (
            select(Skill.id)
            .where(
                Skill.source == source,
                Skill.source_id == source_id,
                Skill.version == version,
                Skill.id != skill_id,
            )
        )
        if artifact_hash is None:
            query = query.where(Skill.artifact_hash.is_not(None))
        else:
            query = query.where(Skill.artifact_hash != artifact_hash)
        return list(self.session.scalars(query))
    
    def has_successful_result_for_content_hash(
        self,
        sibling_skill_ids: list[int],
        content_hash: str,
        analyzer_name: str,
        analyzer_version: str,
    ) -> bool:
        """Return True if any sibling skill already has a successful result whose
        stored content_hash matches. Indicates the developer-authored content is
        identical and re-analysis would produce the same output."""
        query = (
            select(AnalysisResult.id)
            .where(
                AnalysisResult.skill_id.in_(sibling_skill_ids),
                AnalysisResult.status == "success",
                AnalysisResult.analyzer_name == analyzer_name,
                AnalysisResult.analyzer_version == analyzer_version,
                AnalysisResult.result_json["artifact"]["content_hash"].astext == content_hash,
            )
            .limit(1)
        )
        return self.session.scalar(query) is not None

    def has_successful_result(
        self,
        skill_id: int,
        artifact_hash: str | None,
        analyzer_name: str,
        analyzer_version: str,
    ) -> bool:
        query = (
            select(AnalysisResult.id)
            .where(
                AnalysisResult.skill_id == skill_id,
                AnalysisResult.status == "success",
                AnalysisResult.analyzer_name == analyzer_name,
                AnalysisResult.analyzer_version == analyzer_version,
            )
            .limit(1)
        )
        if artifact_hash is None:
            query = query.where(AnalysisResult.artifact_hash.is_(None))
        else:
            query = query.where(AnalysisResult.artifact_hash == artifact_hash)

        return self.session.scalar(query) is not None

    def create_result(
        self,
        skill_id: int,
        analysis_run_id: int,
        status: str,
        risk_level: str,
        summary: str,
        result_json: dict[str, Any],
        findings: list[dict[str, Any]] | None = None,
        artifact_hash: str | None = None,
        analyzer_name: str | None = None,
        analyzer_version: str | None = None,
    ) -> AnalysisResult:
        result = AnalysisResult(
            skill_id=skill_id,
            analysis_run_id=analysis_run_id,
            artifact_hash=artifact_hash,
            analyzer_name=analyzer_name,
            analyzer_version=analyzer_version,
            status=status,
            risk_level=risk_level,
            summary=summary,
            result_json=result_json,
            created_at=utc_now(),
        )
        self.session.add(result)
        self.session.flush()

        for finding in findings or []:
            self.session.add(
                AnalysisFinding(
                    analysis_result_id=result.id,
                    category=finding["category"],
                    severity=finding["severity"],
                    title=finding["title"],
                    description=finding["description"],
                    evidence_json=finding.get("evidence_json"),
                    created_at=utc_now(),
                )
            )

        return result

    def results_by_risk_level(self) -> list[tuple[str, int]]:
        query = (
            select(AnalysisResult.risk_level, func.count(AnalysisResult.id))
            .group_by(AnalysisResult.risk_level)
            .order_by(AnalysisResult.risk_level)
        )
        return [(risk_level, count) for risk_level, count in self.session.execute(query)]

    def findings_by_category(self) -> list[tuple[str, int]]:
        query = (
            select(AnalysisFinding.category, func.count(AnalysisFinding.id))
            .group_by(AnalysisFinding.category)
            .order_by(AnalysisFinding.category)
        )
        return [(category, count) for category, count in self.session.execute(query)]

    def findings_by_severity(self) -> list[tuple[str, int]]:
        query = (
            select(AnalysisFinding.severity, func.count(AnalysisFinding.id))
            .group_by(AnalysisFinding.severity)
            .order_by(AnalysisFinding.severity)
        )
        return [(severity, count) for severity, count in self.session.execute(query)]

    def latest_run_summary(self) -> dict[str, Any] | None:
        run = self.session.scalars(select(AnalysisRun).order_by(desc(AnalysisRun.id)).limit(1)).first()
        if run is None:
            return None

        result_counts = {
            status: count
            for status, count in self.session.execute(
                select(AnalysisResult.status, func.count(AnalysisResult.id))
                .where(AnalysisResult.analysis_run_id == run.id)
                .group_by(AnalysisResult.status)
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

    def findings(self, severity: str | None = None, limit: int = 50) -> list[AnalysisFinding]:
        query = select(AnalysisFinding).order_by(desc(AnalysisFinding.id)).limit(limit)
        if severity is not None:
            query = query.where(AnalysisFinding.severity == severity)
        return list(self.session.scalars(query))
