from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import select

from analyzers.llm.analyzer import analyze
from artifacts.s3_loader import S3ArtifactLoader
from llm_config import LLMSettings
from db.llm_repository import LLMAnalysisRepository
from db.models import Skill


ANALYZER_NAME = "llm"
ANALYZER_VERSION = "1"

class LLMAnalysisPipeline:

    def __init__(
        self,
        settings: LLMSettings,
        session_factory: sessionmaker[Session],
        artifact_loader: S3ArtifactLoader | None = None,
        logger: logging.Logger | None = None,
    ):
        self.settings = settings
        self.session_factory = session_factory
        self.artifact_loader = artifact_loader or S3ArtifactLoader(
            bucket_name=settings.s3_bucket,
            region_name=settings.aws_region,
        )
        self.api_key = settings.api_key
        self.logger = logger or logging.getLogger("openclaw.llm_analysis")
        
    
    def run(
        self,
        risk_levels : list[str] | None = None,
        skill_id: int | None = None,
        limit : int | None = None,
        force : bool = False,
        progress_every: int = 25,
    ) -> dict[str, Any]:
        started_at = time.monotonic()
        risk_levels = risk_levels or ["critical", "high"]
        with self.session_factory() as session:
            repo = LLMAnalysisRepository(session)
            for stale in repo.get_running_runs(ANALYZER_NAME, ANALYZER_VERSION):
                repo.try_reconcile(stale)
            session.commit()

            still_active = repo.get_running_runs(ANALYZER_NAME, ANALYZER_VERSION)
            if still_active:
                raise RuntimeError(
                    f"Run #{still_active[0].id} for {ANALYZER_NAME} v{ANALYZER_VERSION} is still "
                    f"in progress (started {still_active[0].started_at}, "
                    f"{repo.count_results_for_run(still_active[0].id)}/{still_active[0].n_selected} done). "
                    "Refusing to start a new run until it finishes."
                )
            run = repo.create_run(
                analyzer_name = ANALYZER_NAME,
                analyzer_version = ANALYZER_VERSION,
                config_json={
                    "limit": limit,
                    "skill_id": skill_id,
                    "force": force,
                    "progress_every": progress_every,
                    "risk_levels":risk_levels
                },
            )
            # self.logger.debug("DEBUG -> analysis_run_table : {run}")
            run_id = run.id
            session.commit()
            
            candidates = repo.select_skill_by_risk_level(risk_levels, limit=limit, skill_id=skill_id)
            # self.logger.debug("DEBUG -> candidate skills : {candidates}")
            skills = []
            for result in candidates:
                skill = session.scalar(select(Skill).where(Skill.id == result.skill_id))
                if skill and skill.artifact_uri : skills.append((skill,result))
            
            repo.set_expected_count(run_id, len(skills))
            
            summary = {
                "llm_analysis_run_id": run_id,
                "selected": len(skills),
                "skipped": 0,
                "succeeded": 0,
                "failed": 0,
                "elapsed_seconds": 0.0,
                "analyzer_name": ANALYZER_NAME,
                "analyzer_version": ANALYZER_VERSION,
            }

            self.logger.info(
                "Starting llm analysis run #%s analyzer=%s v%s selected=%s risk_levels=%s",
                run_id,
                ANALYZER_NAME,
                ANALYZER_VERSION,
                len(skills),
                risk_levels,
            )
            
            try:
                total = len(skills)
                for index, (skill, result) in enumerate(skills,start=1):
                    # if not force and repo.has_successful_result(
                    #     skill_id = skill.id,
                    #     artifact_hash = skill.artifact_hash,
                    #     analyzer_name = "llm",
                    #     analyzer_version = "1",
                    # ):
                    #     summary["skipped"] += 1
                    #     self.logger.info(
                    #         "[%s/%s] skill_id=%s %s/%s v%s skipped existing successful result elapsed=%.1fs",
                    #         index,
                    #         total,
                    #         skill.id,
                    #         skill.source,
                    #         skill.source_id,
                    #         skill.version,
                    #         elapsed_seconds(started_at),
                    #     )
                    #     self.logger.debug("DEBUG -> rule-based-result : {result}")
                    existing = None
                    if not force:
                        existing = repo.get_successful_result(
                            skill_id=skill.id,
                            artifact_hash=skill.artifact_hash,
                            analyzer_name="llm",
                            analyzer_version="1",
                        )
                    if existing:
                        repo.attach_skipped_result(run_id, skill.id, existing)
                        session.commit()
                        summary["skipped"] += 1
                        self.logger.info(
                            "[%s/%s] skill_id=%s %s/%s v%s reused existing successful result elapsed=%.1fs",
                            index, total, skill.id, skill.source, skill.source_id, skill.version,
                            elapsed_seconds(started_at),
                        )
                    elif self._process_skill(session, repo, run_id, skill, result, index, total, started_at):
                        summary["succeeded"] += 1
                    else:
                        summary["failed"] += 1
                    
                summary["elapsed_seconds"] = elapsed_seconds(started_at)
                repo.finish_run(run_id, "success")
                session.commit()
                
                self.logger.info(
                    "Completed run #%s selected=%s skipped=%s succeeded=%s failed=%s elapsed=%.1fs",
                    run_id,
                    summary["selected"],
                    summary["skipped"],
                    summary["succeeded"],
                    summary["failed"],
                    summary["elapsed_seconds"],
                )
                return summary

            except Exception as exc:
                session.rollback()
                repo.finish_run(run_id, "failed", str(exc))
                session.commit()
                self.logger.error(
                    "llm analysis run #%s failed error_type=%s error=%s elapsed=%.1fs",
                    run_id,
                    type(exc).__name__,
                    exc,
                    elapsed_seconds(started_at),
                )
                self.logger.debug("llm analysis run failure details", exc_info=True)
                raise
        
    
    def _process_skill(
        self,
        session : Session,
        repo : LLMAnalysisRepository,
        analysis_run_id : int,
        skill: Skill,        
        rule_based_result: Any,
        index: int,
        total: int,
        started_at: float, 
    ) -> bool:
        temp_path : Path | None = None
        
        try:
            repo.touch_heartbeat(analysis_run_id)
            session.commit()
            temp_path = self._make_temp_dir(skill.id)
            # self.logger.debug("DEBUG temp_path: {temp_path}")
            self.logger.info(
                "[%s/%s] skill_id=%s %s/%s v%s downloading artifact artifact_uri=%s",
                index,
                total,
                skill.id,
                skill.source,
                skill.source_id,
                skill.version,
                skill.artifact_uri,
            )
            download_result = self.artifact_loader.download_prefix(skill.artifact_uri, temp_path)
            self.logger.info(
                "[%s/%s] skill_id=%s downloaded objects=%s bytes=%s elapsed=%.1fs",
                index,
                total,
                skill.id,
                download_result.object_count,
                download_result.bytes_downloaded,
                elapsed_seconds(started_at),
            )
            # self.logger.debug("DEBUG -> Download resuts : {download_result}")
            if not rule_based_result.result_json:
                raise ValueError(f"skill_id={skill.id} has empty result_json — skipping")
            report = analyze(
                root_path = download_result.root_path,
                result_json=rule_based_result.result_json,
                risk_level=rule_based_result.risk_level,
                summary=rule_based_result.summary,
                api_key=self.api_key,
            )
            # self.logger.debug("DEBUG -> report : {report}")
            result_json = {
                **report,
                "artifact": {
                    "uri": skill.artifact_uri,
                    "hash": skill.artifact_hash,
                    "downloaded_objects": download_result.object_count,
                    "downloaded_bytes": download_result.bytes_downloaded,
                },
            }
            repo.create_result(
                skill_id=skill.id,
                llm_analysis_run_id=analysis_run_id,
                status=report["status"],
                risk_level=report["risk_label"],
                confidence=report["confidence"],
                explanation=report["explanation"],
                false_positives_json={"false_positives": report["false_positives"]},
                rule_based_risk_level=rule_based_result.risk_level,
                rule_based_result_id=rule_based_result.id,
                result_json=result_json,
                human_escalation=report.get("human_escalation", False),
                findings=report["findings"],
                artifact_hash=skill.artifact_hash,
                analyzer_name=ANALYZER_NAME,
                analyzer_version=ANALYZER_VERSION,
            )
            session.commit()
            self.logger.info(
                "[%s/%s] skill_id=%s analyzed risk=%s findings=%s elapsed=%.1fs",
                index,
                total,
                skill.id,   
                report["risk_label"],
                len(report["findings"]),
                elapsed_seconds(started_at),
            )
            return True
        except Exception as exc:
            session.rollback()
            self.logger.error(
                "[%s/%s] skill_id=%s failed artifact_uri=%s error_type=%s error=%s elapsed=%.1fs",
                index,
                total,
                skill.id,
                skill.artifact_uri,
                type(exc).__name__,
                exc,
                elapsed_seconds(started_at),
            )
            self.logger.debug(
                "[%s/%s] skill_id=%s failure details",
                index,
                total,
                skill.id,
                exc_info=True,
            )
            repo.create_result(
                skill_id=skill.id,
                llm_analysis_run_id=analysis_run_id,
                status="failed",
                risk_level="unknown",
                confidence=0.0,              
                explanation=f"LLM analysis failed: {exc}",  
                false_positives_json={"false_positives": []},  
                rule_based_risk_level=rule_based_result.risk_level,  
                rule_based_result_id=rule_based_result.id,           
                result_json={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "artifact": {
                        "uri": skill.artifact_uri,
                        "hash": skill.artifact_hash,
                    },
                },
                findings=[],
                artifact_hash=skill.artifact_hash,
                analyzer_name=ANALYZER_NAME,
                analyzer_version=ANALYZER_VERSION,
            )
            session.commit()
            return False
        finally:
            if temp_path is not None:
                self._cleanup_temp_dir(temp_path)
            
            
    def _make_temp_dir(self, skill_id: int) -> Path:
        tmp_dir = self.settings.artifact_tmp_dir / "llm"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        return Path(
            tempfile.mkdtemp(
                prefix=f"skill-{skill_id}-",
                dir=str(tmp_dir),
            )
        )

    def _cleanup_temp_dir(self, temp_path: Path) -> None:
        try:
            shutil.rmtree(temp_path)
            self.logger.debug("cleaned temp directory %s", temp_path)
        except Exception as exc:
            self.logger.warning(
                "failed to clean temp directory %s error_type=%s error=%s",
                temp_path,
                type(exc).__name__,
                exc,
            )
    
    
def elapsed_seconds(started_at: float) -> float:
    return time.monotonic() - started_at

    
    
            
        