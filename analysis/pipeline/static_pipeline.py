from __future__ import annotations

import hashlib
import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from analyzers.base import Analyzer
from analyzers.static.analyzer import StaticAnalyzer, COLLECTOR_METADATA_FILES
from artifacts.s3_loader import S3ArtifactLoader
from config import Settings
from db.models import Skill
from db.repository import AnalysisRepository


class StaticAnalysisPipeline:
    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        artifact_loader: S3ArtifactLoader | None = None,
        analyzer: Analyzer | None = None,
        logger: logging.Logger | None = None,
        max_consecutive_failures: int = 10,
        max_failure_rate: float = 0.5,
        min_skills_before_rate_check: int = 20,
        min_processed_before_consecutive_check: int = 100,
        max_absolute_failures: int = 50,
    ):
        self.max_consecutive_failures = max_consecutive_failures
        self.max_failure_rate = max_failure_rate
        self.min_skills_before_rate_check = min_skills_before_rate_check
        self.min_processed_before_consecutive_check = min_processed_before_consecutive_check
        self.max_absolute_failures = max_absolute_failures
        self.settings = settings
        self.session_factory = session_factory
        self.artifact_loader = artifact_loader or S3ArtifactLoader(
            bucket_name=settings.s3_bucket,
            region_name=settings.aws_region,
        )
        self.analyzer = analyzer or StaticAnalyzer()
        self.logger = logger or logging.getLogger("openclaw.analysis")

    def run(
        self,
        limit: int | None = None,
        skill_id: int | None = None,
        force: bool = False,
        progress_every: int = 25,
    ) -> dict[str, Any]:
        started_at = time.monotonic()
        with self.session_factory() as session:
            repo = AnalysisRepository(session)
            run = repo.create_run(
                analyzer_name=self.analyzer.name,
                analyzer_version=self.analyzer.version,
                config_json={
                    "limit": limit,
                    "skill_id": skill_id,
                    "force": force,
                    "progress_every": progress_every,
                },
            )
            run_id = run.id
            session.commit()

            skills = [
                skill_to_dict(skill)
                for skill in repo.select_candidate_skills(limit=limit, skill_id=skill_id)
            ]

            summary = {
                "analysis_run_id": run_id,
                "selected": len(skills),
                "skipped": 0,
                "succeeded": 0,
                "failed": 0,
                "elapsed_seconds": 0.0,
                "analyzer_name": self.analyzer.name,
                "analyzer_version": self.analyzer.version,
            }

            self.logger.info(
                "Starting static analysis run #%s analyzer=%s v%s selected=%s force=%s",
                run_id,
                self.analyzer.name,
                self.analyzer.version,
                len(skills),
                force,
            )

            try:
                total = len(skills)
                consecutive_failures = 0
                for index, skill in enumerate(skills, start=1):
                    if not force and repo.has_successful_result(
                        skill_id=skill["id"],
                        artifact_hash=skill["artifact_hash"],
                        analyzer_name=self.analyzer.name,
                        analyzer_version=self.analyzer.version,
                    ):
                        summary["skipped"] += 1
                        self.logger.info(
                            "[%s/%s] skill_id=%s %s/%s v%s skipped existing successful result elapsed=%.1fs",
                            index,
                            total,
                            skill["id"],
                            skill["source"],
                            skill["source_id"],
                            skill["version"],
                            elapsed_seconds(started_at),
                        )
                    elif self._process_skill(session, repo, run_id, skill, index, total, started_at, force):
                        summary["succeeded"] += 1
                        consecutive_failures = 0
                    else:
                        summary["failed"] += 1
                        consecutive_failures += 1

                    should_stop, stop_reason = self._check_failure_threshold(
                        summary, consecutive_failures
                    )
                    if should_stop:
                        self.logger.error(stop_reason)
                        repo.finish_run(run_id, "failed", stop_reason)
                        session.commit()
                        summary["stop_reason"] = stop_reason
                        return summary

                    processed = summary["skipped"] + summary["succeeded"] + summary["failed"]
                    if progress_every > 0 and processed % progress_every == 0 and processed < total:
                        self.logger.info(
                            "Progress run #%s processed=%s/%s skipped=%s succeeded=%s failed=%s elapsed=%.1fs",
                            run_id,
                            processed,
                            total,
                            summary["skipped"],
                            summary["succeeded"],
                            summary["failed"],
                            elapsed_seconds(started_at),
                        )

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
                    "Static analysis run #%s failed error_type=%s error=%s elapsed=%.1fs",
                    run_id,
                    type(exc).__name__,
                    exc,
                    elapsed_seconds(started_at),
                )
                self.logger.debug("Static analysis run failure details", exc_info=True)
                raise

    def _check_failure_threshold(
        self,
        summary: dict,
        consecutive_failures: int,
    ) -> tuple[bool, str]:
        """Check if failure thresholds are exceeded.

        Three checks:
        1. Consecutive failures — only after min_processed_before_consecutive_check
        2. Failure rate — only after min_skills_before_rate_check
        3. Absolute failure count — always checked

        Returns (should_stop, reason).
        """
        processed = summary["succeeded"] + summary["failed"]
        progress_str = (
            f"Progress so far: {summary['succeeded']} succeeded, "
            f"{summary['failed']} failed out of {processed} processed."
        )

        # Check 1 — consecutive failures (only after minimum processed count)
        if (
            processed >= self.min_processed_before_consecutive_check
            and consecutive_failures >= self.max_consecutive_failures
        ):
            reason = (
                f"Stopping — {consecutive_failures} consecutive failures "
                f"(threshold: {self.max_consecutive_failures}). "
                f"Something is systematically wrong. {progress_str}"
            )
            return True, reason

        # Check 2 — failure rate
        if processed >= self.min_skills_before_rate_check:
            failure_rate = summary["failed"] / processed
            if failure_rate > self.max_failure_rate:
                reason = (
                    f"Stopping — failure rate {failure_rate:.1%} exceeds "
                    f"threshold {self.max_failure_rate:.1%}. {progress_str}"
                )
                return True, reason

        # Check 3 — absolute failure count
        if summary["failed"] >= self.max_absolute_failures:
            reason = (
                f"Stopping — absolute failure count {summary['failed']} "
                f"exceeds threshold {self.max_absolute_failures}. {progress_str}"
            )
            return True, reason

        return False, ""

    def _process_skill(
        self,
        session: Session,
        repo: AnalysisRepository,
        analysis_run_id: int,
        skill: dict[str, Any],
        index: int,
        total: int,
        started_at: float,
        force: bool = False,
    ) -> bool:
        temp_path: Path | None = None
        try:
            temp_path = self._make_temp_dir(skill["id"])
            self.logger.info(
                "[%s/%s] skill_id=%s %s/%s v%s downloading artifact artifact_uri=%s",
                index,
                total,
                skill["id"],
                skill["source"],
                skill["source_id"],
                skill["version"],
                skill["artifact_uri"],
            )
            download_result = self.artifact_loader.download_prefix(skill["artifact_uri"], temp_path)

            if not force:
                sibling_ids = repo.find_sibling_skill_ids(
                    skill["id"], skill["source"], skill["source_id"],
                    skill["version"], skill["artifact_hash"],
                )
                if sibling_ids:
                    content_hash = compute_content_hash(download_result.root_path)
                    if repo.has_successful_result_for_content_hash(
                        sibling_ids, content_hash,
                        self.analyzer.name, self.analyzer.version,
                    ):
                        self.logger.info(
                            "[%s/%s] skill_id=%s skipped: same developer content as "
                            "sibling (collector metadata only difference) elapsed=%.1fs",
                            index, total, skill["id"], elapsed_seconds(started_at),
                        )
                        return True
                else:
                    content_hash = compute_content_hash(download_result.root_path)
            else:
                content_hash = compute_content_hash(download_result.root_path)

            self.logger.info(
                "[%s/%s] skill_id=%s downloaded objects=%s bytes=%s elapsed=%.1fs",
                index,
                total,
                skill["id"],
                download_result.object_count,
                download_result.bytes_downloaded,
                elapsed_seconds(started_at),
            )

            report = self.analyzer.analyze(download_result.root_path)
            result_json = {
                **report.result_json,
                "artifact": {
                    "uri": skill["artifact_uri"],
                    "hash": skill["artifact_hash"],
                    "content_hash": content_hash,
                    "downloaded_objects": download_result.object_count,
                    "downloaded_bytes": download_result.bytes_downloaded,
                },
            }
            repo.create_result(
                skill_id=skill["id"],
                analysis_run_id=analysis_run_id,
                status=report.status,
                risk_level=report.risk_level,
                summary=report.summary,
                result_json=result_json,
                findings=report.findings,
                artifact_hash=skill["artifact_hash"],
                analyzer_name=self.analyzer.name,
                analyzer_version=self.analyzer.version,
            )
            session.commit()
            self.logger.info(
                "[%s/%s] skill_id=%s analyzed risk=%s findings=%s elapsed=%.1fs",
                index,
                total,
                skill["id"],
                report.risk_level,
                len(report.findings),
                elapsed_seconds(started_at),
            )
            return True
        except Exception as exc:
            session.rollback()
            self.logger.error(
                "[%s/%s] skill_id=%s failed artifact_uri=%s error_type=%s error=%s elapsed=%.1fs",
                index,
                total,
                skill["id"],
                skill["artifact_uri"],
                type(exc).__name__,
                exc,
                elapsed_seconds(started_at),
            )
            self.logger.debug(
                "[%s/%s] skill_id=%s failure details",
                index,
                total,
                skill["id"],
                exc_info=True,
            )
            repo.create_result(
                skill_id=skill["id"],
                analysis_run_id=analysis_run_id,
                status="failed",
                risk_level="unknown",
                summary=f"Static analysis failed: {exc}",
                result_json={
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                    "artifact": {
                        "uri": skill["artifact_uri"],
                        "hash": skill["artifact_hash"],
                        "content_hash": content_hash if "content_hash" in locals() else None,
                    },
                },
                findings=[],
                artifact_hash=skill["artifact_hash"],
                analyzer_name=self.analyzer.name,
                analyzer_version=self.analyzer.version,
            )
            session.commit()
            return False
        finally:
            if temp_path is not None:
                self._cleanup_temp_dir(temp_path)

    def _make_temp_dir(self, skill_id: int) -> Path:
        tmp_dir = self.settings.artifact_tmp_dir / "static"
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


def skill_to_dict(skill: Skill) -> dict[str, Any]:
    return {
        "id": skill.id,
        "source": skill.source,
        "source_id": skill.source_id,
        "name": skill.name,
        "version": skill.version,
        "artifact_uri": skill.artifact_uri,
        "artifact_hash": skill.artifact_hash,
    }


def elapsed_seconds(started_at: float) -> float:
    return time.monotonic() - started_at


def compute_content_hash(root_path: Path) -> str:
    """SHA-256 hash of developer-authored files only.

    Excludes COLLECTOR_METADATA_FILES so that two artifact snapshots
    that differ only by skill-card.md or _detail.json produce the
    same content hash and are not re-analyzed unnecessarily.
    """
    hasher = hashlib.sha256()
    for path in sorted(root_path.rglob("*")):
        if path.is_file() and path.name not in COLLECTOR_METADATA_FILES:
            relative = path.relative_to(root_path).as_posix()
            hasher.update(relative.encode())
            hasher.update(path.read_bytes())
    return hasher.hexdigest()
