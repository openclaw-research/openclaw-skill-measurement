from __future__ import annotations

import logging
import os
import shutil
import tempfile
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from analyzers.dynamic.analyzer import DynamicAnalyzer
from analyzers.dynamic.llm_interpreter import LLMDailyLimitExceeded
from artifacts.s3_loader import S3ArtifactLoader
from config import Settings
from db.dynamic_repository import DynamicAnalysisRepository


ANALYZER_NAME = "dynamic"
ANALYZER_VERSION = "3"


def _extract_skill_summary(skill_md: str, max_chars: int = 500) -> str:
    """Extract security-relevant summary from SKILL.md.

    Skips code blocks, images, badges, and verbose sections like
    Examples/Installation to keep token cost low while preserving
    the skill's stated purpose, features, and agent instructions.
    """
    lines = skill_md.strip().splitlines()
    summary = []
    chars = 0
    in_code_block = False

    for line in lines:
        stripped = line.strip()

        # Track code blocks — skip them
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        # Skip empty, horizontal rules, image links, badge lines
        if not stripped or stripped == "---":
            continue
        if stripped.startswith("![") or stripped.startswith("[!["):
            continue

        # Stop at sections not relevant to security judgment
        if any(stripped.lower().startswith(f"## {s}") for s in (
            "example", "install", "setup", "usage", "changelog",
            "license", "contributing", "faq", "troubleshoot",
        )):
            break

        summary.append(stripped)
        chars += len(stripped)
        if chars >= max_chars:
            break

    return "\n".join(summary)


class DynamicAnalysisPipeline:
    """Pipeline that runs dynamic analysis on LLM-confirmed critical/high
    shell-script skills from the corpus.

    Mirrors the structure of StaticAnalysisPipeline and LLMAnalysisPipeline.
    Each skill is:
      1. Downloaded from S3 to a temp directory
      2. Analyzed by DynamicAnalyzer (Docker + strace + LLM interpretation)
      3. Results stored in dynamic_analysis_results table
      4. Temp directory cleaned up immediately
    """

    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        artifact_loader: S3ArtifactLoader | None = None,
        logger: logging.Logger | None = None,
        timeout_secs: int = 30,
        total_timeout_secs: int = 120,
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
        self.logger = logger or logging.getLogger("openclaw.dynamic_analysis")
        self.timeout_secs = timeout_secs
        self.total_timeout_secs = total_timeout_secs

    def run(
        self,
        limit: int | None = None,
        force: bool = False,
        progress_every: int = 25,
    ) -> dict[str, Any]:
        started_at = time.monotonic()

        # Register signal handlers for graceful Docker cleanup on kill
        self._register_signal_handlers()

        # Clean up any orphaned Docker containers and images from previous runs
        self._docker_cleanup()

        with self.session_factory() as session:
            repo = DynamicAnalysisRepository(session)
            run = repo.create_run(
                analyzer_name=ANALYZER_NAME,
                analyzer_version=ANALYZER_VERSION,
                config_json={
                    "limit": limit,
                    "force": force,
                    "timeout_secs": self.timeout_secs,
                    "total_timeout_secs": self.total_timeout_secs,
                    "progress_every": progress_every,
                },
            )
            run_id = run.id
            session.commit()

            candidates = repo.select_qualified_skills(
                analyzer_name=ANALYZER_NAME,
                analyzer_version=ANALYZER_VERSION,
                limit=limit,
                force=force,
            )

            repo.set_expected_count(run_id, len(candidates))
            session.commit()

            _, _, free = shutil.disk_usage("/")
            free_gb = free / (1024 ** 3)
            summary = {
                "dynamic_analysis_run_id": run_id,
                "selected": len(candidates),
                "skipped": 0,
                "succeeded": 0,
                "failed": 0,
                "elapsed_seconds": 0.0,
                "disk_free_gb_start": round(free_gb, 1),
                "analyzer_name": ANALYZER_NAME,
                "analyzer_version": ANALYZER_VERSION,
            }

            self.logger.info(
                "Starting dynamic analysis run #%s analyzer=%s v%s selected=%s disk_free=%.1fGB",
                run_id, ANALYZER_NAME, ANALYZER_VERSION, len(candidates), free_gb,
            )

            try:
                total = len(candidates)
                consecutive_failures = 0
                for index, row in enumerate(candidates, start=1):
                    if not self._check_disk_space(min_gb=10.0):
                        self.logger.error(
                            "Stopping pipeline early at skill %d/%d due to low disk space",
                            index, total,
                        )
                        break
                    if not self._check_docker_health():
                        self.logger.error(
                            "Stopping pipeline early at skill %d/%d — Docker daemon not responding",
                            index, total,
                        )
                        break
                    if self._process_skill(
                        session, repo, run_id, row, index, total, started_at
                    ):
                        summary["succeeded"] += 1
                        consecutive_failures = 0
                    else:
                        summary["failed"] += 1
                        consecutive_failures += 1

                    self._periodic_docker_cleanup(
                        every_n=5,
                        processed=summary["succeeded"] + summary["failed"],
                    )

                    should_stop, stop_reason = self._check_failure_threshold(
                        summary, consecutive_failures
                    )
                    if should_stop:
                        self.logger.error(stop_reason)
                        repo.finish_run(run_id, "failed", stop_reason)
                        session.commit()
                        summary["stop_reason"] = stop_reason
                        return summary

                    processed = summary["succeeded"] + summary["failed"]
                    if (
                        progress_every > 0
                        and processed % progress_every == 0
                        and processed < total
                    ):
                        _, _, free = shutil.disk_usage("/")
                        free_gb = free / (1024 ** 3)
                        self.logger.info(
                            "Progress run #%s processed=%s/%s succeeded=%s failed=%s "
                            "disk_free=%.1fGB elapsed=%.1fs",
                            run_id, processed, total,
                            summary["succeeded"], summary["failed"],
                            free_gb, elapsed_seconds(started_at),
                        )

                summary["elapsed_seconds"] = elapsed_seconds(started_at)
                repo.finish_run(run_id, "success")
                session.commit()
                _, _, free = shutil.disk_usage("/")
                free_gb = free / (1024 ** 3)
                self.logger.info(
                    "Completed run #%s selected=%s succeeded=%s failed=%s "
                    "disk_free=%.1fGB elapsed=%.1fs",
                    run_id, summary["selected"], summary["succeeded"],
                    summary["failed"], free_gb, summary["elapsed_seconds"],
                )
                return summary

            except Exception as exc:
                session.rollback()
                repo.finish_run(run_id, "failed", str(exc))
                session.commit()
                self.logger.error(
                    "Dynamic analysis run #%s failed error_type=%s error=%s elapsed=%.1fs",
                    run_id, type(exc).__name__, exc, elapsed_seconds(started_at),
                )
                self.logger.debug("Dynamic analysis run failure details", exc_info=True)
                raise

    def _register_signal_handlers(self) -> None:
        """Register signal handlers to clean up Docker on SIGTERM/SIGINT."""
        def _handler(signum, frame):
            self.logger.warning(
                "Received signal %s — running emergency Docker cleanup before exit",
                signum,
            )
            self._emergency_docker_cleanup()
            raise SystemExit(1)

        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)

    def _emergency_docker_cleanup(self) -> None:
        """Stop and remove all running Docker containers on pipeline exit."""
        try:
            # Stop all running containers
            result = subprocess.run(
                ["docker", "ps", "-q"],
                capture_output=True, text=True, timeout=10,
            )
            container_ids = result.stdout.strip().split()
            if container_ids:
                self.logger.warning(
                    "Stopping %d running Docker containers", len(container_ids)
                )
                subprocess.run(
                    ["docker", "stop"] + container_ids,
                    capture_output=True, timeout=30,
                )
                subprocess.run(
                    ["docker", "rm"] + container_ids,
                    capture_output=True, timeout=30,
                )
            # Prune dangling images
            subprocess.run(
                ["docker", "image", "prune", "-f"],
                capture_output=True, timeout=30,
            )
            self.logger.warning("Emergency Docker cleanup completed")
        except Exception as exc:
            self.logger.error("Emergency Docker cleanup failed: %s", exc)

    def _docker_cleanup(self) -> None:
        """Remove orphaned Docker containers and dangling images."""
        try:
            subprocess.run(
                ["docker", "container", "prune", "-f"],
                capture_output=True, timeout=30,
            )
            subprocess.run(
                ["docker", "image", "prune", "-f"],
                capture_output=True, timeout=30,
            )
            self.logger.info("Docker cleanup completed before run")
        except Exception as exc:
            self.logger.warning("Docker cleanup failed: %s", exc)

    def _check_docker_health(self) -> bool:
        """Return False if Docker daemon is not responding."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception as exc:
            self.logger.error("Docker health check failed: %s", exc)
            return False

    def _check_disk_space(self, min_gb: float = 10.0) -> bool:
        """Return False if available disk space is below threshold.
        
        Also runs Docker prune if space is getting low to prevent
        orphaned images from filling the disk.
        """
        total, used, free = shutil.disk_usage("/")
        free_gb = free / (1024 ** 3)

        # Proactive cleanup when space is getting low (< 15GB)
        if free_gb < 15.0:
            self.logger.warning(
                "Disk space getting low (%.1fGB free) — running proactive Docker cleanup",
                free_gb,
            )
            try:
                subprocess.run(
                    ["docker", "image", "prune", "-f"],
                    capture_output=True, timeout=30,
                )
                subprocess.run(
                    ["docker", "container", "prune", "-f"],
                    capture_output=True, timeout=30,
                )
                # Re-check after cleanup
                total, used, free = shutil.disk_usage("/")
                free_gb = free / (1024 ** 3)
                self.logger.info("After cleanup: %.1fGB free", free_gb)
            except Exception as exc:
                self.logger.warning("Proactive Docker cleanup failed: %s", exc)

        if free_gb < min_gb:
            self.logger.error(
                "Disk space critically low: %.1fGB free (minimum %.1fGB) — stopping pipeline",
                free_gb, min_gb,
            )
            return False
        return True

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

    def _periodic_docker_cleanup(self, every_n: int = 5, processed: int = 0) -> None:
        """Periodically stop/remove all containers and run sudo docker system prune.

        Called every N skills synchronously — no new skill starts while running.
        Uses sudo -n (passwordless sudo required) to run
        docker system prune -af which cleans overlay2 layers that accumulate
        invisibly and are not removed by docker image prune alone.
        """
        if processed == 0 or processed % every_n != 0:
            return
        try:
            # Stop and remove any running skill containers
            containers = subprocess.run(
                ["docker", "ps", "-q"],
                capture_output=True, text=True, timeout=10,
            )
            container_ids = containers.stdout.strip().split()
            if container_ids:
                self.logger.warning(
                    "Periodic cleanup: stopping %d running containers",
                    len(container_ids),
                )
                subprocess.run(
                    ["docker", "stop"] + container_ids,
                    capture_output=True, timeout=30,
                )
                subprocess.run(
                    ["docker", "rm"] + container_ids,
                    capture_output=True, timeout=30,
                )

            # Remove all stopped containers
            subprocess.run(
                ["docker", "container", "prune", "-f"],
                capture_output=True, timeout=30,
            )

            # Aggressive prune with sudo — cleans overlay2 layers
            prune = subprocess.run(
                ["sudo", "-n", "docker", "system", "prune", "-af"],
                capture_output=True, timeout=120,
            )
            if prune.returncode == 0:
                self.logger.info("Periodic Docker cleanup completed (sudo system prune)")
            else:
                # Fallback to non-sudo prune
                subprocess.run(
                    ["docker", "image", "prune", "-f"],
                    capture_output=True, timeout=30,
                )
                self.logger.warning(
                    "Periodic Docker sudo prune failed (rc=%d) — used fallback prune",
                    prune.returncode,
                )

            # Rebuild sandbox image if it was removed by prune
            sandbox_check = subprocess.run(
                ["docker", "image", "inspect", "openclaw-sandbox:latest"],
                capture_output=True, timeout=10,
            )
            if sandbox_check.returncode != 0:
                self.logger.info("Rebuilding openclaw-sandbox after prune")
                subprocess.run(
                    ["docker", "build", "-t", "openclaw-sandbox:latest",
                     "-f", "docker/Dockerfile.sandbox", "docker/"],
                    capture_output=True, timeout=120,
                )

        except Exception as exc:
            self.logger.warning("Periodic Docker cleanup failed: %s", exc)

    def _process_skill(
        self,
        session: Session,
        repo: DynamicAnalysisRepository,
        run_id: int,
        row: Any,
        index: int,
        total: int,
        started_at: float,
    ) -> bool:
        temp_path: Path | None = None
        try:
            temp_path = self._make_temp_dir(row.skill_id)
            self.logger.info(
                "[%s/%s] skill_id=%s source_id=%s downloading artifact_uri=%s",
                index, total, row.skill_id, row.source_id, row.artifact_uri,
            )

            download_result = self.artifact_loader.download_prefix(
                row.artifact_uri, temp_path
            )
            self.logger.info(
                "[%s/%s] skill_id=%s downloaded objects=%s bytes=%s elapsed=%.1fs",
                index, total, row.skill_id,
                download_result.object_count, download_result.bytes_downloaded,
                elapsed_seconds(started_at),
            )

            # Build LLM prior from Layer 2 results
            llm_prior = None
            if row.llm_explanation:
                llm_prior = {
                    "risk_level":       row.llm_risk,
                    "explanation":      (row.llm_explanation or "")[:800],
                    "human_escalation": bool(getattr(row, "human_escalation", False)),
                }

            # Read SKILL.md for LLM context — extract security-relevant summary
            skill_md_path = temp_path / "SKILL.md"
            if skill_md_path.exists():
                raw_md = skill_md_path.read_text(encoding="utf-8", errors="ignore")
                skill_purpose = _extract_skill_summary(raw_md, max_chars=500)
            else:
                skill_purpose = row.source_id

            analyzer = DynamicAnalyzer(
                timeout_secs=self.timeout_secs,
                total_timeout_secs=self.total_timeout_secs,
                skill_purpose=skill_purpose,
                llm_prior=llm_prior,
                static_risk=row.static_risk or "unknown",
            )
            try:
                report = analyzer.analyze(download_result.root_path)
            except LLMDailyLimitExceeded:
                self.logger.error(
                    "LLM daily limit reached — both Groq keys exhausted at skill %s "
                    "run #%s succeeded=%s — stopping pipeline gracefully",
                    row.source_id, run_id, summary["succeeded"],
                )
                repo.finish_run(run_id, "success")
                session.commit()
                return summary

            llm = report.result_json.get("llm_interpretation")

            repo.create_result(
                skill_id=row.skill_id,
                dynamic_analysis_run_id=run_id,
                status=report.status,
                verdict=report.verdict,
                verdict_reason=report.verdict_reason,
                syscall_count=report.syscall_count,
                executables_run=list(report.executables_run),
                exit_codes=report.result_json.get("exit_codes", []),
                network_calls=list(report.network_calls),
                credential_paths_read=list(report.credential_paths_read),
                sensitive_writes=list(report.sensitive_writes),
                exfiltration_domains=list(report.exfiltration_domains),
                reverse_shell_processes=list(report.reverse_shell_processes),
                result_json=report.result_json,
                static_result_id=row.static_result_id,
                llm_result_id=row.llm_result_id,
                artifact_hash=row.artifact_hash,
                analyzer_name=ANALYZER_NAME,
                analyzer_version=ANALYZER_VERSION,
                llm_purpose_fit=llm.get("purpose_fit") if llm else None,
                llm_prior_agreement=llm.get("prior_agreement") if llm else None,
                llm_unexecuted_risk=llm.get("unexecuted_risk") if llm else None,
                llm_confidence=llm.get("overall_confidence") if llm else None,
                llm_analysis_notes=llm.get("analysis_notes") if llm else None,
            )
            session.commit()

            self.logger.info(
                "[%s/%s] skill_id=%s verdict=%s syscalls=%s elapsed=%.1fs",
                index, total, row.skill_id, report.verdict,
                report.syscall_count, elapsed_seconds(started_at),
            )
            return True

        except Exception as exc:
            session.rollback()
            self.logger.error(
                "[%s/%s] skill_id=%s failed artifact_uri=%s error_type=%s error=%s elapsed=%.1fs",
                index, total, row.skill_id, row.artifact_uri,
                type(exc).__name__, exc, elapsed_seconds(started_at),
            )
            self.logger.debug(
                "[%s/%s] skill_id=%s failure details",
                index, total, row.skill_id, exc_info=True,
            )
            try:
                repo.create_result(
                    skill_id=row.skill_id,
                    dynamic_analysis_run_id=run_id,
                    status="failed",
                    verdict="inconclusive",
                    verdict_reason=f"Pipeline error: {exc}",
                    syscall_count=0,
                    executables_run=[],
                    exit_codes=[],
                    network_calls=[],
                    credential_paths_read=[],
                    sensitive_writes=[],
                    exfiltration_domains=[],
                    reverse_shell_processes=[],
                    result_json={
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                        "artifact": {
                            "uri": row.artifact_uri,
                            "hash": row.artifact_hash,
                        },
                    },
                    static_result_id=row.static_result_id,
                    llm_result_id=row.llm_result_id,
                    artifact_hash=row.artifact_hash,
                    analyzer_name=ANALYZER_NAME,
                    analyzer_version=ANALYZER_VERSION,
                )
                session.commit()
            except Exception as store_exc:
                session.rollback()
                self.logger.error(
                    "[%s/%s] skill_id=%s failed to store failure record: %s",
                    index, total, row.skill_id, store_exc,
                )
            return False

        finally:
            if temp_path is not None:
                self._cleanup_temp_dir(temp_path)

    def _make_temp_dir(self, skill_id: int) -> Path:
        tmp_dir = self.settings.artifact_tmp_dir / "dynamic"
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
                temp_path, type(exc).__name__, exc,
            )


def elapsed_seconds(started_at: float) -> float:
    return time.monotonic() - started_at
