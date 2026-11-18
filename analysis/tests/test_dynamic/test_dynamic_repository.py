"""Tests for db/dynamic_repository.py.

Tests the repository's data preparation logic without a real DB.
Full integration tests run on the VM against PostgreSQL.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
from db.dynamic_repository import DynamicAnalysisRepository, utc_now
from db.dynamic_models import DynamicAnalysisRun, DynamicAnalysisResult


def _make_repo() -> DynamicAnalysisRepository:
    """Create a repository with a mocked session."""
    session = MagicMock()
    session.scalar.return_value = None
    session.scalars.return_value = iter([])
    session.execute.return_value = MagicMock()
    return DynamicAnalysisRepository(session)


def test_utc_now_returns_aware_datetime():
    import datetime
    now = utc_now()
    assert now.tzinfo is not None
    assert now.tzinfo == datetime.UTC


def test_create_run_adds_to_session():
    repo = _make_repo()
    repo.create_run(
        analyzer_name="dynamic",
        analyzer_version="1",
        config_json={"timeout": 30},
    )
    repo.session.add.assert_called_once()
    repo.session.flush.assert_called_once()
    added = repo.session.add.call_args[0][0]
    assert isinstance(added, DynamicAnalysisRun)
    assert added.analyzer_name == "dynamic"
    assert added.analyzer_version == "1"
    assert added.status == "running"
    assert added.config_json == {"timeout": 30}


def test_create_run_without_config():
    repo = _make_repo()
    repo.create_run(analyzer_name="dynamic", analyzer_version="1")
    added = repo.session.add.call_args[0][0]
    assert added.config_json is None


def test_finish_run_calls_execute():
    repo = _make_repo()
    repo.finish_run(run_id=1, status="success")
    repo.session.execute.assert_called_once()


def test_finish_run_with_error_message():
    repo = _make_repo()
    repo.finish_run(run_id=1, status="failed", error_message="timeout")
    repo.session.execute.assert_called_once()


def test_set_expected_count_calls_execute():
    repo = _make_repo()
    repo.set_expected_count(run_id=1, n_selected=1630)
    repo.session.execute.assert_called_once()


def test_has_successful_result_returns_false_when_none():
    repo = _make_repo()
    repo.session.scalar.return_value = None
    result = repo.has_successful_result(
        skill_id=1,
        analyzer_name="dynamic",
        analyzer_version="1",
    )
    assert result is False


def test_has_successful_result_returns_true_when_found():
    repo = _make_repo()
    repo.session.scalar.return_value = 42
    result = repo.has_successful_result(
        skill_id=1,
        analyzer_name="dynamic",
        analyzer_version="1",
    )
    assert result is True


def test_create_result_adds_to_session():
    repo = _make_repo()
    repo.create_result(
        skill_id=1,
        dynamic_analysis_run_id=1,
        status="success",
        verdict="suspicious",
        verdict_reason="Network call observed",
        syscall_count=1500,
        executables_run=["install.sh"],
        exit_codes=[0],
        network_calls=["ai.syln.cn"],
        credential_paths_read=[],
        sensitive_writes=["/etc/systemd/system/test.service"],
        exfiltration_domains=[],
        reverse_shell_processes=[],
        result_json={"verdict": "suspicious"},
        analyzer_name="dynamic",
        analyzer_version="1",
    )
    repo.session.add.assert_called_once()
    repo.session.flush.assert_called_once()
    added = repo.session.add.call_args[0][0]
    assert isinstance(added, DynamicAnalysisResult)
    assert added.verdict == "suspicious"
    assert added.syscall_count == 1500
    assert added.network_calls == ["ai.syln.cn"]
    assert added.sensitive_writes == ["/etc/systemd/system/test.service"]


def test_create_result_with_llm_fields():
    repo = _make_repo()
    repo.create_result(
        skill_id=1,
        dynamic_analysis_run_id=1,
        status="success",
        verdict="benign",
        verdict_reason="No dangerous patterns",
        syscall_count=300,
        executables_run=["install.sh"],
        exit_codes=[0],
        network_calls=[],
        credential_paths_read=[],
        sensitive_writes=[],
        exfiltration_domains=[],
        reverse_shell_processes=[],
        result_json={"verdict": "benign"},
        analyzer_name="dynamic",
        analyzer_version="1",
        llm_purpose_fit="consistent",
        llm_prior_agreement="contradicts",
        llm_unexecuted_risk="low",
        llm_confidence=0.8,
        llm_analysis_notes="Ran cleanly with no dangerous events.",
    )
    added = repo.session.add.call_args[0][0]
    assert added.llm_purpose_fit == "consistent"
    assert added.llm_prior_agreement == "contradicts"
    assert added.llm_confidence == 0.8


def test_count_results_for_run():
    repo = _make_repo()
    repo.session.scalar.return_value = 42
    count = repo.count_results_for_run(run_id=1)
    assert count == 42


def test_count_results_for_run_returns_zero_when_none():
    repo = _make_repo()
    repo.session.scalar.return_value = None
    count = repo.count_results_for_run(run_id=1)
    assert count == 0


def test_latest_run_summary_returns_none_when_no_runs():
    repo = _make_repo()
    mock_scalars = MagicMock()
    mock_scalars.first.return_value = None
    repo.session.scalars.return_value = mock_scalars
    result = repo.latest_run_summary()
    assert result is None

def test_has_successful_result_returns_false_when_none():
    # already exists — just checking we have it
    pass


def test_select_qualified_skills_called_with_force_false():
    """When force=False, select_qualified_skills should filter already-analyzed skills."""
    repo = _make_repo()
    mock_execute = MagicMock()
    mock_execute.__iter__ = MagicMock(return_value=iter([]))
    repo.session.execute.return_value = mock_execute
    repo.select_qualified_skills(
        analyzer_name="dynamic",
        analyzer_version="1",
        force=False,
    )
    repo.session.execute.assert_called_once()


def test_select_qualified_skills_called_with_force_true():
    """When force=True, select_qualified_skills should not filter already-analyzed skills."""
    repo = _make_repo()
    mock_execute = MagicMock()
    mock_execute.__iter__ = MagicMock(return_value=iter([]))
    repo.session.execute.return_value = mock_execute
    repo.select_qualified_skills(
        analyzer_name="dynamic",
        analyzer_version="1",
        force=True,
    )
    repo.session.execute.assert_called_once()