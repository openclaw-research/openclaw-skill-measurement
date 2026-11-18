"""Tests for db/dynamic_models.py.

Verifies the DynamicAnalysisRun and DynamicAnalysisResult model
definitions are correct — column types, nullable constraints,
foreign keys, and table names.
"""
from __future__ import annotations

from db.dynamic_models import (
    DYNAMIC_TABLES,
    DynamicAnalysisResult,
    DynamicAnalysisRun,
)


def test_dynamic_analysis_run_table_name():
    assert DynamicAnalysisRun.__tablename__ == "dynamic_analysis_runs"


def test_dynamic_analysis_result_table_name():
    assert DynamicAnalysisResult.__tablename__ == "dynamic_analysis_results"


def test_dynamic_tables_contains_both():
    table_names = {t.name for t in DYNAMIC_TABLES}
    assert "dynamic_analysis_runs" in table_names
    assert "dynamic_analysis_results" in table_names


def test_dynamic_result_has_required_columns():
    cols = {c.name for c in DynamicAnalysisResult.__table__.columns}
    required = {
        "id", "skill_id", "dynamic_analysis_run_id",
        "static_result_id", "llm_result_id",
        "analyzer_name", "analyzer_version",
        "status", "verdict", "verdict_reason",
        "syscall_count", "executables_run", "exit_codes",
        "network_calls", "credential_paths_read",
        "sensitive_writes", "exfiltration_domains",
        "reverse_shell_processes",
        "llm_purpose_fit", "llm_prior_agreement",
        "llm_unexecuted_risk", "llm_confidence",
        "llm_analysis_notes",
        "result_json", "created_at",
    }
    assert required.issubset(cols)


def test_dynamic_run_has_required_columns():
    cols = {c.name for c in DynamicAnalysisRun.__table__.columns}
    required = {
        "id", "analyzer_name", "analyzer_version",
        "status", "started_at", "finished_at",
        "config_json", "error_message",
    }
    assert required.issubset(cols)


def test_dynamic_result_nullable_llm_fields():
    cols = {c.name: c for c in DynamicAnalysisResult.__table__.columns}
    assert cols["llm_purpose_fit"].nullable is True
    assert cols["llm_prior_agreement"].nullable is True
    assert cols["llm_unexecuted_risk"].nullable is True
    assert cols["llm_confidence"].nullable is True
    assert cols["llm_analysis_notes"].nullable is True


def test_dynamic_result_nullable_link_fields():
    cols = {c.name: c for c in DynamicAnalysisResult.__table__.columns}
    assert cols["static_result_id"].nullable is True
    assert cols["llm_result_id"].nullable is True


def test_dynamic_result_non_nullable_required_fields():
    cols = {c.name: c for c in DynamicAnalysisResult.__table__.columns}
    assert cols["skill_id"].nullable is False
    assert cols["dynamic_analysis_run_id"].nullable is False
    assert cols["verdict"].nullable is False
    assert cols["verdict_reason"].nullable is False
    assert cols["result_json"].nullable is False