"""Tests for static pipeline bug fixes.

Covers:
1. IPv6 URL handling in scan_urls (matching.py)
2. List-type dependencies in extract_package_json_context (extraction.py)
3. Separate tmp directories per pipeline
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch


# Fix 1: IPv6 URL handling

def test_scan_urls_handles_invalid_ipv6_url():
    """scan_urls should not raise on malformed IPv6 URLs."""
    from analyzers.static.rules.matching import scan_urls

    text = "connect to http://[::invalid]/path for service"
    external_urls = []
    scan_urls("test.md", text, external_urls)
    for entry in external_urls:
        assert "domain" in entry
        assert isinstance(entry["domain"], str)


def test_scan_urls_ipv6_domain_is_empty_string_on_error():
    """scan_urls should store empty domain string for malformed IPv6 URLs."""
    from analyzers.static.rules.matching import scan_urls

    text = "http://[::1invalid]/api"
    external_urls = []
    scan_urls("test.sh", text, external_urls)
    for entry in external_urls:
        assert isinstance(entry["domain"], str)


def test_scan_urls_valid_url_still_works():
    """scan_urls should still work correctly for normal URLs."""
    from analyzers.static.rules.matching import scan_urls

    text = "connect to https://api.example.com/v1/endpoint"
    external_urls = []
    scan_urls("test.sh", text, external_urls)
    domains = [e["domain"] for e in external_urls]
    assert any("example.com" in d for d in domains)


# Fix 2: List-type dependencies

def test_extract_package_json_list_dependencies():
    """extract_package_json_context should handle list-type dependencies."""
    from analyzers.static.extraction import extract_package_json_context

    text = '{"name": "test", "dependencies": ["express", "lodash"]}'
    indicators = {"dependency_or_install_script": {"count": 0, "evidence": []}}
    result = extract_package_json_context("package.json", text, indicators)
    assert "dependencies" in result
    assert result["dependencies"] == []


def test_extract_package_json_list_dev_dependencies():
    """extract_package_json_context should handle list-type devDependencies."""
    from analyzers.static.extraction import extract_package_json_context

    text = '{"name": "test", "devDependencies": ["jest", "eslint"]}'
    indicators = {"dependency_or_install_script": {"count": 0, "evidence": []}}
    result = extract_package_json_context("package.json", text, indicators)
    assert result["dev_dependencies"] == []


def test_extract_package_json_normal_dict_dependencies():
    """extract_package_json_context should still work with normal dict dependencies."""
    from analyzers.static.extraction import extract_package_json_context

    text = '{"name": "test", "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}}'
    indicators = {"dependency_or_install_script": {"count": 0, "evidence": []}}
    result = extract_package_json_context("package.json", text, indicators)
    assert "express" in result["dependencies"]
    assert "lodash" in result["dependencies"]


def test_extract_package_json_null_dependencies():
    """extract_package_json_context should handle null dependencies."""
    from analyzers.static.extraction import extract_package_json_context

    text = '{"name": "test", "dependencies": null}'
    indicators = {"dependency_or_install_script": {"count": 0, "evidence": []}}
    result = extract_package_json_context("package.json", text, indicators)
    assert result["dependencies"] == []


# Fix 3: Separate tmp directories per pipeline

def test_static_pipeline_uses_static_subdir():
    """StaticAnalysisPipeline should use tmp/static/ subdirectory."""
    import shutil
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
    )
    tmp_path = pipeline._make_temp_dir(skill_id=1)
    assert "static" in str(tmp_path)
    shutil.rmtree(settings.artifact_tmp_dir)


def test_dynamic_pipeline_uses_dynamic_subdir():
    """DynamicAnalysisPipeline should use tmp/dynamic/ subdirectory."""
    import shutil
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
    )
    tmp_path = pipeline._make_temp_dir(skill_id=1)
    assert "dynamic" in str(tmp_path)
    shutil.rmtree(settings.artifact_tmp_dir)


def test_llm_pipeline_uses_llm_subdir():
    """LLMAnalysisPipeline should use tmp/llm/ subdirectory."""
    import shutil
    from pipeline.llm_pipeline import LLMAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"
    settings.api_key = "test"

    pipeline = LLMAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
    )
    tmp_path = pipeline._make_temp_dir(skill_id=1)
    assert "llm" in str(tmp_path)
    shutil.rmtree(settings.artifact_tmp_dir)


def test_pipelines_use_separate_subdirs():
    """Static, LLM, and dynamic pipelines should each use different subdirs."""
    import shutil
    from pipeline.static_pipeline import StaticAnalysisPipeline
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline
    from pipeline.llm_pipeline import LLMAnalysisPipeline

    base_tmp = Path(tempfile.mkdtemp())

    def make_settings():
        s = MagicMock()
        s.artifact_tmp_dir = base_tmp
        s.s3_bucket = "test"
        s.aws_region = "us-east-1"
        s.api_key = "test"
        return s

    static_p = StaticAnalysisPipeline(settings=make_settings(), session_factory=MagicMock())
    dynamic_p = DynamicAnalysisPipeline(settings=make_settings(), session_factory=MagicMock())
    llm_p = LLMAnalysisPipeline(settings=make_settings(), session_factory=MagicMock())

    static_tmp = static_p._make_temp_dir(1)
    dynamic_tmp = dynamic_p._make_temp_dir(1)
    llm_tmp = llm_p._make_temp_dir(1)

    assert "static" in str(static_tmp)
    assert "dynamic" in str(dynamic_tmp)
    assert "llm" in str(llm_tmp)

    assert str(static_tmp.parent) != str(dynamic_tmp.parent)
    assert str(dynamic_tmp.parent) != str(llm_tmp.parent)
    assert str(static_tmp.parent) != str(llm_tmp.parent)

    shutil.rmtree(base_tmp)

def test_static_pipeline_tmp_parent_is_artifact_tmp_dir():
    """Static pipeline tmp dir parent should be artifact_tmp_dir/static."""
    import shutil
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    base = Path(tempfile.mkdtemp())
    settings.artifact_tmp_dir = base
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(settings=settings, session_factory=MagicMock())
    tmp_path = pipeline._make_temp_dir(skill_id=1)

    assert tmp_path.parent == base / "static"
    shutil.rmtree(base)


def test_dynamic_pipeline_tmp_parent_is_artifact_tmp_dir():
    """Dynamic pipeline tmp dir parent should be artifact_tmp_dir/dynamic."""
    import shutil
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline

    settings = MagicMock()
    base = Path(tempfile.mkdtemp())
    settings.artifact_tmp_dir = base
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    pipeline = DynamicAnalysisPipeline(settings=settings, session_factory=MagicMock())
    tmp_path = pipeline._make_temp_dir(skill_id=1)

    assert tmp_path.parent == base / "dynamic"
    shutil.rmtree(base)


def test_llm_pipeline_tmp_parent_is_artifact_tmp_dir():
    """LLM pipeline tmp dir parent should be artifact_tmp_dir/llm."""
    import shutil
    from pipeline.llm_pipeline import LLMAnalysisPipeline

    settings = MagicMock()
    base = Path(tempfile.mkdtemp())
    settings.artifact_tmp_dir = base
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"
    settings.api_key = "test"

    pipeline = LLMAnalysisPipeline(settings=settings, session_factory=MagicMock())
    tmp_path = pipeline._make_temp_dir(skill_id=1)

    assert tmp_path.parent == base / "llm"
    shutil.rmtree(base)


def test_static_subdir_created_automatically():
    """Static pipeline should create the static subdir if it doesn't exist."""
    import shutil
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    base = Path(tempfile.mkdtemp())
    settings.artifact_tmp_dir = base
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(settings=settings, session_factory=MagicMock())
    assert not (base / "static").exists()
    pipeline._make_temp_dir(skill_id=1)
    assert (base / "static").exists()
    shutil.rmtree(base)

# Fix 4: Failure threshold


def test_static_pipeline_stops_on_consecutive_failures():
    """StaticAnalysisPipeline should stop when consecutive failures exceed threshold."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    session = MagicMock()
    session_factory = MagicMock()
    session_factory.return_value.__enter__ = MagicMock(return_value=session)
    session_factory.return_value.__exit__ = MagicMock(return_value=False)

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_candidate_skills.return_value = [MagicMock() for _ in range(20)]
    repo.has_successful_result.return_value = False

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
        max_consecutive_failures=3,
        max_failure_rate=0.9,
        min_processed_before_consecutive_check=0,
        max_absolute_failures=1000,
    )

    with patch("pipeline.static_pipeline.AnalysisRepository", return_value=repo), \
         patch.object(pipeline, "_process_skill", return_value=False):
        summary = pipeline.run()

    assert summary["failed"] == 3
    assert "stop_reason" in summary
    assert "consecutive" in summary["stop_reason"].lower()


def test_static_pipeline_stops_on_high_failure_rate():
    """StaticAnalysisPipeline should stop when failure rate exceeds threshold."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    session = MagicMock()
    session_factory = MagicMock()
    session_factory.return_value.__enter__ = MagicMock(return_value=session)
    session_factory.return_value.__exit__ = MagicMock(return_value=False)

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_candidate_skills.return_value = [MagicMock() for _ in range(30)]
    repo.has_successful_result.return_value = False

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
        max_consecutive_failures=100,
        max_failure_rate=0.5,
        min_skills_before_rate_check=20,
    )

    # Alternate success/failure but mostly failures
    results = [False, False, True, False, False, True, False, False, False, False] * 3

    with patch("pipeline.static_pipeline.AnalysisRepository", return_value=repo), \
         patch.object(pipeline, "_process_skill", side_effect=results):
        summary = pipeline.run()

    assert "stop_reason" in summary
    assert "failure rate" in summary["stop_reason"].lower()


def test_check_failure_threshold_consecutive():
    """_check_failure_threshold should return stop=True on consecutive failures."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"
    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=5,
    )

    summary = {"succeeded": 100, "failed": 5}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=5)
    assert should_stop is True
    assert "consecutive" in reason.lower()


def test_check_failure_threshold_not_triggered():
    """_check_failure_threshold should return stop=False when thresholds not exceeded."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"
    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=10,
        max_failure_rate=0.5,
    )

    summary = {"succeeded": 8, "failed": 2}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=2)
    assert should_stop is False
    assert reason == ""


def test_dynamic_pipeline_stops_on_consecutive_failures():
    """DynamicAnalysisPipeline should stop when consecutive failures exceed threshold."""
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test"
    settings.aws_region = "us-east-1"

    session = MagicMock()
    session_factory = MagicMock()
    session_factory.return_value.__enter__ = MagicMock(return_value=session)
    session_factory.return_value.__exit__ = MagicMock(return_value=False)

    repo = MagicMock()
    repo.create_run.return_value.id = 1
    repo.select_qualified_skills.return_value = [MagicMock() for _ in range(20)]

    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=session_factory,
        max_consecutive_failures=3,
        max_failure_rate=0.9,
        min_processed_before_consecutive_check=0,
        max_absolute_failures=1000,
    )
    pipeline._docker_cleanup = MagicMock()
    pipeline._check_docker_health = MagicMock(return_value=True)

    with patch("pipeline.dynamic_pipeline.DynamicAnalysisRepository", return_value=repo), \
         patch.object(pipeline, "_process_skill", return_value=False), \
         patch("pipeline.dynamic_pipeline.shutil.disk_usage",
               return_value=(58 * 1024**3, 29 * 1024**3, 29 * 1024**3)), \
         patch("pipeline.dynamic_pipeline.subprocess.run",
               return_value=MagicMock(returncode=0)):
        summary = pipeline.run()

    assert summary["failed"] == 3
    assert "stop_reason" in summary
    assert "consecutive" in summary["stop_reason"].lower()

def test_consecutive_check_not_triggered_before_min_processed():
    """Consecutive failure check should not trigger before min_processed_before_consecutive_check."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=5,
        min_processed_before_consecutive_check=100,
    )

    # 10 consecutive failures but only 10 processed — below min_processed threshold
    summary = {"succeeded": 0, "failed": 10}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=10)
    assert should_stop is False


def test_consecutive_check_triggers_after_min_processed():
    """Consecutive failure check should trigger after min_processed_before_consecutive_check."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=5,
        min_processed_before_consecutive_check=100,
    )

    # 10 consecutive failures and 110 processed — above min_processed threshold
    summary = {"succeeded": 100, "failed": 10}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=10)
    assert should_stop is True
    assert "consecutive" in reason.lower()


def test_absolute_failure_count_triggers_stop():
    """Pipeline should stop when absolute failure count exceeds threshold."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=100,
        max_failure_rate=0.9,
        max_absolute_failures=50,
    )

    # 50 failures but consecutive=1 and rate=5% — only absolute count triggers
    summary = {"succeeded": 950, "failed": 50}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=1)
    assert should_stop is True
    assert "absolute" in reason.lower()


def test_absolute_failure_not_triggered_below_threshold():
    """Pipeline should not stop when absolute failures below threshold."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=100,
        max_failure_rate=0.9,
        max_absolute_failures=50,
    )

    summary = {"succeeded": 950, "failed": 49}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=1)
    assert should_stop is False


def test_stop_reason_contains_progress_info():
    """Stop reason should include progress information."""
    from pipeline.static_pipeline import StaticAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = StaticAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=5,
        min_processed_before_consecutive_check=0,
    )

    summary = {"succeeded": 100, "failed": 10}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=5)
    assert should_stop is True
    assert "100" in reason  # succeeded count
    assert "10" in reason   # failed count
    assert "110" in reason  # processed count


def test_dynamic_pipeline_absolute_failure_threshold():
    """DynamicAnalysisPipeline should stop when absolute failure count exceeded."""
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=100,
        max_failure_rate=0.9,
        max_absolute_failures=50,
    )

    summary = {"succeeded": 500, "failed": 50}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=1)
    assert should_stop is True
    assert "absolute" in reason.lower()


def test_dynamic_pipeline_consecutive_not_triggered_before_min():
    """DynamicAnalysisPipeline consecutive check should respect min_processed."""
    from pipeline.dynamic_pipeline import DynamicAnalysisPipeline

    settings = MagicMock()
    settings.artifact_tmp_dir = Path(tempfile.mkdtemp())
    settings.s3_bucket = "test-bucket"
    settings.aws_region = "us-east-1"

    pipeline = DynamicAnalysisPipeline(
        settings=settings,
        session_factory=MagicMock(),
        max_consecutive_failures=5,
        min_processed_before_consecutive_check=100,
        max_absolute_failures=1000,
    )

    # Only 10 processed, 10 consecutive — below min_processed threshold
    summary = {"succeeded": 0, "failed": 10}
    should_stop, reason = pipeline._check_failure_threshold(summary, consecutive_failures=10)
    assert should_stop is False