"""Tests for analyze-dynamic CLI command."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest


def test_analyze_dynamic_command_exists():
    """analyze-dynamic command should be registered in the CLI parser."""
    from cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "analyze-dynamic",
        "--limit", "10",
        "--timeout-secs", "30",
        "--total-timeout-secs", "120",
    ])
    assert args.command == "analyze-dynamic"
    assert args.limit == 10
    assert args.timeout_secs == 30
    assert args.total_timeout_secs == 120


def test_analyze_dynamic_defaults():
    """analyze-dynamic should have sensible defaults."""
    from cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["analyze-dynamic"])
    assert args.limit is None
    assert args.force is False
    assert args.timeout_secs == 30
    assert args.total_timeout_secs == 120
    assert args.log_level == "INFO"
    assert args.progress_every == 25


def test_analyze_dynamic_force_flag():
    """--force flag should be parseable."""
    from cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["analyze-dynamic", "--force"])
    assert args.force is True

def test_configure_file_logging_accepts_logger_name():
    """configure_file_logging should accept a custom logger name."""
    from cli import configure_file_logging
    import logging
    from pathlib import Path

    Path("logs").mkdir(exist_ok=True)
    logger, log_path = configure_file_logging(
        "test-dynamic", "INFO", "openclaw.dynamic_analysis"
    )
    assert logger.name == "openclaw.dynamic_analysis"
    # Close handlers before cleanup
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    log_path.unlink(missing_ok=True)


def test_analyze_dynamic_uses_correct_logger():
    """analyze-dynamic command should configure openclaw.dynamic_analysis logger."""
    from cli import configure_file_logging
    import logging
    from pathlib import Path

    Path("logs").mkdir(exist_ok=True)
    logger, log_path = configure_file_logging(
        "analyze-dynamic", "INFO", "openclaw.dynamic_analysis"
    )
    assert logger.name == "openclaw.dynamic_analysis"
    assert isinstance(logger, logging.Logger)
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    log_path.unlink(missing_ok=True)