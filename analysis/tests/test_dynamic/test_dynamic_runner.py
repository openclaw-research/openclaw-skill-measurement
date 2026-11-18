"""Tests for analyzers/dynamic/runner.py.

Focuses on the early return paths that return 3-tuples,
and cleanup behavior after script execution.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest


def test_run_scripts_returns_three_tuple_when_sandbox_unavailable():
    """run_scripts_in_docker should return 3-tuple when sandbox image unavailable."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=False):
            result = run_scripts_in_docker(Path(tmp))

    assert len(result) == 3
    strace, executed, exit_codes = result
    assert strace == ""
    assert executed == []
    assert exit_codes == []


def test_run_scripts_returns_three_tuple_when_image_build_fails():
    """run_scripts_in_docker should return 3-tuple when skill image build fails."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=True), \
             patch("analyzers.dynamic.runner.detect_required_packages", return_value=[]), \
             patch("analyzers.dynamic.runner.has_heavy_packages", return_value=False), \
             patch("analyzers.dynamic.runner.build_skill_image", return_value=None):
            result = run_scripts_in_docker(Path(tmp))

    assert len(result) == 3
    strace, executed, exit_codes = result
    assert strace == ""
    assert executed == []
    assert exit_codes == []


def test_run_scripts_returns_three_tuple_when_no_scripts():
    """run_scripts_in_docker should return 3-tuple when no shell scripts found."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=True), \
             patch("analyzers.dynamic.runner.detect_required_packages", return_value=[]), \
             patch("analyzers.dynamic.runner.has_heavy_packages", return_value=False), \
             patch("analyzers.dynamic.runner.build_skill_image", return_value="openclaw-sandbox:latest"), \
             patch("analyzers.dynamic.runner.find_shell_scripts", return_value=[]):
            result = run_scripts_in_docker(Path(tmp))

    assert len(result) == 3
    strace, executed, exit_codes = result
    assert strace == ""
    assert executed == []
    assert exit_codes == []


def test_run_scripts_cleanup_called_after_execution():
    """cleanup_skill_image should always be called after script execution."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fake_script = Path(tmp) / "install.sh"
        fake_script.write_text("#!/bin/bash\necho hi\n")

        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=True), \
             patch("analyzers.dynamic.runner.detect_required_packages", return_value=[]), \
             patch("analyzers.dynamic.runner.has_heavy_packages", return_value=False), \
             patch("analyzers.dynamic.runner.build_skill_image", return_value="test-image:latest"), \
             patch("analyzers.dynamic.runner.find_shell_scripts", return_value=[fake_script]), \
             patch("analyzers.dynamic.runner.run_script_in_docker", return_value=("strace output", "", 0)), \
             patch("analyzers.dynamic.runner.cleanup_skill_image") as mock_cleanup, \
             patch("analyzers.dynamic.runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            run_scripts_in_docker(Path(tmp))

    mock_cleanup.assert_called_once_with("test-image:latest")


def test_run_scripts_cleanup_called_even_when_cleanup_fails():
    """docker image prune should be attempted even if cleanup_skill_image fails."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=True), \
             patch("analyzers.dynamic.runner.detect_required_packages", return_value=[]), \
             patch("analyzers.dynamic.runner.has_heavy_packages", return_value=False), \
             patch("analyzers.dynamic.runner.build_skill_image", return_value="test-image:latest"), \
             patch("analyzers.dynamic.runner.find_shell_scripts", return_value=[]), \
             patch("analyzers.dynamic.runner.cleanup_skill_image", side_effect=Exception("Docker error")), \
             patch("analyzers.dynamic.runner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            # Should not raise even if cleanup fails
            result = run_scripts_in_docker(Path(tmp))

    assert len(result) == 3


def test_run_scripts_prune_called_after_cleanup():
    """docker image prune -f should be called after cleanup to free space."""
    from analyzers.dynamic.runner import run_scripts_in_docker
    from pathlib import Path
    import tempfile

    prune_called = []

    def mock_subprocess_run(cmd, **kwargs):
        if "prune" in cmd:
            prune_called.append(cmd)
        return MagicMock(returncode=0)

    with tempfile.TemporaryDirectory() as tmp:
        fake_script = Path(tmp) / "install.sh"
        fake_script.write_text("#!/bin/bash\necho hi\n")

        with patch("analyzers.dynamic.runner.ensure_sandbox_image", return_value=True), \
             patch("analyzers.dynamic.runner.detect_required_packages", return_value=[]), \
             patch("analyzers.dynamic.runner.has_heavy_packages", return_value=False), \
             patch("analyzers.dynamic.runner.build_skill_image", return_value="test-image:latest"), \
             patch("analyzers.dynamic.runner.find_shell_scripts", return_value=[fake_script]), \
             patch("analyzers.dynamic.runner.run_script_in_docker", return_value=("strace output", "", 0)), \
             patch("analyzers.dynamic.runner.cleanup_skill_image"), \
             patch("analyzers.dynamic.runner.subprocess.run", side_effect=mock_subprocess_run):
            run_scripts_in_docker(Path(tmp))

    assert len(prune_called) > 0
    assert "prune" in prune_called[0]