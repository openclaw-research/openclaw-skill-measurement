"""Tests for analyzers/dynamic/verdict.py.

All tests are fully standalone — no Docker, no DB, no S3.
ParsedEvents instances are constructed directly and fed to calculate_verdict() and build_verdict_summary().
"""
from __future__ import annotations

from analyzers.dynamic.parser import ParsedEvents
from analyzers.dynamic.verdict import calculate_verdict, build_verdict_summary


def _events(**kwargs) -> ParsedEvents:
    """Helper to build a ParsedEvents with only the fields needed for a test."""
    defaults = {
        "file_reads": [],
        "file_writes": [],
        "network_calls": [],
        "processes_spawned": [],
        "credential_paths_read": [],
        "exfiltration_domains": [],
        "sensitive_writes": [],
        "reverse_shell_processes": [],
        "syscall_count": 10,
    }
    defaults.update(kwargs)
    return ParsedEvents(**defaults)


def test_no_syscalls_returns_inconclusive():
    events = _events(syscall_count=0)
    assert calculate_verdict(events) == "inconclusive"


def test_no_dangerous_events_returns_benign():
    events = _events(
        file_reads=["/etc/hosts", "/usr/lib/python3/ssl.py"],
        syscall_count=50,
    )
    assert calculate_verdict(events) == "benign"


def test_reverse_shell_process_returns_malicious():
    events = _events(
        reverse_shell_processes=["/bin/bash"],
        processes_spawned=["/bin/bash"],
    )
    assert calculate_verdict(events) == "malicious"


def test_credential_read_plus_network_returns_malicious():
    events = _events(
        credential_paths_read=["/root/.ssh/id_rsa"],
        network_calls=["104.20.5.215"],
    )
    assert calculate_verdict(events) == "malicious"


def test_exfiltration_domain_returns_malicious():
    events = _events(
        network_calls=["pastebin.com"],
        exfiltration_domains=["pastebin.com"],
    )
    assert calculate_verdict(events) == "malicious"


def test_credential_read_plus_sensitive_write_returns_malicious():
    events = _events(
        credential_paths_read=["/root/.aws/credentials"],
        sensitive_writes=["/home/user/.bashrc"],
    )
    assert calculate_verdict(events) == "malicious"


def test_network_only_returns_suspicious():
    events = _events(
        network_calls=["api.github.com"],
    )
    assert calculate_verdict(events) == "suspicious"


def test_credential_read_only_returns_suspicious():
    events = _events(
        credential_paths_read=["/root/.ssh/id_rsa"],
    )
    assert calculate_verdict(events) == "suspicious"


def test_sensitive_write_only_returns_suspicious():
    events = _events(
        sensitive_writes=["/home/user/.bashrc"],
    )
    assert calculate_verdict(events) == "suspicious"


def test_malicious_takes_priority_over_suspicious():
    events = _events(
        reverse_shell_processes=["/bin/bash"],
        network_calls=["api.github.com"],
        credential_paths_read=["/root/.ssh/id_rsa"],
    )
    assert calculate_verdict(events) == "malicious"


def test_summary_inconclusive():
    events = _events(syscall_count=0)
    verdict = calculate_verdict(events)
    summary = build_verdict_summary(events, verdict)
    assert "inconclusive" in summary.lower()


def test_summary_malicious_includes_reverse_shell():
    events = _events(
        reverse_shell_processes=["/bin/bash"],
        processes_spawned=["/bin/bash"],
    )
    verdict = calculate_verdict(events)
    summary = build_verdict_summary(events, verdict)
    assert "malicious" in summary.lower()
    assert "/bin/bash" in summary


def test_summary_malicious_includes_credential_paths():
    events = _events(
        credential_paths_read=["/root/.aws/credentials"],
        network_calls=["104.20.5.215"],
    )
    verdict = calculate_verdict(events)
    summary = build_verdict_summary(events, verdict)
    assert "/root/.aws/credentials" in summary


def test_summary_malicious_includes_exfiltration_domains():
    events = _events(
        exfiltration_domains=["pastebin.com"],
        network_calls=["pastebin.com"],
    )
    verdict = calculate_verdict(events)
    summary = build_verdict_summary(events, verdict)
    assert "pastebin.com" in summary


def test_summary_benign_mentions_syscall_count():
    events = _events(syscall_count=42)
    summary = build_verdict_summary(events, "benign")
    assert "42" in summary


def test_summary_suspicious_includes_network():
    events = _events(network_calls=["api.github.com"])
    verdict = calculate_verdict(events)
    summary = build_verdict_summary(events, verdict)
    assert "api.github.com" in summary

def test_low_syscalls_all_nonzero_exits_returns_context_dependent():
    events = _events(syscall_count=145)
    assert calculate_verdict(events, exit_codes=[1]) == "context_dependent"


def test_low_syscalls_zero_exit_returns_benign():
    events = _events(syscall_count=145)
    assert calculate_verdict(events, exit_codes=[0]) == "benign"


def test_low_syscalls_mixed_exits_returns_benign():
    """If any exit code is 0, not context_dependent."""
    events = _events(syscall_count=145)
    assert calculate_verdict(events, exit_codes=[1, 0, 1]) == "benign"


def test_high_syscalls_all_exit_1_returns_context_dependent():
    """All scripts failing with exit 1 = context_dependent even with high syscalls."""
    events = _events(syscall_count=5000)
    assert calculate_verdict(events, exit_codes=[1, 1, 1]) == "context_dependent"


def test_no_exit_codes_returns_benign_not_context_dependent():
    """Without exit codes we can't determine context_dependent."""
    events = _events(syscall_count=145)
    assert calculate_verdict(events, exit_codes=None) == "benign"


def test_malicious_overrides_context_dependent():
    """Malicious verdict takes priority even with low syscalls."""
    events = _events(
        syscall_count=50,
        credential_paths_read=["/root/.ssh/id_rsa"],
        network_calls=["pastebin.com"],
        exfiltration_domains=["pastebin.com"],
    )
    assert calculate_verdict(events, exit_codes=[1]) == "malicious"


def test_summary_context_dependent():
    events = _events(syscall_count=145)
    summary = build_verdict_summary(events, "context_dependent")
    assert "context_dependent" in summary.lower() or "agent context" in summary.lower()
    assert "145" in summary

def test_all_exit_127_returns_context_dependent_regardless_of_syscalls():
    """Exit 127 (command not found) always means context_dependent."""
    events = _events(syscall_count=2000)
    assert calculate_verdict(events, exit_codes=[127, 127, 127]) == "context_dependent"


def test_all_exit_127_mixed_with_benign_indicators():
    """Even with high syscalls, exit 127 on all scripts = context_dependent."""
    events = _events(syscall_count=5000, file_reads=["/etc/hosts"])
    assert calculate_verdict(events, exit_codes=[127, 127]) == "context_dependent"


def test_mixed_exit_codes_some_success_returns_benign():
    """If any script succeeded (exit 0), verdict based on events not exit codes."""
    events = _events(syscall_count=1000)
    assert calculate_verdict(events, exit_codes=[127, 0, 1]) == "benign"


def test_exit_126_returns_context_dependent():
    """Exit 126 (permission denied) = context_dependent."""
    events = _events(syscall_count=500)
    assert calculate_verdict(events, exit_codes=[126]) == "context_dependent"

# ── npm install side effect detection ─────────────────────────────────────────

def test_npm_install_pattern_not_malicious():
    """npm reading .npmrc and contacting npm registries is not malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc"],
        network_calls=["registry.npmjs.org", "github.com", "mths.be"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node"],
        syscall_count=36000,
        credential_reads_with_process=[
            {"path": "/.npmrc", "process": "/usr/bin/npm", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "registry.npmjs.org", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "github.com", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "mths.be", "process": "/usr/bin/npm", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_npm_install_with_github_co_not_malicious():
    """npm contacting github.co redirect is not malicious."""
    events = ParsedEvents(
        credential_paths_read=["/root/.npmrc"],
        network_calls=["github.co", "github.com", "mths.be", "registry.npmjs.org"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node"],
        syscall_count=35000,
        credential_reads_with_process=[
            {"path": "/root/.npmrc", "process": "/usr/bin/npm", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "github.co", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "github.com", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "mths.be", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "registry.npmjs.org", "process": "/usr/bin/npm", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_npm_install_with_unknown_domain_is_malicious():
    """npm pattern with unknown domain is still malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc"],
        network_calls=["registry.npmjs.org", "openow.ai"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node"],
        syscall_count=36000,
    )
    assert calculate_verdict(events) == "malicious"


def test_npm_install_without_npm_process_is_malicious():
    """Npmrc read + npm domains without npm process is still malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc"],
        network_calls=["registry.npmjs.org", "github.com"],
        processes_spawned=["/usr/bin/bash"],
        syscall_count=5000,
    )
    assert calculate_verdict(events) == "malicious"


def test_npm_install_with_non_npmrc_credential_is_malicious():
    """npm pattern with non-.npmrc credential read is still malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc", "/root/.ssh/id_rsa"],
        network_calls=["registry.npmjs.org", "github.com"],
        processes_spawned=["/usr/bin/npm"],
        syscall_count=36000,
    )
    assert calculate_verdict(events) == "malicious"


def test_wenjuan_survey_pattern_not_malicious():
    """Exact wenjuan-survey strace pattern is not malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc"],
        network_calls=["github.co", "github.com", "mths.be", "registry.npmjs.org"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node", "/usr/bin/bash"],
        syscall_count=36996,
        credential_reads_with_process=[
            {"path": "/.npmrc", "process": "/usr/bin/npm", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "github.co", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "github.com", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "mths.be", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "registry.npmjs.org", "process": "/usr/bin/npm", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_eisenhower_task_manager_pattern_not_malicious():
    """Exact eisenhower-task-manager strace pattern is not malicious."""
    events = ParsedEvents(
        credential_paths_read=["/skill/dashboard/.npmrc"],
        network_calls=["github.co", "github.com", "mths.be", "registry.npmjs.org"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node", "/usr/bin/bash"],
        syscall_count=31749,
        credential_reads_with_process=[
            {"path": "/skill/dashboard/.npmrc", "process": "/usr/bin/npm", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "github.co", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "github.com", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "mths.be", "process": "/usr/bin/npm", "pid": "1234"},
            {"domain": "registry.npmjs.org", "process": "/usr/bin/npm", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_test_wp_pattern_still_malicious():
    """test-wp pattern with openow.ai remains malicious despite npm processes."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc", "/root/.npmrc"],
        network_calls=["github.co", "github.com", "openow.ai"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/node", "/usr/bin/bash"],
        syscall_count=34795,
    )
    assert calculate_verdict(events) == "malicious"

def test_vagrant_docker_apt_pattern_not_malicious():
    """vagrant-skill pattern: docker reads config + apt contacts ubuntu mirrors."""
    events = ParsedEvents(
        credential_paths_read=["/root/.docker/config.json"],
        network_calls=["help.ubuntu.com"],
        processes_spawned=["/usr/bin/docker", "/usr/bin/apt-get", "/usr/bin/bash"],
        syscall_count=34579,
        credential_reads_with_process=[
            {"path": "/root/.docker/config.json", "process": "/usr/bin/docker", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "help.ubuntu.com", "process": "/usr/bin/apt-get", "pid": "5678"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_git_netrc_github_not_malicious():
    """git reads .netrc and contacts github.com — tool side effect."""
    events = ParsedEvents(
        credential_paths_read=["/root/.netrc"],
        network_calls=["github.com"],
        processes_spawned=["/usr/bin/git", "/usr/lib/git-core/git-remote-https"],
        syscall_count=2642,
        credential_reads_with_process=[
            {"path": "/root/.netrc", "process": "/usr/bin/git", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "github.com", "process": "/usr/bin/git", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) != "malicious"


def test_cross_process_credential_network_is_malicious():
    """Different processes reading credential and making network call is malicious."""
    events = ParsedEvents(
        credential_paths_read=["/.npmrc"],
        network_calls=["openow.ai"],
        processes_spawned=["/usr/bin/npm", "/usr/bin/curl"],
        syscall_count=36000,
        credential_reads_with_process=[
            {"path": "/.npmrc", "process": "/usr/bin/npm", "pid": "1111"}
        ],
        network_calls_with_process=[
            {"domain": "openow.ai", "process": "/usr/bin/curl", "pid": "2222"},
        ],
    )
    assert calculate_verdict(events) == "malicious"


def test_unexplained_credential_path_is_malicious():
    """Credential read by unknown tool with network call is malicious."""
    events = ParsedEvents(
        credential_paths_read=["/root/.ssh/id_rsa"],
        network_calls=["attacker.com"],
        processes_spawned=["/usr/bin/bash"],
        syscall_count=5000,
        credential_reads_with_process=[
            {"path": "/root/.ssh/id_rsa", "process": "/usr/bin/bash", "pid": "1234"}
        ],
        network_calls_with_process=[
            {"domain": "attacker.com", "process": "/usr/bin/bash", "pid": "1234"},
        ],
    )
    assert calculate_verdict(events) == "malicious"