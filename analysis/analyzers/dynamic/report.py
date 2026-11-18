"""Data contract for dynamic analysis results.

DynamicAnalysisReport is the single output type of DynamicAnalyzer.analyze(). It mirrors the structure of AnalysisReport from the static analyzer but carries runtime-observed evidence rather than statically-inferred indicators.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class DynamicAnalysisReport:
    """Structured result of executing a skill artifact in a sandboxed container.

    status values:
        success         — container ran and strace output was collected
        failed          — container exited with error before producing output
        timeout         — container exceeded the time limit
        no_executable   — no runnable .sh files found in the artifact

    verdict values:
        malicious       — dangerous syscall patterns confirmed at runtime
        suspicious      — network or sensitive file access observed but
                          insufficient to confirm malicious intent alone
        benign          — no dangerous patterns observed
        inconclusive    — execution produced no meaningful syscall output
    """

    status: str
    verdict: str

    # Observed runtime events
    file_reads: tuple[str, ...]          = field(default_factory=tuple)
    file_writes: tuple[str, ...]         = field(default_factory=tuple)
    network_calls: tuple[str, ...]       = field(default_factory=tuple)
    processes_spawned: tuple[str, ...]   = field(default_factory=tuple)
    credential_paths_read: tuple[str, ...]   = field(default_factory=tuple)
    exfiltration_domains: tuple[str, ...]    = field(default_factory=tuple)
    sensitive_writes: tuple[str, ...]        = field(default_factory=tuple)
    reverse_shell_processes: tuple[str, ...] = field(default_factory=tuple)

    # Execution metadata
    syscall_count: int                   = 0
    execution_time_secs: float           = 0.0
    exit_code: int | None                = None
    executables_run: tuple[str, ...]     = field(default_factory=tuple)

    # Full structured output for DB storage
    result_json: dict[str, Any]          = field(default_factory=dict)

    # Human-readable summary
    summary: str                         = ""
    verdict_reason: str                  = ""