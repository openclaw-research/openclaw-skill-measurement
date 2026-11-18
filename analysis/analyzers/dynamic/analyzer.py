"""Dynamic analyzer orchestrator.

Parallel to analyzers/static/analyzer.py — same interface, different analysis method. Downloads are handled by the pipeline layer; this module receives a root_path and returns a DynamicAnalysisReport.

Workflow:
    1. Find shell scripts in the artifact directory
    2. Run each in a sandboxed Docker container with strace
    3. Parse strace output into structured runtime events
    4. Calculate verdict from events
    5. Build and return DynamicAnalysisReport
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from collections import Counter

from analyzers.dynamic.llm_interpreter import LLMInterpretation, LLMDailyLimitExceeded, interpret
from analyzers.dynamic.parser import parse_strace
from analyzers.dynamic.report import DynamicAnalysisReport
from analyzers.dynamic.runner import find_shell_scripts, run_scripts_in_docker
from analyzers.dynamic.verdict import build_verdict_reason, build_verdict_summary, calculate_verdict

# Default tmp directory — inside repo, gitignored
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_TMP_DIR = _REPO_ROOT / "tmp" / "dynamic"

logger = logging.getLogger(__name__)

_VERDICT_RANK: dict[str, int] = {
    "malicious": 3,
    "suspicious": 2,
    "context_dependent": 1,
    "benign": 0,
}

def _apply_llm_verdict(
    rule_verdict: str,
    llm_interpretation: "LLMInterpretation | None",
) -> tuple[str, str]:
    """Apply LLM final verdict with safeguards.

    Returns (final_verdict, override_reason).

    Safeguards:
    - LLM can only DOWNGRADE (malicious→suspicious, suspicious→benign)
    - LLM cannot UPGRADE verdict
    - Low confidence (<0.7) LLM outputs are ignored
    - If LLM final_verdict is missing or invalid, keep rule verdict
    """
    if llm_interpretation is None:
        return rule_verdict, ""

    llm_verdict = llm_interpretation.final_verdict
    confidence  = llm_interpretation.overall_confidence
    override_reason = llm_interpretation.override_reason or ""

    # LLM did not produce a valid verdict
    if not llm_verdict or llm_verdict not in _VERDICT_RANK:
        return rule_verdict, ""

    # Low confidence — ignore LLM verdict
    if confidence < 0.7:
        return rule_verdict, ""

    # Stricter threshold for downgrading malicious
    # Malicious is our most important verdict — false negatives worse than FPs
    if rule_verdict == "malicious" and confidence < 0.92:
        return rule_verdict, ""

    # LLM cannot upgrade to malicious — rule-based must fire first
    if llm_verdict == "malicious" and rule_verdict != "malicious":
        return rule_verdict, ""

    # Accept downgrades
    if _VERDICT_RANK.get(llm_verdict, -1) <= _VERDICT_RANK.get(rule_verdict, -1):
        return llm_verdict, override_reason

    # Allow upgrade to suspicious from benign/context_dependent with high confidence
    if llm_verdict == "suspicious" and rule_verdict in ("benign", "context_dependent"):
        if confidence >= 0.85:
            return llm_verdict, override_reason

    return rule_verdict, ""

class DynamicAnalyzer:
    """Dynamic analyzer v1. Executes shell scripts in Docker with strace."""

    name = "dynamic"
    version = "3"

    def __init__(
        self,
        timeout_secs: int = 30,
        memory_limit: str = "512m",
        cpu_limit: str = "0.5",
        max_scripts: int | None = None,
        total_timeout_secs: int = 120,
        skill_purpose: str = "",
        llm_prior: dict | None = None,
        static_risk: str = "unknown",
    ) -> None:
        self.timeout_secs = timeout_secs
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.max_scripts = max_scripts
        self.total_timeout_secs = total_timeout_secs
        self.skill_purpose = skill_purpose
        self.llm_prior = llm_prior
        self.static_risk = static_risk

    def analyze(self, root_path: Path) -> DynamicAnalysisReport:
        """Analyze a downloaded artifact directory by executing its shell scripts.

        Args:
            root_path: Root of the downloaded skill artifact directory.

        Returns:
            DynamicAnalysisReport with verdict and observed runtime events.
        """
        root = Path(root_path).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(
                f"Analysis root does not exist or is not a directory: {root}"
            )

        scripts = find_shell_scripts(root)

        if not scripts:
            logger.info("No shell scripts found in %s — returning no_executable", root)
            return DynamicAnalysisReport(
                status="no_executable",
                verdict="inconclusive",
                verdict_reason="No shell scripts found in artifact directory.",
                summary="No shell scripts found in artifact directory.",
                result_json={
                    "analyzer": {"name": self.name, "version": self.version},
                    "status": "no_executable",
                    "executables_found": 0,
                },
            )

        workspace = root / "workspace"
        workspace.mkdir(exist_ok=True)
        if not (workspace / "MEMORY.md").exists():
            (workspace / "MEMORY.md").write_text(
                "# Synthetic workspace for dynamic analysis\n"
            )
        if not (workspace / "IDENTITY.md").exists():
            (workspace / "IDENTITY.md").write_text("ID: 99999\n")
        if not (workspace / ".env").exists():
            (workspace / ".env").write_text("")

        strace_output, executed, exit_codes = run_scripts_in_docker(
            root_path=root,
            timeout_secs=self.timeout_secs,
            memory_limit=self.memory_limit,
            cpu_limit=self.cpu_limit,
            max_scripts=self.max_scripts,
            total_timeout_secs=self.total_timeout_secs,
        )

        if not strace_output:
            logger.warning("No strace output produced for %s", root)
            return DynamicAnalysisReport(
                status="failed",
                verdict="inconclusive",
                verdict_reason="No strace output produced — Docker unavailable or script exited before producing output.",
                executables_run=tuple(executed),
                summary=(
                    "Script execution produced no strace output. "
                    "Docker may not be installed or the script exited immediately."
                ),
                result_json={
                    "analyzer": {"name": self.name, "version": self.version},
                    "status": "failed",
                    "executables_run": executed,
                },
            )

        events = parse_strace(strace_output)
        verdict = calculate_verdict(events, exit_codes=exit_codes)
        verdict_reason = build_verdict_reason(events, verdict, exit_codes=exit_codes)
        summary = build_verdict_summary(events, verdict)

        # Run LLM interpretation for suspicious/malicious verdicts
        llm_interpretation: LLMInterpretation | None = None
        if verdict != "inconclusive" and (
            os.environ.get("GROQ_API_KEY") or os.environ.get("API_KEY")
        ):
            from analyzers.static.rules.definitions import (
                COLLECTOR_METADATA_FILES,
                SHELL_EXTENSIONS,
            )
            skip_extensions = SHELL_EXTENSIONS | {
                ".md", ".json", ".txt", ".yaml", ".yml",
                ".toml", ".rst", ".html", ".css",
            }
            from collections import Counter
            unexecuted_all = [
                f
                for f in sorted(root.rglob("*"))
                if f.is_file()
                and f.suffix.lower() not in skip_extensions
                and f.name not in COLLECTOR_METADATA_FILES
            ]
            ext_counts = Counter(
                f.suffix.lower() or "[none]" for f in unexecuted_all
            )
            unexecuted_summary = ", ".join(
                f"{count} {ext} file{'s' if count > 1 else ''}"
                for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1])
            ) if ext_counts else "none"

            strace_summary = {
                "credential_paths_read":          list(events.credential_paths_read),
                "generated_credential_paths":     list(events.generated_credential_paths),
                "sensitive_writes":               list(events.sensitive_writes),
                "network_calls":                  list(events.network_calls),
                "truncated_network_calls":        list(events.truncated_network_calls),
                "exfiltration_domains":           list(events.exfiltration_domains),
                "reverse_shell_processes":        list(events.reverse_shell_processes),
                "processes_spawned":              list(events.processes_spawned),
                "file_writes":                    list(events.file_writes),
                "executables_run":                executed,
                "exit_codes":                     exit_codes,
                "syscall_count":                  events.syscall_count,
                "unexecuted_files":               unexecuted_summary,
                "dynamic_verdict":                verdict,
                "credential_reads_with_process":  list(events.credential_reads_with_process),
                "network_calls_with_process":     list(events.network_calls_with_process),
            }
            llm_interpretation = interpret(
                skill_source_id=root.name,
                skill_purpose=self.skill_purpose,
                static_risk=self.static_risk,
                dynamic_verdict=verdict,
                strace_summary=strace_summary,
                llm_prior=self.llm_prior,
            )
            if llm_interpretation:
                logger.info(
                    "LLM interpretation: purpose_fit=%s agreement=%s confidence=%.2f",
                    llm_interpretation.purpose_fit,
                    llm_interpretation.prior_agreement,
                    llm_interpretation.overall_confidence,
                )

            # Post-process: if dynamic verdict is benign and at least one
            # script ran fully (exit 0), prior_agreement should be contradicts
            # — the prior critical prediction is not supported by runtime evidence.
            if (
                llm_interpretation
                and verdict == "benign"
                and exit_codes
                and 0 in exit_codes
                and llm_interpretation.prior_agreement == "inconclusive"
            ):
                from analyzers.dynamic.llm_interpreter import LLMInterpretation
                llm_interpretation = LLMInterpretation(
                    purpose_fit=llm_interpretation.purpose_fit,
                    purpose_fit_reasoning=llm_interpretation.purpose_fit_reasoning,
                    prior_agreement="contradicts",
                    prior_agreement_reasoning=(
                        "Skill ran fully with no dangerous events observed — "
                        "prior critical prediction is not supported by runtime evidence."
                    ),
                    unexecuted_risk=llm_interpretation.unexecuted_risk,
                    unexecuted_risk_reasoning=llm_interpretation.unexecuted_risk_reasoning,
                    overall_confidence=llm_interpretation.overall_confidence,
                    analysis_notes=llm_interpretation.analysis_notes,
                    final_verdict=llm_interpretation.final_verdict,
                    override_reason=llm_interpretation.override_reason,
                    raw_response=llm_interpretation.raw_response,
                )
                logger.info(
                    "Post-processed prior_agreement to contradicts for benign verdict"
                )

        # Apply LLM verdict — may downgrade rule-based verdict
        # Apply LLM verdict — may downgrade rule-based verdict
        final_verdict, llm_override_reason = _apply_llm_verdict(
            rule_verdict=verdict,
            llm_interpretation=llm_interpretation,
        )
        if final_verdict != verdict:
            logger.info(
                "LLM overrode verdict for %s: %s -> %s (reason: %s)",
                root.name, verdict, final_verdict, llm_override_reason,
            )

        # Add caveat for benign verdict when unexecuted code files exist
        benign_caveat = None
        if final_verdict == "benign":
            code_extensions = {".py", ".js", ".ts", ".mjs", ".ps1", ".cjs"}
            unexecuted_code = [
                f.name for f in sorted(root.rglob("*"))
                if f.is_file() and f.suffix.lower() in code_extensions
            ]
            if unexecuted_code:
                shown = unexecuted_code[:10]
                remainder = len(unexecuted_code) - len(shown)
                file_list_str = ", ".join(shown)
                if remainder > 0:
                    file_list_str += f" (and {remainder} more)"
                benign_caveat = (
                    f"IMPORTANT: This benign verdict is based on shell script "
                    f"analysis only. The following code files were NOT executed "
                    f"and NOT analyzed: {file_list_str}. "
                    f"Malicious behavior in these files cannot be ruled out."
                )

        result_json = {
            "analyzer": {"name": self.name, "version": self.version},
            "status": "success",
            "verdict": final_verdict,
            "rule_based_verdict": verdict,
            "llm_override_reason": llm_override_reason if final_verdict != verdict else None,
            "verdict_reason": verdict_reason,
            "benign_caveat": benign_caveat,
            "llm_interpretation": {
                "purpose_fit": llm_interpretation.purpose_fit,
                "purpose_fit_reasoning": llm_interpretation.purpose_fit_reasoning,
                "prior_agreement": llm_interpretation.prior_agreement,
                "prior_agreement_reasoning": llm_interpretation.prior_agreement_reasoning,
                "unexecuted_risk": llm_interpretation.unexecuted_risk,
                "unexecuted_risk_reasoning": llm_interpretation.unexecuted_risk_reasoning,
                "overall_confidence": llm_interpretation.overall_confidence,
                "analysis_notes": llm_interpretation.analysis_notes,
            } if llm_interpretation else None,
            "executables_run": executed,
            "exit_codes": exit_codes,
            "file_reads": events.file_reads,
            "file_writes": events.file_writes,
            "network_calls": events.network_calls,
            "processes_spawned": events.processes_spawned,
            "credential_paths_read": events.credential_paths_read,
            "exfiltration_domains": events.exfiltration_domains,
            "sensitive_writes": events.sensitive_writes,
            "reverse_shell_processes": events.reverse_shell_processes,
            "syscall_count": events.syscall_count,
        }

        return DynamicAnalysisReport(
            status="success",
            verdict=final_verdict,
            verdict_reason=verdict_reason,
            file_reads=tuple(events.file_reads),
            file_writes=tuple(events.file_writes),
            network_calls=tuple(events.network_calls),
            processes_spawned=tuple(events.processes_spawned),
            credential_paths_read=tuple(events.credential_paths_read),
            exfiltration_domains=tuple(events.exfiltration_domains),
            sensitive_writes=tuple(events.sensitive_writes),
            reverse_shell_processes=tuple(events.reverse_shell_processes),
            syscall_count=events.syscall_count,
            executables_run=tuple(executed),
            summary=summary,
            result_json=result_json,
        )