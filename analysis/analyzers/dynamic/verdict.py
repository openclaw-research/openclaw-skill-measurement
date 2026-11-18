"""Compute a risk verdict from parsed dynamic runtime events.

Mirrors the logic of static/scoring.py but operates on observed runtime behavior rather than statically-inferred indicators. 
Verdicts are intentionally conservative — a benign verdict means no dangerous patterns were observed, not that the skill is guaranteed safe.

Verdict tiers:
    malicious     — dangerous behavior confirmed at runtime
    suspicious    — concerning patterns observed but insufficient alone
    benign        — no dangerous patterns observed
    inconclusive  — execution produced no meaningful output
"""
from __future__ import annotations

from analyzers.dynamic.parser import ParsedEvents


CONTEXT_DEPENDENT_SYSCALL_THRESHOLD = 200
FAILED_EXIT_CODES = frozenset({1, 2, 126, 127})

def calculate_verdict(
    events: ParsedEvents,
    exit_codes: list[int] | None = None,
) -> str:
    if events.syscall_count == 0:
        return "inconclusive"

    if _is_malicious(events):
        return "malicious"

    if _is_suspicious(events):
        return "suspicious"

    # All scripts failed to complete — context, deps, or input missing
    if exit_codes and all(code != 0 for code in exit_codes):
        # exit 127 = command not found (undetected missing dep)
        # exit 126 = permission denied
        # exit 1/2 = general error (interactive input, missing context)
        # If all exits are known failure codes → context_dependent
        if all(code in FAILED_EXIT_CODES for code in exit_codes):
            return "context_dependent"

        # Low syscall count + non-zero → exited very early
        if events.syscall_count < CONTEXT_DEPENDENT_SYSCALL_THRESHOLD:
            return "context_dependent"

    return "benign"

def build_verdict_reason(
    events: ParsedEvents,
    verdict: str,
    exit_codes: list[int] | None = None,
) -> str:
    """Build a human-readable reason explaining the verdict."""
    if verdict == "inconclusive":
        return "No syscall output produced — Docker may not be available or script exited before producing output."

    if verdict == "malicious":
        if events.reverse_shell_processes:
            return f"Reverse shell process spawned: {', '.join(events.reverse_shell_processes)}."
        if events.credential_paths_read and events.network_calls:
            return (
                f"Credential exfiltration chain: read {', '.join(events.credential_paths_read[:2])} "
                f"and contacted {', '.join(events.network_calls[:2])}."
            )
        if events.exfiltration_domains:
            return f"Known exfiltration domain contacted: {', '.join(events.exfiltration_domains)}."
        if events.credential_paths_read and events.sensitive_writes:
            return (
                f"Credential read and sensitive path written: "
                f"{', '.join(events.credential_paths_read[:1])} → "
                f"{', '.join(events.sensitive_writes[:1])}."
            )

    if verdict == "suspicious":
        if events.sensitive_writes and events.network_calls:
            return (
                f"Persistence mechanism installed ({', '.join(events.sensitive_writes[:1])}) "
                f"and network contact observed ({', '.join(events.network_calls[:1])})."
            )
        if events.sensitive_writes:
            return f"Sensitive path written: {', '.join(events.sensitive_writes[:2])}."
        if events.network_calls:
            return f"Network calls observed: {', '.join(events.network_calls[:3])}."
        if events.credential_paths_read:
            return f"Credential paths read: {', '.join(events.credential_paths_read[:2])}."

    if verdict == "context_dependent":
        reasons = []
        if exit_codes:
            if 127 in exit_codes:
                reasons.append("missing system dependencies (exit 127)")
            if 126 in exit_codes:
                reasons.append("permission denied (exit 126)")
            if any(c in (1, 2) for c in exit_codes):
                reasons.append("missing agent context or interactive input required")
        return f"Scripts could not execute fully: {'; '.join(reasons) if reasons else 'non-zero exit codes'}."

    return f"No dangerous syscall patterns observed across {events.syscall_count} syscalls."


def build_verdict_summary(events: ParsedEvents, verdict: str) -> str:
    """Build a human-readable summary of the dynamic verdict.

    Args:
        events: ParsedEvents produced by parse_strace()
        verdict: Verdict string from calculate_verdict()

    Returns:
        A one-paragraph summary suitable for storing in result_json.
    """
    parts = [f"Dynamic analysis verdict: {verdict}."]

    if events.reverse_shell_processes:
        parts.append(
            f"Reverse shell processes spawned: {', '.join(events.reverse_shell_processes)}."
        )
    if events.credential_paths_read:
        parts.append(
            f"Credential paths read: {', '.join(events.credential_paths_read)}."
        )
    if events.exfiltration_domains:
        parts.append(
            f"Exfiltration domains contacted: {', '.join(events.exfiltration_domains)}."
        )
    if events.sensitive_writes:
        parts.append(
            f"Sensitive paths written: {', '.join(events.sensitive_writes)}."
        )
    if events.network_calls and not events.exfiltration_domains:
        parts.append(
            f"Network calls observed: {', '.join(events.network_calls[:5])}."
        )
    if verdict == "benign":
        parts.append(
            f"No dangerous syscall patterns observed "
            f"({events.syscall_count} syscalls recorded)."
        )
    if verdict == "inconclusive":
        parts.append("No syscall output produced — skill may require agent context to execute.")

    if verdict == "context_dependent":
        parts.append(
            f"Scripts exited with failure codes — skill requires agent context, "
            f"missing dependencies, or interactive input to exhibit full behavior "
            f"({events.syscall_count} syscalls recorded)."
        )

    return " ".join(parts)


# Known tool processes and the credential path patterns they legitimately access.
# A credential read is a tool side effect when:
#   1. The tool process was present in the execution
#   2. The credential path matches the tool's expected credential pattern
#   3. The SAME process (by PID) that read the credential also made the network calls
#      OR all network calls are unexplained but no sensitive writes occurred
_TOOL_CREDENTIAL_PATTERNS: dict[str, list[str]] = {
    "npm":     [".npmrc"],
    "npx":     [".npmrc"],
    "yarn":    [".npmrc"],
    "pnpm":    [".npmrc"],
    "node":    [".npmrc"],
    "git":     [".netrc", ".git-credentials"],
    "docker":  [".docker/config.json"],
    "apt":     [".docker/config.json"],
    "apt-get": [".docker/config.json"],
    "pip":     [".pypirc"],
    "pip3":    [".pypirc"],
    "cargo":   [".cargo/credentials"],
    "gem":     [".gem/credentials"],
    "composer":[".composer/auth.json"],
    "openssl": [],  # generates keys, reads nothing pre-existing
}


def _is_tool_mediated_side_effect(events: ParsedEvents) -> bool:
    """Return True if ALL credential reads are explained by known tool processes.

    General principle: a credential read is NOT suspicious if a known tool
    that legitimately uses that credential type was present in the execution
    AND (using process attribution) that same tool made the network calls.

    This is general — works for npm, git, docker, apt, pip, cargo, etc.
    No domain allowlists needed — we reason from process identity.
    """
    if not events.credential_paths_read:
        return True

    process_basenames = {p.split("/")[-1] for p in events.processes_spawned}

    # Check every credential read is explained by a known tool
    for cred_path in events.credential_paths_read:
        cred_path_lower = cred_path.lower()
        explained = False
        for tool, patterns in _TOOL_CREDENTIAL_PATTERNS.items():
            if tool in process_basenames:
                if any(pattern in cred_path_lower for pattern in patterns):
                    explained = True
                    break
        if not explained:
            return False  # This credential read has no tool explanation

    # Use process attribution to verify tool-mediated behavior
    if events.network_calls:
        if events.credential_reads_with_process and events.network_calls_with_process:
            # Attribution available — check if same process read credential AND made network call
            cred_processes = {
                r["process"].split("/")[-1]
                for r in events.credential_reads_with_process
            }
            net_processes = {
                n["process"].split("/")[-1]
                for n in events.network_calls_with_process
            }
            # If different non-unknown processes — check if both are known tools
            if (
                cred_processes
                and net_processes
                and not (cred_processes & net_processes)
                and "unknown" not in cred_processes
                and "unknown" not in net_processes
            ):
                # Allow if BOTH processes are known tools
                # e.g. docker reads config.json + apt-get contacts ubuntu mirrors
                known_tools = set(_TOOL_CREDENTIAL_PATTERNS.keys())
                cred_basenames = {p.split("/")[-1] for p in cred_processes}
                net_basenames = {p.split("/")[-1] for p in net_processes}
                if not (cred_basenames <= known_tools and net_basenames <= known_tools):
                    return False  # At least one unknown process → suspicious
            # Same process made both → tool side effect confirmed ✅
        else:
            # No process attribution available — cannot verify tool-mediated behavior
            # Be conservative: LLM will downgrade if actually benign
            return False

    # No known exfiltration domains
    if events.exfiltration_domains:
        return False

    # No persistence writes
    if events.sensitive_writes:
        return False

    return True


def _is_malicious(events: ParsedEvents) -> bool:
    """Return True if runtime evidence confirms malicious behavior."""
    # Reverse shell spawned
    if events.reverse_shell_processes:
        return True

    # Credential read + network call — exclude tool-mediated side effects
    # Tools like npm, git, docker legitimately read credential files as side effects
    if events.credential_paths_read and events.network_calls:
        if not _is_tool_mediated_side_effect(events):
            return True

    # Known exfiltration domain contacted
    if events.exfiltration_domains:
        return True

    # Credential read + sensitive write (local credential harvesting)
    if events.credential_paths_read and events.sensitive_writes:
        return True

    return False


def _is_suspicious(events: ParsedEvents) -> bool:
    """Return True if runtime evidence is concerning but not conclusive."""
    # Network call without exfiltration domain — could be legitimate
    if events.network_calls:
        return True

    # Credential path read without network (local read, no exfil confirmed)
    if events.credential_paths_read:
        return True

    # Sensitive path written (persistence attempt)
    if events.sensitive_writes:
        return True

    return False