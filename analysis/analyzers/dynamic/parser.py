"""Parse strace output into structured runtime events.

Takes raw strace text output and maps syscalls to behavioral categories
that mirror the static analyzer's indicator categories. Term lists for
credential paths, exfiltration domains, and persistence targets are
imported directly from rules/definitions.py so both analyzers share
a single source of truth.

What this module adds beyond the static analyzer:
    - Syscall-to-category mapping (openat, connect, execve, write)
    - O_RDONLY / O_WRONLY / O_CREAT flag classification
    - Raw IP address detection and private IP exclusion
    - Runtime process name matching against reverse_shell_patterns terms
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from analyzers.static.rules.definitions import FINDING_RULES


def _extract_terms(category: str) -> frozenset[str]:
    """Extract plain string terms from a FINDING_RULES category as lowercase."""
    terms = FINDING_RULES[category]["terms"]
    result = set()
    for t in terms:
        if isinstance(t, str):
            result.add(t.lower())
        elif isinstance(t, dict):
            result.add(t["term"].lower())
    return frozenset(result)


# Imported from static analyzer — single source of truth
CREDENTIAL_TERMS     = _extract_terms("credential_theft_targets")
EXFILTRATION_TERMS   = _extract_terms("exfiltration_channels")
PERSISTENCE_TERMS    = _extract_terms("persistence_mechanisms")
REVERSE_SHELL_TERMS  = _extract_terms("reverse_shell_patterns")

# Dynamic-only — IP address handling (no static equivalent)
# Private/loopback IPs are excluded from network_calls
PRIVATE_IP_PREFIXES = (
    "127.",
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31.",
    "::1",
    "0.0.0.0",
)

# strace regex patterns
# PID prefix: strace -f output prefixes each line with PID
_RE_PID = re.compile(r'^(\d+)\s+')

_RE_OPENAT = re.compile(
    r'openat\s*\([^,]+,\s*"([^"]+)",\s*([^)]+)\)'
)
_RE_OPEN = re.compile(
    r'\bopen\s*\(\s*"([^"]+)",\s*([^)]+)\)'
)
_RE_CONNECT_IP = re.compile(
    r'connect\s*\(\d+,\s*\{[^}]*sin_addr\s*=\s*inet_addr\("([^"]+)"\)'
)
_RE_EXECVE = re.compile(
    r'execve\s*\(\s*"([^"]+)",\s*\[([^\]]*)\]'
)
_RE_WRITE_URL = re.compile(
    r'write\s*\(\d+,\s*"([^"]*https?://[^"]*)"'
)
_RE_SENDTO_URL = re.compile(
    r'sendto\s*\(\d+,\s*"([^"]*https?://[^"]*)"'
)
_RE_READ_URL = re.compile(
    r'read\(\d+,\s*"([^"]*https?://[^"]*)"'
)


@dataclass
class ParsedEvents:
    """Structured runtime events extracted from a strace log."""
    file_reads:                 list[str]  = field(default_factory=list)
    file_writes:                list[str]  = field(default_factory=list)
    network_calls:              list[str]  = field(default_factory=list)
    truncated_network_calls:    list[str]  = field(default_factory=list)
    processes_spawned:          list[str]  = field(default_factory=list)
    credential_paths_read:      list[str]  = field(default_factory=list)
    generated_credential_paths: list[str]  = field(default_factory=list)
    exfiltration_domains:       list[str]  = field(default_factory=list)
    sensitive_writes:           list[str]  = field(default_factory=list)
    reverse_shell_processes:    list[str]  = field(default_factory=list)
    syscall_count:              int        = 0
    # Process-attributed events — track which process made each call
    # Each entry: {"path": "/.npmrc", "process": "npm", "pid": 1234}
    credential_reads_with_process:  list[dict] = field(default_factory=list)
    # Each entry: {"domain": "github.com", "process": "npm", "pid": 1234}
    network_calls_with_process:     list[dict] = field(default_factory=list)


def parse_strace(strace_output: str) -> ParsedEvents:
    """Parse raw strace output into structured runtime events.

    Args:
        strace_output: Raw text output from strace -f -e trace=all

    Returns:
        ParsedEvents with all observed runtime events categorized.
    """
    events = ParsedEvents()

    if not strace_output or not strace_output.strip():
        return events

    # PID → process name mapping built from execve() calls
    # Used to attribute network calls and credential reads to processes
    pid_to_process: dict[str, str] = {}

    for line in strace_output.splitlines():
        line = line.strip()
        if not line:
            continue

        events.syscall_count += 1

        # Extract PID from line prefix (strace -f output)
        pid = ""
        pid_match = _RE_PID.match(line)
        if pid_match:
            pid = pid_match.group(1)

        # Build PID → process map from execve calls
        for match in _RE_EXECVE.finditer(line):
            process = match.group(1)
            args = match.group(2)
            clean_args = re.sub(r'[",]', '', args).strip()
            full_invocation = f"{process} {clean_args}"
            events.processes_spawned.append(process)
            if pid:
                pid_to_process[pid] = process
            if _is_reverse_shell_process(full_invocation):
                events.reverse_shell_processes.append(process)

        for match in _RE_OPENAT.finditer(line):
            _classify_file_access(
                match.group(1), match.group(2), events,
                pid=pid, pid_to_process=pid_to_process,
            )

        for match in _RE_OPEN.finditer(line):
            _classify_file_access(
                match.group(1), match.group(2), events,
                pid=pid, pid_to_process=pid_to_process,
            )

        for match in _RE_CONNECT_IP.finditer(line):
            ip = match.group(1)
            if not _is_private_ip(ip):
                events.network_calls.append(ip)
                process_name = pid_to_process.get(pid, "unknown")
                events.network_calls_with_process.append({
                    "domain": ip,
                    "process": process_name,
                    "pid": pid,
                })

        for match in _RE_WRITE_URL.finditer(line):
            domain = _extract_domain(match.group(1))
            if domain:
                if _is_truncated_domain(domain):
                    events.truncated_network_calls.append(domain)
                else:
                    events.network_calls.append(domain)
                    process_name = pid_to_process.get(pid, "unknown")
                    events.network_calls_with_process.append({
                        "domain": domain,
                        "process": process_name,
                        "pid": pid,
                    })
                    if _is_exfiltration_domain(domain):
                        events.exfiltration_domains.append(domain)

        for match in _RE_SENDTO_URL.finditer(line):
            domain = _extract_domain(match.group(1))
            if domain:
                if _is_truncated_domain(domain):
                    events.truncated_network_calls.append(domain)
                else:
                    events.network_calls.append(domain)
                    process_name = pid_to_process.get(pid, "unknown")
                    events.network_calls_with_process.append({
                        "domain": domain,
                        "process": process_name,
                        "pid": pid,
                    })
                    if _is_exfiltration_domain(domain):
                        events.exfiltration_domains.append(domain)

        for match in _RE_READ_URL.finditer(line):
            domain = _extract_domain(match.group(1))
            if domain:
                if _is_truncated_domain(domain):
                    events.truncated_network_calls.append(domain)
                else:
                    events.network_calls.append(domain)
                    process_name = pid_to_process.get(pid, "unknown")
                    events.network_calls_with_process.append({
                        "domain": domain,
                        "process": process_name,
                        "pid": pid,
                    })
                    if _is_exfiltration_domain(domain):
                        events.exfiltration_domains.append(domain)

    events.file_reads                  = _deduplicate(events.file_reads)
    events.file_writes                 = _deduplicate(events.file_writes)
    events.network_calls               = _deduplicate(events.network_calls)
    events.truncated_network_calls     = _deduplicate(events.truncated_network_calls)
    events.processes_spawned           = _deduplicate(events.processes_spawned)
    events.credential_paths_read       = _deduplicate(events.credential_paths_read)
    events.generated_credential_paths  = _deduplicate(events.generated_credential_paths)
    events.exfiltration_domains        = _deduplicate(events.exfiltration_domains)
    events.sensitive_writes            = _deduplicate(events.sensitive_writes)
    events.reverse_shell_processes     = _deduplicate(events.reverse_shell_processes)

    return events


def _classify_file_access(
    path: str,
    flags: str,
    events: ParsedEvents,
    pid: str = "",
    pid_to_process: dict[str, str] | None = None,
) -> None:
    """Classify a file open syscall into reads, writes, credential reads.

    Tracks two credential subcategories:
    - credential_paths_read: pre-existing credential files read (suspicious)
    - generated_credential_paths: credential files created this run (benign)

    Also tracks credential_reads_with_process for process attribution.
    """
    flags_upper = flags.upper()
    is_write = any(
        f in flags_upper
        for f in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND")
    )
    process_name = (pid_to_process or {}).get(pid, "unknown")

    if is_write:
        events.file_writes.append(path)
        if _is_sensitive_write(path):
            events.sensitive_writes.append(path)
        if _is_credential_path(path):
            events.generated_credential_paths.append(path)
    else:
        events.file_reads.append(path)
        if _is_credential_path(path):
            if path in events.file_writes:
                events.generated_credential_paths.append(path)
            else:
                events.credential_paths_read.append(path)
                events.credential_reads_with_process.append({
                    "path": path,
                    "process": process_name,
                    "pid": pid,
                })


def _is_credential_path(path: str) -> bool:
    """Return True if path matches a credential_theft_targets term."""
    path_lower = path.lower()
    return any(term in path_lower for term in CREDENTIAL_TERMS)


def _is_sensitive_write(path: str) -> bool:
    """Return True if path matches a persistence_mechanisms term."""
    path_lower = path.lower()
    return any(term in path_lower for term in PERSISTENCE_TERMS)


def _is_exfiltration_domain(domain: str) -> bool:
    """Return True if domain matches an exfiltration_channels term."""
    domain_lower = domain.lower()
    return any(term in domain_lower for term in EXFILTRATION_TERMS)


def _is_reverse_shell_process(process: str) -> bool:
    """Return True if a spawned process matches reverse_shell_patterns terms."""
    process_lower = process.lower()
    return any(term in process_lower for term in REVERSE_SHELL_TERMS)


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is loopback or private (not externallyroutable)."""
    return any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES)

def _is_truncated_domain(domain: str) -> bool:
    """Return True if domain appears to be a strace buffer truncation artifact.

    strace truncates long strings mid-character. Truncated domains are
    typically very short, end with a period, or are clearly incomplete.
    These should not be treated as suspicious unknown domains.
    """
    if not domain:
        return True
    # Very short — likely truncated (e.g. 'raw.gi', 'loca', '...')
    if len(domain) <= 6:
        return True
    # Ends with period — truncated mid-TLD (e.g. 'open.alipay.', 'openow.')
    if domain.endswith("."):
        return True
    # Strace ellipsis artifact
    if domain in ("...", "..", "."):
        return True
    # Contains only dots — artifact
    if all(c == "." for c in domain):
        return True
    # No dot means it's a fragment — real domains always have at least one dot
    if "." not in domain:
        return True
    return False

def _extract_domain(url: str) -> str | None:
    """Extract domain from a URL string, stripping strace truncation artifacts."""
    match = re.search(r'https?://([^/\s"\']+)', url)
    if match:
        domain = match.group(1).split(":")[0]
        # Strip strace newline artifacts
        domain = domain.rstrip("\\n").rstrip("\n").strip()
        return domain if domain else None
    return None


def _deduplicate(items: list[str]) -> list[str]:
    """Remove duplicates while preserving insertion order."""
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result