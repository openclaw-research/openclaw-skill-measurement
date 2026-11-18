"""Tests for analyzers/dynamic/parser.py.

All tests are fully standalone — no Docker, no DB, no S3.
Synthetic strace output strings are fed directly to parse_strace()
and the resulting ParsedEvents are asserted against expected values.
"""
from __future__ import annotations

from analyzers.dynamic.parser import (
    ParsedEvents,
    parse_strace,
    _is_credential_path,
    _is_exfiltration_domain,
    _is_sensitive_write,
    _is_private_ip,
    _extract_domain,
)


def test_empty_input_returns_empty_events():
    events = parse_strace("")
    assert events.file_reads == []
    assert events.file_writes == []
    assert events.network_calls == []
    assert events.processes_spawned == []
    assert events.syscall_count == 0


def test_whitespace_only_input_returns_empty_events():
    events = parse_strace("   \n\n   ")
    assert events.syscall_count == 0


def test_openat_readonly_maps_to_file_read():
    strace = 'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/etc/hosts" in events.file_reads
    assert "/etc/hosts" not in events.file_writes


def test_openat_wronly_maps_to_file_write():
    strace = 'openat(AT_FDCWD, "/tmp/output.txt", O_WRONLY|O_CREAT) = 4'
    events = parse_strace(strace)
    assert "/tmp/output.txt" in events.file_writes
    assert "/tmp/output.txt" not in events.file_reads


def test_openat_rdwr_maps_to_file_write():
    strace = 'openat(AT_FDCWD, "/tmp/data.bin", O_RDWR) = 5'
    events = parse_strace(strace)
    assert "/tmp/data.bin" in events.file_writes


def test_open_syscall_readonly_maps_to_file_read():
    strace = 'open("/home/user/config.json", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/home/user/config.json" in events.file_reads


def test_credential_path_detected_in_file_read():
    strace = 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/root/.ssh/id_rsa" in events.credential_paths_read
    assert "/root/.ssh/id_rsa" in events.file_reads


def test_aws_credentials_detected():
    strace = 'openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/home/user/.aws/credentials" in events.credential_paths_read


def test_kube_config_detected():
    strace = 'openat(AT_FDCWD, "/home/user/.kube/config", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/home/user/.kube/config" in events.credential_paths_read


def test_non_credential_path_not_in_credential_reads():
    strace = 'openat(AT_FDCWD, "/usr/lib/python3.11/ssl.py", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/usr/lib/python3.11/ssl.py" not in events.credential_paths_read


def test_connect_external_ip_maps_to_network_call():
    strace = 'connect(4, {sa_family=AF_INET, sin_addr=inet_addr("104.20.5.215")}, 16) = 0'
    events = parse_strace(strace)
    assert "104.20.5.215" in events.network_calls


def test_connect_loopback_excluded():
    strace = 'connect(4, {sa_family=AF_INET, sin_addr=inet_addr("127.0.0.1")}, 16) = 0'
    events = parse_strace(strace)
    assert "127.0.0.1" not in events.network_calls


def test_connect_private_ip_excluded():
    strace = 'connect(4, {sa_family=AF_INET, sin_addr=inet_addr("192.168.1.1")}, 16) = 0'
    events = parse_strace(strace)
    assert "192.168.1.1" not in events.network_calls


def test_execve_maps_to_processes_spawned():
    strace = 'execve("/bin/bash", ["/bin/bash", "-c", "echo hi"], NULL) = 0'
    events = parse_strace(strace)
    assert "/bin/bash" in events.processes_spawned


def test_reverse_shell_process_detected():
    strace = 'execve("/bin/bash", ["bash", "-i"], NULL) = 0'
    events = parse_strace(strace)
    assert "/bin/bash" in events.reverse_shell_processes


def test_normal_process_not_in_reverse_shell():
    strace = 'execve("/usr/bin/python3", ["python3", "script.py"], NULL) = 0'
    events = parse_strace(strace)
    assert "/usr/bin/python3" not in events.reverse_shell_processes


def test_write_with_url_maps_to_network_call():
    strace = 'write(4, "GET https://pastebin.com/api/post HTTP/1.1\\r\\n", 42) = 42'
    events = parse_strace(strace)
    assert "pastebin.com" in events.network_calls


def test_exfiltration_domain_detected_in_write():
    strace = 'write(4, "POST https://pastebin.com/api/post HTTP/1.1\\r\\n", 42) = 42'
    events = parse_strace(strace)
    assert "pastebin.com" in events.exfiltration_domains


def test_sendto_with_url_maps_to_network_call():
    strace = 'sendto(4, "GET https://ngrok.io/collect HTTP/1.1\\r\\n", 40, 0, NULL, 0) = 40'
    events = parse_strace(strace)
    assert "ngrok.io" in events.network_calls
    assert "ngrok.io" in events.exfiltration_domains


def test_sensitive_write_to_bashrc_detected():
    strace = 'openat(AT_FDCWD, "/home/user/.bashrc", O_WRONLY|O_APPEND) = 5'
    events = parse_strace(strace)
    assert "/home/user/.bashrc" in events.sensitive_writes
    assert "/home/user/.bashrc" in events.file_writes


def test_crontab_write_detected():
    strace = 'openat(AT_FDCWD, "/etc/crontab", O_WRONLY|O_CREAT) = 4'
    events = parse_strace(strace)
    assert "/etc/crontab" in events.sensitive_writes


def test_deduplication_of_repeated_paths():
    strace = '\n'.join([
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
    ])
    events = parse_strace(strace)
    assert events.file_reads.count("/etc/hosts") == 1


def test_syscall_count_increments_per_line():
    strace = '\n'.join([
        'openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3',
        'read(3, "127.0.0.1 localhost\\n", 4096) = 20',
        'close(3) = 0',
    ])
    events = parse_strace(strace)
    assert events.syscall_count == 3


def test_multiple_events_in_one_strace_output():
    strace = '\n'.join([
        'openat(AT_FDCWD, "/root/.aws/credentials", O_RDONLY) = 3',
        'connect(4, {sa_family=AF_INET, sin_addr=inet_addr("104.20.5.215")}, 16) = 0',
        'execve("/bin/bash", ["bash", "-i"], NULL) = 0',
        'write(4, "POST https://pastebin.com/api/post HTTP/1.1", 42) = 42',
    ])
    events = parse_strace(strace)
    assert "/root/.aws/credentials" in events.credential_paths_read
    assert "104.20.5.215" in events.network_calls
    assert "/bin/bash" in events.reverse_shell_processes
    assert "pastebin.com" in events.exfiltration_domains


def test_is_credential_path_ssh_key():
    assert _is_credential_path("/home/user/.ssh/id_rsa") is True


def test_is_credential_path_normal_file():
    assert _is_credential_path("/usr/lib/libssl.so") is False


def test_is_exfiltration_domain_pastebin():
    assert _is_exfiltration_domain("pastebin.com") is True


def test_is_exfiltration_domain_legitimate():
    assert _is_exfiltration_domain("api.github.com") is False


def test_is_sensitive_write_bashrc():
    assert _is_sensitive_write("/home/user/.bashrc") is True


def test_is_sensitive_write_normal_file():
    assert _is_sensitive_write("/home/user/output.txt") is False


def test_is_private_ip_loopback():
    assert _is_private_ip("127.0.0.1") is True


def test_is_private_ip_rfc1918():
    assert _is_private_ip("192.168.1.100") is True


def test_is_private_ip_external():
    assert _is_private_ip("8.8.8.8") is False


def test_extract_domain_simple_url():
    assert _extract_domain("https://pastebin.com/api/post") == "pastebin.com"


def test_extract_domain_with_port():
    assert _extract_domain("https://evil.com:8443/collect") == "evil.com"


def test_extract_domain_no_url():
    assert _extract_domain("no url here") is None

def test_read_syscall_with_url_maps_to_network_call():
    strace = 'read(255, "curl https://pastebin.com/api/post HTTP/1.1\\r\\n", 47) = 47'
    events = parse_strace(strace)
    assert "pastebin.com" in events.network_calls
    assert "pastebin.com" in events.exfiltration_domains


def test_read_syscall_with_legitimate_url_not_exfiltration():
    strace = 'read(255, "curl https://api.github.com/repos\\r\\n", 40) = 40'
    events = parse_strace(strace)
    assert "api.github.com" in events.network_calls
    assert "api.github.com" not in events.exfiltration_domains

# ── New field: truncated_network_calls ────────────────────────────────────────

def test_truncated_domain_goes_to_truncated_network_calls():
    """Short domains that are strace artifacts go to truncated_network_calls."""
    strace = 'write(4, "GET https://raw.gi HTTP/1.1\\r\\n", 30) = 30'
    events = parse_strace(strace)
    assert "raw.gi" in events.truncated_network_calls
    assert "raw.gi" not in events.network_calls


def test_domain_ending_with_period_is_truncated():
    """Domains ending with '.' are strace truncation artifacts."""
    strace = 'write(4, "POST https://open.alipay. HTTP/1.1\\r\\n", 40) = 40'
    events = parse_strace(strace)
    assert "open.alipay." in events.truncated_network_calls
    assert "open.alipay." not in events.network_calls


def test_ellipsis_artifact_is_truncated():
    """'...' is a strace truncation artifact."""
    strace = 'write(4, "GET https://... HTTP/1.1\\r\\n", 20) = 20'
    events = parse_strace(strace)
    assert "..." in events.truncated_network_calls
    assert "..." not in events.network_calls


def test_newline_stripped_from_domain():
    """Domains with strace newline artifacts are cleaned before classification."""
    strace = 'write(4, "POST https://clawhub.com\\n HTTP/1.1\\r\\n", 40) = 40'
    events = parse_strace(strace)
    assert "clawhub.com" in events.network_calls
    assert "clawhub.com" not in events.truncated_network_calls


def test_full_domain_goes_to_network_calls_not_truncated():
    """A full legitimate domain goes to network_calls, not truncated."""
    strace = 'write(4, "GET https://api.github.com/repos HTTP/1.1\\r\\n", 40) = 40'
    events = parse_strace(strace)
    assert "api.github.com" in events.network_calls
    assert "api.github.com" not in events.truncated_network_calls


def test_truncated_domain_not_checked_for_exfiltration():
    """Truncated domains should not be added to exfiltration_domains."""
    strace = 'write(4, "POST https://pastebi HTTP/1.1\\r\\n", 30) = 30'
    events = parse_strace(strace)
    assert "pastebi" in events.truncated_network_calls
    assert "pastebi" not in events.exfiltration_domains


def test_loca_truncated_domain():
    """'loca' is a truncated 'localhost' artifact — goes to truncated."""
    strace = 'write(4, "GET https://loca HTTP/1.1\\r\\n", 20) = 20'
    events = parse_strace(strace)
    assert "loca" in events.truncated_network_calls
    assert "loca" not in events.network_calls


# ── New field: generated_credential_paths ─────────────────────────────────────

def test_credential_created_then_read_goes_to_generated():
    """Credential file created this run then read → generated_credential_paths."""
    strace = '\n'.join([
        'openat(AT_FDCWD, "/tmp/app_private_key.pem", O_WRONLY|O_CREAT) = 3',
        'openat(AT_FDCWD, "/tmp/app_private_key.pem", O_RDONLY) = 4',
    ])
    events = parse_strace(strace)
    assert "/tmp/app_private_key.pem" in events.generated_credential_paths
    assert "/tmp/app_private_key.pem" not in events.credential_paths_read


def test_pre_existing_credential_goes_to_credential_paths_read():
    """Pre-existing credential file (not created this run) → credential_paths_read."""
    strace = 'openat(AT_FDCWD, "/root/.npmrc", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/root/.npmrc" in events.credential_paths_read
    assert "/root/.npmrc" not in events.generated_credential_paths


def test_credential_write_tracked_in_generated():
    """Credential file opened for write → tracked in generated_credential_paths."""
    strace = 'openat(AT_FDCWD, "/tmp/keypair/app_private_key.pem", O_WRONLY|O_CREAT) = 3'
    events = parse_strace(strace)
    assert "/tmp/keypair/app_private_key.pem" in events.generated_credential_paths


def test_alipay_pattern_self_generated_credential():
    """Mimics alipay false positive — openssl generates key then reads it back."""
    strace = '\n'.join([
        # openssl writes the key
        'openat(AT_FDCWD, "/tmp/tmp.abc123/app_private_key.pem", O_WRONLY|O_CREAT) = 3',
        # skill reads back its own key
        'openat(AT_FDCWD, "/tmp/tmp.abc123/app_private_key.pem", O_RDONLY) = 4',
        # network call to legitimate service
        'write(4, "POST https://open.alipay.com/gateway HTTP/1.1\\r\\n", 50) = 50',
    ])
    events = parse_strace(strace)
    # Key is self-generated — not a credential theft
    assert "/tmp/tmp.abc123/app_private_key.pem" in events.generated_credential_paths
    assert "/tmp/tmp.abc123/app_private_key.pem" not in events.credential_paths_read
    # Alipay domain — full domain goes to network_calls
    assert "open.alipay.com" in events.network_calls
    # credential_paths_read is empty → malicious rule should not fire
    assert events.credential_paths_read == []


def test_ssh_key_read_without_prior_write_is_credential_theft():
    """Pre-existing SSH key read (no prior write) → credential_paths_read."""
    strace = 'openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/root/.ssh/id_rsa" in events.credential_paths_read
    assert "/root/.ssh/id_rsa" not in events.generated_credential_paths


def test_netrc_read_without_prior_write_is_credential_theft():
    """Pre-existing .netrc read (no prior write) → credential_paths_read."""
    strace = '\n'.join([
        'execve("/usr/bin/git", ["git", "clone", "https://github.com/..."], NULL) = 0',
        'openat(AT_FDCWD, "/root/.netrc", O_RDONLY) = 3',
    ])
    events = parse_strace(strace)
    assert "/root/.netrc" in events.credential_paths_read
    assert "/root/.netrc" not in events.generated_credential_paths


def test_docker_config_read_without_write_is_credential_theft():
    """Pre-existing docker config read (no write) → credential_paths_read."""
    strace = 'openat(AT_FDCWD, "/root/.docker/config.json", O_RDONLY) = 3'
    events = parse_strace(strace)
    assert "/root/.docker/config.json" in events.credential_paths_read
    assert "/root/.docker/config.json" not in events.generated_credential_paths


# ── ParsedEvents has new fields ───────────────────────────────────────────────

def test_parsed_events_has_truncated_network_calls_field():
    """ParsedEvents has truncated_network_calls field initialized to empty list."""
    events = ParsedEvents()
    assert hasattr(events, "truncated_network_calls")
    assert events.truncated_network_calls == []


def test_parsed_events_has_generated_credential_paths_field():
    """ParsedEvents has generated_credential_paths field initialized to empty list."""
    events = ParsedEvents()
    assert hasattr(events, "generated_credential_paths")
    assert events.generated_credential_paths == []


def test_empty_input_new_fields_empty():
    """Empty strace input leaves new fields empty."""
    events = parse_strace("")
    assert events.truncated_network_calls == []
    assert events.generated_credential_paths == []

# ── Process attribution ───────────────────────────────────────────────────────

def test_network_call_attributed_to_process():
    """Network call is attributed to the process that made it."""
    strace = '\n'.join([
        '1234 execve("/usr/bin/curl", ["curl", "https://openow.ai/"], NULL) = 0',
        '1234 write(4, "POST https://openow.ai/api HTTP/1.1\\r\\n", 40) = 40',
    ])
    events = parse_strace(strace)
    assert len(events.network_calls_with_process) > 0
    attributed = events.network_calls_with_process[0]
    assert attributed["domain"] == "openow.ai"
    assert attributed["process"] == "/usr/bin/curl"
    assert attributed["pid"] == "1234"


def test_npm_network_call_attributed_to_npm():
    """npm network call is attributed to npm process."""
    strace = '\n'.join([
        '5678 execve("/usr/bin/npm", ["npm", "install"], NULL) = 0',
        '5678 write(4, "GET https://registry.npmjs.org/axios HTTP/1.1\\r\\n", 50) = 50',
    ])
    events = parse_strace(strace)
    npm_calls = [c for c in events.network_calls_with_process
                 if "npmjs" in c["domain"]]
    assert len(npm_calls) > 0
    assert npm_calls[0]["process"] == "/usr/bin/npm"
    assert npm_calls[0]["pid"] == "5678"


def test_credential_read_attributed_to_process():
    """Credential read is attributed to the process that read it."""
    strace = '\n'.join([
        '1234 execve("/usr/bin/npm", ["npm", "install"], NULL) = 0',
        '1234 openat(AT_FDCWD, "/.npmrc", O_RDONLY) = 3',
    ])
    events = parse_strace(strace)
    assert len(events.credential_reads_with_process) > 0
    attributed = events.credential_reads_with_process[0]
    assert attributed["path"] == "/.npmrc"
    assert attributed["process"] == "/usr/bin/npm"
    assert attributed["pid"] == "1234"


def test_different_pids_attributed_separately():
    """Different PIDs attributed to their respective processes."""
    strace = '\n'.join([
        '1111 execve("/usr/bin/npm", ["npm", "install"], NULL) = 0',
        '2222 execve("/usr/bin/curl", ["curl", "https://openow.ai/"], NULL) = 0',
        '1111 openat(AT_FDCWD, "/.npmrc", O_RDONLY) = 3',
        '2222 write(4, "POST https://openow.ai/collect HTTP/1.1\\r\\n", 40) = 40',
    ])
    events = parse_strace(strace)

    # npm read .npmrc
    npm_cred = [c for c in events.credential_reads_with_process
                if c["pid"] == "1111"]
    assert len(npm_cred) > 0
    assert npm_cred[0]["process"] == "/usr/bin/npm"

    # curl contacted openow.ai
    curl_net = [c for c in events.network_calls_with_process
                if "openow" in c["domain"]]
    assert len(curl_net) > 0
    assert curl_net[0]["process"] == "/usr/bin/curl"
    assert curl_net[0]["pid"] == "2222"


def test_unknown_process_when_no_execve():
    """Process is 'unknown' when no execve was seen for that PID."""
    strace = '9999 write(4, "GET https://example.com/ HTTP/1.1\\r\\n", 35) = 35'
    events = parse_strace(strace)
    net_calls = [c for c in events.network_calls_with_process
                 if "example.com" in c["domain"]]
    assert len(net_calls) > 0
    assert net_calls[0]["process"] == "unknown"


def test_parsed_events_has_process_attribution_fields():
    """ParsedEvents has credential_reads_with_process and network_calls_with_process."""
    events = ParsedEvents()
    assert hasattr(events, "credential_reads_with_process")
    assert hasattr(events, "network_calls_with_process")
    assert events.credential_reads_with_process == []
    assert events.network_calls_with_process == []