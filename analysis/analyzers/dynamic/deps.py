"""Detect system package dependencies required by shell scripts.

Scans shell scripts for common dependency check patterns:
    command -v <tool>
    which <tool>
    type <tool>
    require <tool>

Maps detected tool names to their apt package names so they can be
installed in the sandbox container before execution.
"""
from __future__ import annotations

import re
from pathlib import Path

from analyzers.static.rules.definitions import SHELL_EXTENSIONS


# Maps common tool names to their apt package names
TOOL_TO_PACKAGE = {
    "jq":           "jq",
    "curl":         "curl",
    "wget":         "wget",
    "inotifywait":  "inotify-tools",
    "inotifywait":  "inotify-tools",
    "python3":      "python3",
    "python":       "python3",
    "pip":          "python3-pip",
    "pip3":         "python3-pip",
    "node":         "nodejs",
    "nodejs":       "nodejs",
    "npm":          "npm",
    "git":          "git",
    "unzip":        "unzip",
    "zip":          "zip",
    "tar":          "tar",
    "rsync":        "rsync",
    "ssh":          "openssh-client",
    "nc":           "netcat-openbsd",
    "ncat":         "ncat",
    "netcat":       "netcat-openbsd",
    "socat":        "socat",
    "dig":          "dnsutils",
    "nslookup":     "dnsutils",
    "nmap":         "nmap",
    "docker":       "docker.io",
    "systemctl":    "systemd",
    "crontab":      "cron",
    "at":           "at",
    "make":         "make",
    "gcc":          "gcc",
    "go":           "golang",
    "ruby":         "ruby",
    "perl":         "perl",
    "php":          "php",
    "java":         "default-jre",
    "mvn":          "maven",
    "gradle":       "gradle",
    "aws":          "awscli",
    "gcloud":       "google-cloud-cli",
    "kubectl":      "kubectl",
    "helm":         "helm",
    "terraform":    "terraform",
    "ansible":      "ansible",
    "ffmpeg":       "ffmpeg",
    "convert":      "imagemagick",
    "pv":           "pv",
    "xxd":          "xxd",
    "base64":       "coreutils",
    "openssl":      "openssl",
    "gpg":          "gnupg",
    "7z":           "p7zip-full",
}

# Patterns that indicate a tool dependency check
_RE_COMMAND_V = re.compile(
    r'command\s+-v\s+([a-zA-Z0-9_\-]+)',
    re.IGNORECASE,
)
_RE_WHICH = re.compile(
    r'\bwhich\s+([a-zA-Z0-9_\-]+)',
    re.IGNORECASE,
)
_RE_TYPE = re.compile(
    r'\btype\s+([a-zA-Z0-9_\-]+)',
    re.IGNORECASE,
)
_RE_HASH = re.compile(
    r'\bhash\s+([a-zA-Z0-9_\-]+)',
    re.IGNORECASE,
)


def detect_required_packages(root_path: Path) -> list[str]:
    """Scan shell scripts in an artifact for required system packages.

    Args:
        root_path: Root of the downloaded skill artifact.

    Returns:
        Sorted list of apt package names needed by the skill's shell scripts.
        Empty list if no dependencies detected or no shell scripts found.
    """
    tools: set[str] = set()

    for script in root_path.rglob("*"):
        if not script.is_file():
            continue
        if script.suffix.lower() not in SHELL_EXTENSIONS:
            continue

        try:
            content = script.read_text(errors="ignore")
        except OSError:
            continue

        for pattern in (_RE_COMMAND_V, _RE_WHICH, _RE_TYPE, _RE_HASH):
            for match in pattern.finditer(content):
                tool = match.group(1).lower().strip()
                if tool in TOOL_TO_PACKAGE:
                    tools.add(tool)

    packages = {TOOL_TO_PACKAGE[tool] for tool in tools}
    return sorted(packages)


def format_apt_install_cmd(packages: list[str]) -> str:
    """Format an apt-get install command for the detected packages.

    Args:
        packages: List of apt package names.

    Returns:
        Shell command string ready to pass to docker exec.
    """
    if not packages:
        return ""
    pkg_str = " ".join(packages)
    return (
        f"apt-get update -qq && "
        f"apt-get install -y {pkg_str} --no-install-recommends 2>/dev/null || true"
    )

# Packages known to be very large — skip install if present
HEAVY_PACKAGES = frozenset({
    "default-jre",
    "default-jdk",
    "openjdk-11-jdk",
    "openjdk-17-jdk",
    "maven",
    "gradle",
    "golang",
    "google-cloud-cli",
    "kubectl",
    "terraform",
    "ansible",
})


def has_heavy_packages(packages: list[str]) -> bool:
    """Return True if package list contains packages too large to install quickly."""
    return bool(set(packages) & HEAVY_PACKAGES)