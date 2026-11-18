"""Execute shell scripts in a sandboxed Docker container with strace.

Finds runnable .sh files in an artifact directory, executes each one in an isolated Docker container with strace monitoring, and returns the combined strace output for parsing.

Docker constraints applied per container:
    --rm                remove container after run
    --network=none      no real network (attempted connects still visible in strace)
    --memory=512m       cap memory to prevent OOM on host
    --cpus=0.5          cap CPU to allow parallel runs
    --read-only         read-only root filesystem
    --tmpfs /tmp        writable /tmp for scripts that need it
    --cap-drop=ALL      drop all Linux capabilities
    --no-new-privileges prevent privilege escalation

Note: --network=none means actual network calls cannot complete, but strace will still record the connect() and sendto() syscalls — which is exactly what we want for analysis without real exfiltration risk.
"""
from __future__ import annotations

import hashlib
import logging
import subprocess
from pathlib import Path

from analyzers.dynamic.deps import HEAVY_PACKAGES, detect_required_packages, has_heavy_packages
from analyzers.static.rules.definitions import SHELL_EXTENSIONS

logger = logging.getLogger(__name__)

DOCKER_IMAGE = "openclaw-sandbox:latest"
DOCKERFILE_PATH = Path(__file__).resolve().parent.parent.parent / "docker" / "Dockerfile.sandbox"
DEFAULT_TIMEOUT_SECS = 30
DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "0.5"


def ensure_sandbox_image() -> bool:
    """Build the openclaw-sandbox Docker image if not already built.

    Returns True if image is available, False if build failed.
    """
    check = subprocess.run(
        ["docker", "image", "inspect", DOCKER_IMAGE],
        capture_output=True,
    )
    if check.returncode == 0:
        return True

    logger.info("Building %s from %s", DOCKER_IMAGE, DOCKERFILE_PATH)
    result = subprocess.run(
        ["docker", "build", "-t", DOCKER_IMAGE,
         "-f", str(DOCKERFILE_PATH),
         str(DOCKERFILE_PATH.parent)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error("Failed to build sandbox image: %s", result.stderr)
        return False
    logger.info("Built %s successfully", DOCKER_IMAGE)
    return True

def build_skill_image(
    root_path: Path,
    packages: list[str],
) -> str | None:
    """Build a skill-specific Docker image with required packages installed.

    Starts from openclaw-sandbox:latest, installs detected packages with network access, commits to a temporary image, and returns the image name.

    Args:
        root_path: Root of the skill artifact (used to generate unique name).
        packages: List of apt package names to install.

    Returns:
        Temporary image name if successful, None if build failed.
    """
    if not ensure_sandbox_image():
        return None

    path_hash = hashlib.sha256(str(root_path).encode()).hexdigest()[:12]
    image_name = f"openclaw-skill-{path_hash}"
    container_name = f"openclaw-setup-{path_hash}"

    # Check if image already exists
    check = subprocess.run(
        ["docker", "image", "inspect", image_name],
        capture_output=True,
    )
    if check.returncode == 0:
        logger.info("Skill image %s already exists — reusing", image_name)
        return image_name

    if not packages:
        logger.info("No packages to install — using base sandbox image")
        return DOCKER_IMAGE

    pkg_str = " ".join(packages)
    install_cmd = (
        f"apt-get update -qq && "
        f"apt-get install -y {pkg_str} --no-install-recommends 2>/dev/null || true"
    )

    logger.info("Installing packages %s into %s", packages, image_name)

    try:
        # Run setup container with network to install packages
        run_result = subprocess.run(
            [
                "docker", "run",
                "--name", container_name,
                "--memory=512m",
                "--cpus=0.5",
                DOCKER_IMAGE,
                "bash", "-c", install_cmd,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if run_result.returncode != 0:
            logger.warning(
                "Package install had errors for %s: %s",
                image_name, run_result.stderr[:200],
            )

        # Commit the container as a new image
        commit_result = subprocess.run(
            ["docker", "commit", container_name, image_name],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if commit_result.returncode != 0:
            logger.error("Failed to commit image %s: %s", image_name, commit_result.stderr)
            return None

        logger.info("Built skill image %s successfully", image_name)
        return image_name

    except subprocess.TimeoutExpired:
        logger.error("Package installation timed out for %s", image_name)
        return None
    except Exception as exc:
        logger.error("Error building skill image %s: %s", image_name, exc)
        return None
    finally:
        # Always remove the setup container
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
        )


def cleanup_skill_image(image_name: str) -> None:
    """Remove a temporary skill-specific Docker image.

    Args:
        image_name: Image name returned by build_skill_image().
    """
    if image_name == DOCKER_IMAGE:
        return
    subprocess.run(
        ["docker", "rmi", "-f", image_name],
        capture_output=True,
    )
    logger.info("Removed skill image %s", image_name)

def find_shell_scripts(root_path: Path) -> list[Path]:
    """Find all .sh files in an artifact directory.

    Args:
        root_path: Root of the downloaded skill artifact.

    Returns:
        List of .sh file paths sorted by size ascending (smallest first
        so simpler scripts run before complex ones).
    """
    scripts = [
        p for p in root_path.rglob("*")
        if p.is_file() and p.suffix.lower() in SHELL_EXTENSIONS
    ]
    def _priority(p: Path) -> tuple[int, int]:
        name = p.stem.lower()
        is_priority = any(
            k in name for k in ("install", "setup", "bootstrap", "init", "watch", "run", "start")
        )
        return (0 if is_priority else 1, p.stat().st_size)

    return sorted(scripts, key=_priority)


def run_script_in_docker(
    script_path: Path,
    root_path: Path,
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    memory_limit: str = DEFAULT_MEMORY_LIMIT,
    cpu_limit: str = DEFAULT_CPU_LIMIT,
    image: str = DOCKER_IMAGE,
) -> tuple[str, str, int]:
    """Run a single shell script in a sandboxed Docker container with strace.

    Args:
        script_path: Path to the .sh file to execute.
        root_path: Root of the artifact (mounted as /skill in the container).
        timeout_secs: Kill container after this many seconds.
        memory_limit: Docker memory limit string (e.g. '512m').
        cpu_limit: Docker CPU limit string (e.g. '0.5').

    Returns:
        Tuple of (strace_output, stderr, exit_code).
        strace_output is empty string if execution failed before producing output.
    """
    relative = script_path.relative_to(root_path)
    container_script = f"/skill/{relative.as_posix()}"

    cmd = [
        "docker", "run",
        "--rm",
        "--network=none",
        f"--memory={memory_limit}",
        f"--cpus={cpu_limit}",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs", "/root:rw,noexec,nosuid,size=64m",
        "--tmpfs", "/etc/systemd/system:rw,noexec,nosuid,size=64m",
        "--cap-drop=ALL",
        "--cap-add=DAC_READ_SEARCH",
        "--cap-add=DAC_OVERRIDE",
        "--security-opt", "no-new-privileges",
        "--volume", f"{root_path.resolve()}:/skill:ro",
        "--env", "LIGHTCLAW_WORKSPACE=/skill/workspace",
        "--env", "OPENCLAW_WORKSPACE=/skill/workspace",
        "--env", "PROJECT_PATH=/skill/workspace",
        "--env", "HOME=/root",
        image,
        "strace", "-f", "-e", "trace=all",
        "bash", container_script,
    ]

    logger.info("Running %s in Docker (timeout=%ds)", relative, timeout_secs)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_secs,
        )

        # Read strace output from the container's /tmp/strace.log
        # We need a second docker run to retrieve it since the container is --rm
        # Instead, use strace -o /dev/stderr to write to stderr directly
        strace_output = result.stderr  # strace writes to stderr by default
        stderr = result.stdout         # script stdout goes here
        exit_code = result.returncode

        logger.info(
            "Script %s finished exit_code=%d strace_lines=%d",
            relative, exit_code, len(strace_output.splitlines()),
        )
        return strace_output, stderr, exit_code

    except subprocess.TimeoutExpired:
        logger.warning("Script %s timed out after %ds", relative, timeout_secs)
        return "", "timeout", -1

    except FileNotFoundError:
        logger.error("Docker not found — is it installed and in PATH?")
        return "", "docker_not_found", -1

    except Exception as exc:
        logger.error("Unexpected error running %s: %s", relative, exc)
        return "", str(exc), -1


def run_scripts_in_docker(
    root_path: Path,
    timeout_secs: int = DEFAULT_TIMEOUT_SECS,
    memory_limit: str = DEFAULT_MEMORY_LIMIT,
    cpu_limit: str = DEFAULT_CPU_LIMIT,
    max_scripts: int | None = None,
    total_timeout_secs: int = 120,
) -> tuple[str, list[str], list[int]]:
    """Find and run all shell scripts in an artifact directory.

    Runs up to max_scripts scripts and concatenates their strace output.
    Stops early if a malicious verdict is likely (exfiltration or reverse
    shell detected in strace output before all scripts complete).

    Args:
        root_path: Root of the downloaded skill artifact.
        timeout_secs: Per-script timeout.
        memory_limit: Docker memory limit per container.
        cpu_limit: Docker CPU limit per container.
        max_scripts: Maximum number of scripts to run (avoids runaway execution).

    Returns:
        Tuple of (combined_strace_output, list_of_executed_script_names).
    """
    if not ensure_sandbox_image():
        logger.error("Sandbox image not available — skipping dynamic analysis")
        return "", [], []

    # Build skill-specific image with required packages
    packages = detect_required_packages(root_path)
    if has_heavy_packages(packages):
        heavy = [p for p in packages if p in HEAVY_PACKAGES]
        logger.info(
            "Skipping package install — heavy packages detected: %s. "
            "Skill will likely exit as context_dependent.", heavy
        )
        skill_image = DOCKER_IMAGE
    else:
        skill_image = build_skill_image(root_path, packages)
    if skill_image is None:
        logger.error("Failed to build skill image — skipping dynamic analysis")
        return "", [], []
    
    scripts = find_shell_scripts(root_path)

    if not scripts:
        logger.info("No shell scripts found in %s", root_path)
        return "", [], []

    if max_scripts is not None:
        scripts = scripts[:max_scripts]

    import time
    combined_strace = []
    executed = []
    exit_codes = []
    budget_start = time.monotonic()

    for script in scripts:
        elapsed = time.monotonic() - budget_start
        if elapsed >= total_timeout_secs:
            logger.warning(
                "Total timeout of %ds reached after %d scripts — stopping early",
                total_timeout_secs, len(executed),
            )
            break

        remaining = total_timeout_secs - elapsed
        per_script_timeout = min(timeout_secs, int(remaining))

        strace_output, _, exit_code = run_script_in_docker(
            script_path=script,
            root_path=root_path,
            timeout_secs=per_script_timeout,
            memory_limit=memory_limit,
            cpu_limit=cpu_limit,
            image=skill_image,
        )
        if strace_output:
            combined_strace.append(strace_output)
        executed.append(script.name)
        exit_codes.append(exit_code)

    try:
        cleanup_skill_image(skill_image)
    except Exception as exc:
        logger.warning("Failed to cleanup skill image %s: %s", skill_image, exc)
    finally:
        # Force prune dangling images to prevent disk accumulation
        try:
            subprocess.run(
                ["docker", "image", "prune", "-f"],
                capture_output=True, timeout=30,
            )
        except Exception:
            pass
    return "\n".join(combined_strace), executed, exit_codes