"""Risk-level calculation and the human-readable result summary (v4).

Risk is a deterministic heuristic over indicator counts:
- ``critical`` when reverse_shell_patterns or credential theft + exfiltration
  co-occur, or download_and_execute + network/process indicators.
- ``high`` when secret or suspicious-prompting indicators co-occur with
  network or process-execution indicators, or when high-severity categories
  have standalone hits.
- ``medium`` when any medium-severity category is present.
- ``low`` when at least one indicator fired but none reach medium threshold.
- ``none`` when zero indicators fired across all categories.

Existing v3 co-occurrence logic is preserved as a subset.
"""

from __future__ import annotations


def calculate_risk_level(counts: dict[str, int]) -> str:
    """Determine risk level from indicator counts across all categories."""

    # --- Critical: unambiguous compromise indicators ---

    if counts.get("reverse_shell_patterns", 0) > 0:
        return "critical"

    if counts.get("download_and_execute", 0) > 0 and (
        counts.get("network_access", 0) > 0 or counts.get("process_execution", 0) > 0
    ):
        return "critical"

    if counts.get("credential_theft_targets", 0) > 0 and (
        counts.get("exfiltration_channels", 0) > 0
    ):
        return "critical"

    # --- High: strong co-occurrence signals ---

    if counts.get("secret_handling", 0) > 0 and (
        counts.get("network_access", 0) > 0 or counts.get("process_execution", 0) > 0
    ):
        return "high"

    if counts.get("suspicious_prompting", 0) > 0 and (
        counts.get("network_access", 0) > 0 or counts.get("process_execution", 0) > 0
    ):
        return "high"

    if counts.get("credential_theft_targets", 0) > 0 and (
        counts.get("network_access", 0) > 0 or counts.get("process_execution", 0) > 0
    ):
        return "high"

    if counts.get("exfiltration_channels", 0) > 0:
        return "high"

    if counts.get("obfuscation_techniques", 0) > 0 and (
        counts.get("network_access", 0) > 0 or counts.get("process_execution", 0) > 0
    ):
        return "high"

    if counts.get("download_and_execute", 0) > 0:
        return "high"

    if counts.get("suspicious_prompting", 0) > 0:
        return "high"

    # --- Medium: any medium-severity category active ---

    medium_categories = (
        "network_access",
        "process_execution",
        "filesystem_access",
        "secret_handling",
        "dependency_or_install_script",
        "persistence_mechanisms",
        "hidden_content",
    )
    if any(counts.get(category, 0) > 0 for category in medium_categories):
        return "medium"

    # --- Low: at least one indicator fired ---

    if any(counts.get(category, 0) > 0 for category in counts):
        return "low"

    # --- None: zero indicators across all categories ---

    return "none"


def build_summary(file_count: int, counts: dict[str, int], risk_level: str) -> str:
    """Build a short human-readable summary string."""
    active_counts = {category: count for category, count in counts.items() if count}
    if active_counts:
        indicator_text = ", ".join(
            f"{category}={count}" for category, count in active_counts.items()
        )
    else:
        indicator_text = "no risky indicators"
    return f"Scanned {file_count} files; risk={risk_level}; {indicator_text}."