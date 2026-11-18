"""Structured finding construction from accumulated indicators.

Findings are derived from indicator counts and evidence. Cross-category
escalation rules in ``ESCALATION_RULES`` produce additional higher-severity
findings when dangerous combinations co-occur (e.g. reverse_shell_patterns
together with network_access is critical). Environment-variable and external
URL evidence produce additional low-severity findings.
"""
from __future__ import annotations

from typing import Any

from analyzers.static.rules.definitions import (
    FINDING_RULES,
    MAX_ENV_EVIDENCE,
    MAX_URL_EVIDENCE,
)


# Cross-category escalation rules. Each rule produces an escalated finding when
# the primary category has hits and at least one of the required categories also
# has hits. Rules are evaluated in order; multiple rules can fire.
ESCALATION_RULES = (
    # --- Critical escalations ---
    {
        "primary": "credential_theft_targets",
        "requires_any": ("exfiltration_channels",),
        "escalated_severity": "critical",
        "title": "Credential theft targets with exfiltration channels detected",
        "description": (
            "References to credential file paths appear together with known "
            "exfiltration endpoints — strong indicator of data theft."
        ),
        "include_categories": ("credential_theft_targets", "exfiltration_channels"),
    },
    {
        "primary": "reverse_shell_patterns",
        "requires_any": ("network_access", "process_execution"),
        "escalated_severity": "critical",
        "title": "Reverse shell with network or execution capability",
        "description": (
            "Reverse shell patterns co-occur with network or process execution "
            "indicators — indicates active compromise capability."
        ),
        "include_categories": ("reverse_shell_patterns", "network_access", "process_execution"),
    },
    # --- High escalations ---
    {
        "primary": "secret_handling",
        "requires_any": ("network_access", "process_execution"),
        "escalated_severity": "high",
        "title": "Secret indicators appear with network or process execution indicators",
        "description": (
            "Credential-related terms appear together with network or process execution "
            "indicators, which may increase exposure risk."
        ),
        "include_categories": ("secret_handling", "network_access", "process_execution"),
    },
    {
        "primary": "suspicious_prompting",
        "requires_any": ("network_access", "process_execution"),
        "escalated_severity": "high",
        "title": "Suspicious instructions appear with network or process execution indicators",
        "description": (
            "Prompting or behavioral instructions related to credentials, persistence, "
            "background execution, or exfiltration appear with stronger execution indicators."
        ),
        "include_categories": ("suspicious_prompting", "network_access", "process_execution"),
    },
    {
        "primary": "credential_theft_targets",
        "requires_any": ("network_access", "process_execution"),
        "escalated_severity": "high",
        "title": "Credential theft targets with network or process execution",
        "description": (
            "References to credential file paths co-occur with network or process "
            "execution indicators — may indicate credential exfiltration."
        ),
        "include_categories": ("credential_theft_targets", "network_access", "process_execution"),
    },
    {
        "primary": "obfuscation_techniques",
        "requires_any": ("network_access", "process_execution"),
        "escalated_severity": "high",
        "title": "Obfuscation with network or process execution indicators",
        "description": (
            "Code obfuscation patterns co-occur with network or process execution "
            "indicators — may indicate hidden payload delivery."
        ),
        "include_categories": ("obfuscation_techniques", "network_access", "process_execution"),
    },
    {
        "primary": "download_and_execute",
        "requires_any": ("network_access",),
        "escalated_severity": "high",
        "title": "Download-and-execute chain with network access",
        "description": (
            "Download-and-execute patterns co-occur with network access — "
            "indicates remote payload delivery chain."
        ),
        "include_categories": ("download_and_execute", "network_access"),
    },
)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_rank(severity: str) -> int:
    """Return a numeric rank for severity comparison."""
    return _SEVERITY_ORDER.get(severity, -1)


def build_findings(
    counts: dict[str, int],
    indicators: dict[str, dict[str, Any]],
    env_var_references: list[dict[str, Any]],
    external_urls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the structured findings list from accumulated indicators."""
    findings: list[dict[str, Any]] = []

    # --- Cross-category escalation findings ---
    fired_escalations: set[str] = set()

    for rule in ESCALATION_RULES:
        primary = rule["primary"]
        if counts.get(primary, 0) == 0:
            continue
        if not any(counts.get(req, 0) > 0 for req in rule["requires_any"]):
            continue

        findings.append(
            {
                "category": primary,
                "severity": rule["escalated_severity"],
                "title": rule["title"],
                "description": rule["description"],
                "evidence_json": {
                    cat: indicators[cat]["evidence"]
                    for cat in rule["include_categories"]
                    if counts.get(cat, 0) > 0
                },
            }
        )
        fired_escalations.add(primary)

    # --- Per-category findings ---
    for category, rule in FINDING_RULES.items():
        if counts.get(category, 0) == 0:
            continue

        severity = rule["severity"]

        # If this category fired an escalation, bump its standalone severity.
        if category in fired_escalations:
            for esc_rule in ESCALATION_RULES:
                if esc_rule["primary"] == category:
                    esc_sev = esc_rule["escalated_severity"]
                    if _severity_rank(esc_sev) > _severity_rank(severity):
                        severity = esc_sev
                    break

        findings.append(
            {
                "category": category,
                "severity": severity,
                "title": rule["title"],
                "description": rule["description"],
                "evidence_json": {
                    "count": counts[category],
                    "evidence": indicators[category]["evidence"],
                },
            }
        )

    # --- Env var reference finding ---
    if env_var_references:
        findings.append(
            {
                "category": "secret_handling",
                "severity": "low",
                "title": "Environment variable references found",
                "description": "Static patterns found references to environment variables.",
                "evidence_json": {
                    "count": len(env_var_references),
                    "evidence": env_var_references[:MAX_ENV_EVIDENCE],
                },
            }
        )

    # --- External URL finding ---
    if external_urls:
        findings.append(
            {
                "category": "network_access",
                "severity": "low",
                "title": "External URLs found",
                "description": "Static parsing found external HTTP or HTTPS URLs.",
                "evidence_json": {
                    "count": len(external_urls),
                    "domains": sorted(
                        {item["domain"] for item in external_urls if item.get("domain")}
                    ),
                    "evidence": external_urls[:MAX_URL_EVIDENCE],
                },
            }
        )

    return findings