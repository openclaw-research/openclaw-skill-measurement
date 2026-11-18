"""High-level static analyzer orchestrator (v4.2).

Deterministic static analyzer that traverses a downloaded artifact directory
and produces a structured risk report without executing artifact code. Uses
region-aware weighted term matching, combo regex patterns, and Unicode
normalization to reduce false positives while maintaining a recall-first
triage funnel for downstream layers.

This module re-exports ``COLLECTOR_METADATA_FILES`` and the analyzer class as
the package's public entry point, matching the interface expected by
``StaticAnalysisPipeline``.
"""
from __future__ import annotations

from pathlib import Path

try:
    from analyzers.base import AnalysisReport
except ImportError:
    from dataclasses import dataclass
    from typing import Any as _Any

    @dataclass(frozen=True)
    class AnalysisReport:
        status: str
        risk_level: str
        summary: str
        result_json: dict[str, _Any]
        findings: list[dict[str, _Any]]

from analyzers.static.rules.definitions import (
    COLLECTOR_METADATA_FILES,
    MAX_ENV_EVIDENCE,
    MAX_URL_EVIDENCE,
)
from analyzers.static.findings import build_findings
from analyzers.static.inventory import scan_tree
from analyzers.static.scoring import build_summary, calculate_risk_level

__all__ = ["StaticAnalyzer", "COLLECTOR_METADATA_FILES"]


class StaticAnalyzer:
    """Static analyzer v4. Region-aware weighted term matching with Unicode normalization."""

    name = "static"
    version = "4.2"

    def analyze(self, root_path: Path) -> AnalysisReport:
        """Analyze a downloaded artifact directory without executing artifact code."""
        root = Path(root_path).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError(f"Analysis root does not exist or is not a directory: {root}")

        state = scan_tree(root)

        counts = {category: data["count"] for category, data in state.indicators.items()}
        risk_level = calculate_risk_level(counts)
        findings = build_findings(
            counts, state.indicators, state.env_var_references, state.external_urls
        )
        summary = build_summary(len(state.inventory), counts, risk_level)

        result_json = {
            "analyzer": {"name": self.name, "version": self.version},
            "file_count": len(state.inventory),
            "file_inventory": state.inventory,
            "collector_metadata_files": state.collector_metadata,
            "important_files": state.important_files,
            "extension_counts": dict(sorted(state.extension_counts.items())),
            "env_var_references": {
                "count": len(state.env_var_references),
                "unique_names": sorted({item["name"] for item in state.env_var_references}),
                "evidence": state.env_var_references[:MAX_ENV_EVIDENCE],
            },
            "external_urls": {
                "count": len(state.external_urls),
                "domains": sorted(
                    {item["domain"] for item in state.external_urls if item.get("domain")}
                ),
                "evidence": state.external_urls[:MAX_URL_EVIDENCE],
            },
            "indicators": state.indicators,
            "parsed_files": state.parsed_files,
            "skipped_files": state.skipped_files,
            "normalization_stats": state.normalization_stats,
        }

        return AnalysisReport(
            status="success",
            risk_level=risk_level,
            summary=summary,
            result_json=result_json,
            findings=findings,
        )