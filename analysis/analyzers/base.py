from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class AnalysisReport:
    status: str
    risk_level: str
    summary: str
    result_json: dict[str, Any]
    findings: list[dict[str, Any]]


class Analyzer(Protocol):
    name: str
    version: str

    def analyze(self, root_path: Path) -> AnalysisReport:
        ...
