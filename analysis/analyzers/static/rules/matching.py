"""Indicator matching helpers (v5 — word boundaries, case sensitivity, region filtering).

Adds per-term controls for boundary checking, case sensitivity, and region-aware
filtering alongside the existing combo-pattern and env/URL scanners.

Term definitions can be either:
  - A plain string (backward compatible, old behavior: case-insensitive substring)
  - A dict with keys: term, boundary, case_sensitive, valid_regions, weight
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from analyzers.static.text import snippet_for_line

from analyzers.static.rules.definitions import (
    COMBO_PATTERNS,
    ENV_PATTERNS,
    FINDING_RULES,
    MAX_ENV_EVIDENCE,
    MAX_EVIDENCE_PER_CATEGORY,
    MAX_URL_EVIDENCE,
    PATH_INDICATOR_CATEGORIES,
    URL_PATTERN,
)


# Default region weight applied when a region is not in `region_weights`.
# Policy C (implicit-low): unlisted regions get faint audit weight (0.1) so
# findings remain visible to downstream layers without driving the risk tier.
DEFAULT_REGION_WEIGHT = 0.1

# Threshold above which a finding contributes to the indicator count.
# Findings below threshold are still recorded as evidence (so the LLM layer
# sees them) but do not drive risk_level computation.
COUNT_THRESHOLD = 1.0

@dataclass(frozen=True, slots=True)
class TermConfig:
    """Parsed configuration for a single detection term."""
    term: str
    term_lower: str
    boundary: str = "none"   # "none" | "word" | "url" | "operator"
    case_sensitive: bool = False
    region_weights: dict[str, float] | None = None  # None = full weight everywhere
    base_weight: float = 1.0


def _parse_term(raw) -> TermConfig:
    """Convert a raw term (str or dict) into a TermConfig."""
    if isinstance(raw, str):
        return TermConfig(term=raw, term_lower=raw.lower())

    # Boundary normalization: accept legacy True/False/str forms.
    raw_boundary = raw.get("boundary", "none")
    if raw_boundary is True:
        boundary = "word"
    elif raw_boundary is False:
        boundary = "none"
    else:
        boundary = str(raw_boundary)
        if boundary not in ("none", "word", "url", "operator"):
            raise ValueError(f"Unknown boundary mode: {boundary!r}")

    # Region weights normalization: accept legacy valid_regions list as a
    # binary {region: 1.0} mapping. New schema uses region_weights directly.
    region_weights = raw.get("region_weights")
    if region_weights is None and "valid_regions" in raw:
        region_weights = {r: 1.0 for r in raw["valid_regions"]}

    return TermConfig(
        term=raw["term"],
        term_lower=raw["term"].lower(),
        boundary=boundary,
        case_sensitive=raw.get("case_sensitive", False),
        region_weights=region_weights,
        base_weight=raw.get("weight", 1.0),
    )


def _is_word_char(ch: str) -> bool:
    """\\w boundary: alphanumeric or underscore."""
    return ch.isalnum() or ch == "_"


_URL_CONTINUE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._~:/?#[]@!$&'()*+,;=-"
)


def _is_url_continue_char(ch: str) -> bool:
    """URL boundary: any RFC 3986 unreserved/reserved/sub-delim char."""
    return ch in _URL_CONTINUE_CHARS


_OPERATOR_CONTINUE_CHARS = frozenset("|&;<>(){}[]")


def _is_operator_continue_char(ch: str) -> bool:
    """Operator boundary: another shell operator means this isn't a real pipe."""
    return ch in _OPERATOR_CONTINUE_CHARS


def _boundary_ok(line: str, pos: int, end_pos: int, mode: str) -> bool:
    """Return True if the match at [pos:end_pos] satisfies the boundary mode."""
    if mode == "none":
        return True

    if mode == "word":
        check = _is_word_char
    elif mode == "url":
        check = _is_url_continue_char
    elif mode == "operator":
        check = _is_operator_continue_char
    else:
        return True

    if pos > 0 and check(line[pos - 1]):
        return False
    if end_pos < len(line) and check(line[end_pos]):
        return False
    return True

# Pre-compile all term configs at import time.
# Dict of category -> list[TermConfig]
_COMPILED_RULES: dict[str, list[TermConfig]] = {
    category: [_parse_term(t) for t in rule["terms"]]
    for category, rule in FINDING_RULES.items()
}

# Evidence recording
def add_evidence(
    indicators: dict[str, dict[str, Any]],
    category: str,
    term: str,
    relative_path: str,
    line_number: int | None,
    snippet: str | None,
    weight: float = 1.0,
) -> None:
    """Record one indicator match.

    Findings with weight >= COUNT_THRESHOLD contribute to the category count.
    Findings below threshold are still stored as evidence but do not drive
    risk_level computation — they remain visible for the LLM layer.
    """
    data = indicators[category]

    if weight >= COUNT_THRESHOLD:
        data["count"] += 1

    if len(data["evidence"]) >= MAX_EVIDENCE_PER_CATEGORY:
        return

    evidence: dict[str, Any] = {
        "path": relative_path,
        "indicator": term,
        "weight": round(weight, 3),
    }
    if line_number is not None:
        evidence["line"] = line_number
    if snippet is not None:
        evidence["snippet"] = snippet
    data["evidence"].append(evidence)

# Core text scanning 
def scan_text_indicators(
    relative_path: str,
    text: str,
    indicators: dict[str, dict[str, Any]],
    region: str = "prose",
) -> None:
    """Match every line against all terms, applying per-term controls.

    Controls applied per term:
      - region_weights: weight multiplier per region (Policy C default 0.1)
      - case_sensitive: search original line vs lowered line
      - boundary: word/url/operator boundary check

    Findings with effective weight = 0 are dropped entirely.
    Findings with 0 < weight < COUNT_THRESHOLD are recorded as evidence
    but do not increment the category count.
    """
    for line_number, line in enumerate(text.splitlines(), start=1):
        lowered = line.lower()

        for category, term_configs in _COMPILED_RULES.items():
            for tc in term_configs:

                # --- Resolve effective weight for this region ---
                if tc.region_weights is None:
                    region_weight = 1.0
                else:
                    region_weight = tc.region_weights.get(region, DEFAULT_REGION_WEIGHT)

                if region_weight <= 0.0:
                    continue  # explicit hard-gate

                effective_weight = tc.base_weight * region_weight
                if effective_weight <= 0.0:
                    continue

                # --- Find the term ---
                if tc.case_sensitive:
                    pos = line.find(tc.term)
                else:
                    pos = lowered.find(tc.term_lower)

                if pos == -1:
                    continue

                # --- Boundary check ---
                end_pos = pos + len(tc.term)
                if not _boundary_ok(line, pos, end_pos, tc.boundary):
                    continue

                add_evidence(
                    indicators,
                    category,
                    tc.term,
                    relative_path,
                    line_number,
                    snippet_for_line(line),
                    weight=effective_weight,
                )

# Combo pattern scanning
def scan_combo_patterns(
    relative_path: str,
    text: str,
    indicators: dict[str, dict[str, Any]],
) -> None:
    """Run multi-token regex patterns against the full file text."""
    for combo in COMBO_PATTERNS:
        match = combo["pattern"].search(text)
        if match is None:
            continue

        match_start = match.start()
        line_number = text[:match_start].count("\n") + 1
        matched_text = match.group(0)
        snippet = " ".join(matched_text.strip().split())[:180]

        add_evidence(
            indicators,
            combo["category"],
            combo["id"],
            relative_path,
            line_number,
            snippet,
        )

# Path, env var, and URL scanning 
def scan_path_indicators(
    relative_path: str,
    indicators: dict[str, dict[str, Any]],
) -> None:
    """Match file paths against path-checked categories. Always full weight."""
    lowered_path = relative_path.lower()
    for category in PATH_INDICATOR_CATEGORIES:
        for tc in _COMPILED_RULES[category]:
            if tc.term_lower in lowered_path:
                add_evidence(
                    indicators, category, tc.term, relative_path, None, None,
                    weight=tc.base_weight,
                )


def scan_env_var_references(
    relative_path: str,
    text: str,
    env_var_references: list[dict[str, Any]],
) -> None:
    """Extract environment variable access patterns."""
    for line_number, line in enumerate(text.splitlines(), start=1):
        for syntax, pattern in ENV_PATTERNS:
            for match in pattern.finditer(line):
                if len(env_var_references) >= MAX_ENV_EVIDENCE:
                    return
                env_var_references.append(
                    {
                        "path": relative_path,
                        "line": line_number,
                        "syntax": syntax,
                        "name": match.group(1),
                        "snippet": snippet_for_line(line),
                    }
                )


def scan_urls(
    relative_path: str,
    text: str,
    external_urls: list[dict[str, Any]],
) -> None:
    """Extract external URLs."""
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in URL_PATTERN.finditer(line):
            if len(external_urls) >= MAX_URL_EVIDENCE:
                return
            url = match.group(0).rstrip(".,")
            try:
                domain = urlparse(url).netloc.lower()
            except ValueError:
                domain = ""
            external_urls.append(
                {
                    "path": relative_path,
                    "line": line_number,
                    "url": url,
                    "domain": domain,
                    "snippet": snippet_for_line(line),
                }
            )