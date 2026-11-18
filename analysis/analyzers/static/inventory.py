"""File traversal, inventory building, and collector-metadata handling (v4).

Replacement for ``analyzers.static.inventory``. The only behavioral change 
is that ``scan_combo_patterns`` is called after ``scan_text_indicators``
for each file, enabling multi-token regex detection.

All other traversal logic, collector-metadata exclusion, and evidence
accumulation are identical to the production module.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyzers.static.extraction import extract_file_context
from analyzers.static.text import read_text_for_analysis

from analyzers.static.rules.definitions import (
    COLLECTOR_METADATA_FILES,
    FINDING_RULES,
    IMPORTANT_FILES,
)
from analyzers.static.rules.matching import (
    scan_combo_patterns,
    scan_env_var_references,
    scan_path_indicators,
    scan_text_indicators,
    scan_urls,
)

from analyzers.static.normalize import normalize

# --- Region routing ---
# Each file gets a `region` tag that downstream layers use to weight findings.

_REGION_BY_EXTENSION: dict[str, str] = {
    # bundled_code: executable scripts, attack-surface files
    ".py": "bundled_code", ".pyw": "bundled_code", ".pyx": "bundled_code",
    ".sh": "bundled_code", ".bash": "bundled_code",
    ".zsh": "bundled_code", ".ksh": "bundled_code", ".fish": "bundled_code",
    ".js": "bundled_code", ".mjs": "bundled_code", ".cjs": "bundled_code",
    ".ts": "bundled_code", ".tsx": "bundled_code", ".jsx": "bundled_code",
    ".ps1": "bundled_code", ".psm1": "bundled_code", ".psd1": "bundled_code",
    ".rb": "bundled_code",
    ".pl": "bundled_code", ".pm": "bundled_code",
    ".php": "bundled_code", ".phtml": "bundled_code",
    ".lua": "bundled_code",
    ".go": "bundled_code",
    ".rs": "bundled_code",

    # binary: not text-scanned, tagged for inventory/LLM visibility
    ".exe": "binary", ".dll": "binary", ".so": "binary",
    ".dylib": "binary", ".bin": "binary",
    ".pyc": "binary", ".pyo": "binary",

    # config: structured data files
    ".json": "config", ".yaml": "config", ".yml": "config",
    ".toml": "config", ".ipynb": "config",

    # prose: markdown, plain text, web markup
    ".md": "prose", ".markdown": "prose", ".mdx": "prose",
    ".txt": "prose", ".rst": "prose",
    ".html": "prose", ".htm": "prose", ".css": "prose",
}

_DEPENDENCY_FILENAMES: frozenset[str] = frozenset({
    "requirements.txt", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "gemfile", "gemfile.lock",
    "go.mod", "go.sum",
    "cargo.toml", "cargo.lock",
    "pyproject.toml",
})

_BUILD_SCRIPT_FILENAMES: frozenset[str] = frozenset({
    "dockerfile", "containerfile", "makefile", "gnumakefile",
})


def region_for_path(relative_path: str) -> str:
    """Return the region tag for a file by its relative path.

    Filename-based rules win over extension-based rules.
    Safe default is 'prose' so unknown extensions don't get code-weight rules.
    """
    name = relative_path.rsplit("/", 1)[-1].lower()

    if name in _BUILD_SCRIPT_FILENAMES:
        return "bundled_code"
    if name in _DEPENDENCY_FILENAMES:
        return "dependency"

    dot = name.rfind(".")
    if dot == -1:
        return "prose"
    ext = name[dot:]
    return _REGION_BY_EXTENSION.get(ext, "prose")

def _default_important_files() -> dict[str, bool]:
    return {name: False for name in IMPORTANT_FILES}


def _default_indicators() -> dict[str, dict[str, Any]]:
    return {category: {"count": 0, "evidence": []} for category in FINDING_RULES}


def _default_parsed_files() -> dict[str, Any]:
    return {
        "skill_md": None,
        "meta_json": None,
        "package_json": None,
        "requirements_txt": None,
        "python_files": [],
        "javascript_typescript_files": [],
        "shell_scripts": [],
    }


@dataclass
class ScanState:
    """Mutable accumulators produced by a single traversal of the artifact."""

    inventory: list[dict[str, Any]] = field(default_factory=list)
    collector_metadata: list[dict[str, Any]] = field(default_factory=list)
    skipped_files: list[dict[str, Any]] = field(default_factory=list)
    extension_counts: Counter[str] = field(default_factory=Counter)
    important_files: dict[str, bool] = field(default_factory=_default_important_files)
    indicators: dict[str, dict[str, Any]] = field(default_factory=_default_indicators)
    env_var_references: list[dict[str, Any]] = field(default_factory=list)
    external_urls: list[dict[str, Any]] = field(default_factory=list)
    parsed_files: dict[str, Any] = field(default_factory=_default_parsed_files)
    normalization_stats: dict[str, Any] = field(
        default_factory=lambda: {
            "files_normalized": 0,
            "nfkc_applied": 0,
            "invisible_chars_stripped": 0,
            "homoglyphs_folded": 0,
            "files_with_transforms": [],
        }
    )


def scan_tree(root: Path) -> ScanState:
    """Traverse ``root`` once and return the accumulated scan state."""
    state = ScanState()

    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue

        relative_path = path.relative_to(root).as_posix()
        path_name = Path(relative_path).name
        extension = path.suffix.lower() or "[none]"

        if path.is_symlink():
            if path_name in COLLECTOR_METADATA_FILES:
                state.collector_metadata.append({
                    "path": relative_path,
                    "type": "symlink",
                    "region": "collector_metadata",
                })
            else:
                state.inventory.append({
                    "path": relative_path,
                    "type": "symlink",
                    "region": "symlink",
                })
                scan_path_indicators(relative_path, state.indicators)
            continue

        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            state.skipped_files.append({"path": relative_path, "reason": str(exc)})
            continue

        if path_name in COLLECTOR_METADATA_FILES:
            state.collector_metadata.append({
                "path": relative_path,
                "size_bytes": size_bytes,
                "extension": extension,
                "region": "collector_metadata",
            })
            continue

        state.extension_counts[extension] += 1
        state.inventory.append({
            "path": relative_path,
            "size_bytes": size_bytes,
            "extension": extension,
            "region": region_for_path(relative_path),
        })

        for key in state.important_files:
            if key.lower() == path_name.lower():
                state.important_files[key] = True
                break

        scan_path_indicators(relative_path, state.indicators)

        text = read_text_for_analysis(path, size_bytes)
        if text is None:
            state.skipped_files.append({"path": relative_path, "reason": "binary_or_too_large"})
            continue

        # --- Normalization pass (Step 1 of v5) ---
        norm_result = normalize(text)
        text = norm_result.text

        if norm_result.any_transform:
            stats = state.normalization_stats
            stats["files_normalized"] += 1
            if norm_result.nfkc_applied:
                stats["nfkc_applied"] += 1
            stats["invisible_chars_stripped"] += norm_result.invisible_chars_stripped
            stats["homoglyphs_folded"] += norm_result.homoglyphs_folded
            stats["files_with_transforms"].append({
                "path": relative_path,
                "nfkc": norm_result.nfkc_applied,
                "invisible": norm_result.invisible_chars_stripped,
                "homoglyphs": norm_result.homoglyphs_folded,
            })

        #scan_text_indicators(relative_path, text, state.indicators)
        file_region = region_for_path(relative_path)
        scan_text_indicators(relative_path, text, state.indicators, region=file_region)
        scan_combo_patterns(relative_path, text, state.indicators)
        scan_env_var_references(relative_path, text, state.env_var_references)
        scan_urls(relative_path, text, state.external_urls)
        extract_file_context(
            relative_path, path_name, extension, text, state.parsed_files, state.indicators
        )

    return state