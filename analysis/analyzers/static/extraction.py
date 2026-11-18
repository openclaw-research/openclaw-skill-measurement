"""Parsed-file context extraction.

Builds the ``parsed_files`` section of the report: structured context for
SKILL.md, _meta.json, package.json, requirements.txt, and lightweight context
for Python, JavaScript/TypeScript, and shell files. package.json install
scripts also contribute dependency_or_install_script evidence.
"""
from __future__ import annotations

import json
import re
from typing import Any

from analyzers.static.rules.definitions import (
    JS_TS_EXTENSIONS,
    PYTHON_EXTENSIONS,
    SHELL_EXTENSIONS,
)
from analyzers.static.rules.matching import add_evidence
from analyzers.static.text import snippet_for_line

SHELL_SHEBANGS = ("#!/bin/sh", "#!/bin/bash", "#!/usr/bin/env bash")
INSTALL_SHELL_NAMES = {"install.sh", "setup.sh"}
PACKAGE_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def extract_file_context(
    relative_path: str,
    path_name: str,
    extension: str,
    text: str,
    parsed_files: dict[str, Any],
    indicators: dict[str, dict[str, Any]],
) -> None:
    lowered_name = path_name.lower()
    if lowered_name == "skill.md":
        parsed_files["skill_md"] = extract_markdown_context(relative_path, text)
    elif lowered_name == "_meta.json":
        parsed_files["meta_json"] = extract_json_context(relative_path, text)
    elif lowered_name == "package.json":
        parsed_files["package_json"] = extract_package_json_context(relative_path, text, indicators)
    elif lowered_name == "requirements.txt":
        parsed_files["requirements_txt"] = extract_requirements_context(relative_path, text)

    if extension in PYTHON_EXTENSIONS:
        parsed_files["python_files"].append(extract_code_context(relative_path, text))
    elif extension in JS_TS_EXTENSIONS:
        parsed_files["javascript_typescript_files"].append(extract_code_context(relative_path, text))
    elif extension in SHELL_EXTENSIONS or text.startswith(SHELL_SHEBANGS):
        parsed_files["shell_scripts"].append(extract_code_context(relative_path, text))
    elif lowered_name in INSTALL_SHELL_NAMES:
        parsed_files["shell_scripts"].append(extract_code_context(relative_path, text))


def extract_markdown_context(relative_path: str, text: str) -> dict[str, Any]:
    headings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("#"):
            headings.append({"line": line_number, "text": snippet_for_line(line)})
    return {"path": relative_path, "line_count": len(text.splitlines()), "headings": headings[:25]}


def extract_json_context(relative_path: str, text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"path": relative_path, "parse_error": str(exc)}

    if isinstance(data, dict):
        return {"path": relative_path, "top_level_keys": sorted(str(key) for key in data.keys())}
    return {"path": relative_path, "json_type": type(data).__name__}


def extract_package_json_context(
    relative_path: str,
    text: str,
    indicators: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"path": relative_path, "parse_error": str(exc)}

    if not isinstance(data, dict):
        return {"path": relative_path, "json_type": type(data).__name__}

    deps_raw = data.get("dependencies") or {}
    dependencies = sorted(deps_raw.keys()) if isinstance(deps_raw, dict) else []
    dev_deps_raw = data.get("devDependencies") or {}
    dev_dependencies = sorted(dev_deps_raw.keys()) if isinstance(dev_deps_raw, dict) else []
    scripts = data.get("scripts") or {}
    install_scripts = {}

    if isinstance(scripts, dict):
        for script_name in PACKAGE_INSTALL_SCRIPTS:
            if script_name in scripts:
                install_scripts[script_name] = str(scripts[script_name])
                add_evidence(
                    indicators,
                    "dependency_or_install_script",
                    script_name,
                    relative_path,
                    None,
                    str(scripts[script_name])[:180],
                )

    return {
        "path": relative_path,
        "dependencies": dependencies,
        "dev_dependencies": dev_dependencies,
        "scripts": sorted(str(key) for key in scripts.keys()) if isinstance(scripts, dict) else [],
        "install_scripts": install_scripts,
    }


def extract_requirements_context(relative_path: str, text: str) -> dict[str, Any]:
    packages = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(("-", "http://", "https://")):
            continue
        packages.append(re.split(r"[<>=!~\[]", stripped, maxsplit=1)[0].strip())
    return {"path": relative_path, "packages": sorted(package for package in packages if package)}


def extract_code_context(relative_path: str, text: str) -> dict[str, Any]:
    return {
        "path": relative_path,
        "line_count": len(text.splitlines()),
        "has_shebang": text.startswith("#!"),
    }
