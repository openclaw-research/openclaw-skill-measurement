"""Text reading and snippet helpers for the static analyzer."""
from __future__ import annotations

from pathlib import Path

from analyzers.static.rules.definitions import MAX_TEXT_BYTES


def read_text_for_analysis(path: Path, size_bytes: int) -> str | None:
    """Return decoded text for a file, or None if it is too large or binary."""
    if size_bytes > MAX_TEXT_BYTES:
        return None

    try:
        data = path.read_bytes()
    except OSError:
        return None

    if b"\x00" in data:
        return None

    return data.decode("utf-8", errors="ignore")


def snippet_for_line(line: str) -> str:
    """Collapse whitespace and truncate a line for compact evidence snippets."""
    return " ".join(line.strip().split())[:180]
