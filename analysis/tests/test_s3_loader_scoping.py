"""
Validate that artifact materialization is scoped to exactly one snapshot.

The crawler stores two coexisting S3 layouts under the same version prefix:
legacy flat ({source}/{slug}/{version}/...) and hash-segmented
({source}/{slug}/{version}/{hash12}/...). A legacy flat artifact_uri is a
string prefix of every sibling hash-segmented snapshot, so an unscoped
recursive listing downloads the same skill twice (root copy + {hash12}/ copy)
and double-counts every indicator. These tests reproduce the affected layout
observed in production (e.g. clawhub/traefik-mantrae-diagnostics/0.1.0/ with
a sibling 8d8ecf164e6d/ snapshot) against a stubbed S3 client.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from artifacts.s3_loader import (
    S3ArtifactLoader,
    is_hash_segmented_prefix,
    is_sibling_snapshot_key,
)

BUCKET = "test-bucket"

# Mirrors the production example: legacy flat objects written 2026-05-26,
# sibling hash-segmented snapshot written by the 2026-07-02 verify crawl.
FLAT_PREFIX = "clawhub/traefik-mantrae-diagnostics/0.1.0/"
HASH_PREFIX = FLAT_PREFIX + "8d8ecf164e6d/"

KEYS = [
    FLAT_PREFIX + "SKILL.md",
    FLAT_PREFIX + "_detail.json",
    FLAT_PREFIX + "_meta.json",
    FLAT_PREFIX + "scripts/mantrae_api.py",
    HASH_PREFIX + "SKILL.md",
    HASH_PREFIX + "_detail.json",
    HASH_PREFIX + "_meta.json",
    HASH_PREFIX + "scripts/mantrae_api.py",
    HASH_PREFIX + "skill-card.md",
]


class StubPaginator:
    def __init__(self, keys):
        self.keys = keys

    def paginate(self, Bucket, Prefix):
        contents = [
            {"Key": key, "Size": 10} for key in self.keys if key.startswith(Prefix)
        ]
        yield {"Contents": contents}


class StubS3Client:
    def __init__(self, keys):
        self.keys = keys
        self.downloaded = []

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return StubPaginator(self.keys)

    def download_file(self, bucket, key, target_path):
        self.downloaded.append(key)
        Path(target_path).write_bytes(b"stub")


@pytest.fixture
def loader_and_client():
    client = StubS3Client(KEYS)
    loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1", client=client)
    return loader, client


def test_flat_uri_skips_sibling_hash_snapshot(tmp_path, loader_and_client):
    loader, client = loader_and_client

    result = loader.download_prefix(f"s3://{BUCKET}/{FLAT_PREFIX}", tmp_path)

    assert result.object_count == 4
    assert sorted(client.downloaded) == sorted(
        key for key in KEYS if key.startswith(FLAT_PREFIX) and not key.startswith(HASH_PREFIX)
    )
    # Nothing was materialized under the sibling hash directory.
    assert not (tmp_path / "8d8ecf164e6d").exists()
    assert (tmp_path / "SKILL.md").exists()
    assert (tmp_path / "scripts" / "mantrae_api.py").exists()


def test_hash_uri_stays_scoped_to_that_snapshot(tmp_path, loader_and_client):
    loader, client = loader_and_client

    result = loader.download_prefix(f"s3://{BUCKET}/{HASH_PREFIX}", tmp_path)

    assert result.object_count == 5
    assert sorted(client.downloaded) == sorted(
        key for key in KEYS if key.startswith(HASH_PREFIX)
    )
    # Files land at the artifact root, not under a hash directory.
    assert (tmp_path / "SKILL.md").exists()
    assert (tmp_path / "skill-card.md").exists()


def test_unaffected_flat_skill_unchanged(tmp_path):
    # A flat prefix with no sibling hash snapshot materializes exactly as before.
    keys = [
        "clawhub/0codekit/1.0.4/SKILL.md",
        "clawhub/0codekit/1.0.4/_detail.json",
        "clawhub/0codekit/1.0.4/skill-card.md",
    ]
    client = StubS3Client(keys)
    loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1", client=client)

    result = loader.download_prefix(f"s3://{BUCKET}/clawhub/0codekit/1.0.4/", tmp_path)

    assert result.object_count == 3
    assert sorted(client.downloaded) == sorted(keys)


def test_hexlike_filename_at_flat_root_is_not_skipped(tmp_path):
    # Only {hash12}/ SUBTREES are siblings; a plain file whose name happens to
    # look like 12 hex chars is real skill content and must be kept.
    keys = [
        "clawhub/some-skill/1.0.0/SKILL.md",
        "clawhub/some-skill/1.0.0/deadbeef1234",
    ]
    client = StubS3Client(keys)
    loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1", client=client)

    result = loader.download_prefix(f"s3://{BUCKET}/clawhub/some-skill/1.0.0/", tmp_path)

    assert result.object_count == 2


def test_prefix_and_key_helpers():
    assert is_hash_segmented_prefix(HASH_PREFIX)
    assert not is_hash_segmented_prefix(FLAT_PREFIX)
    assert is_sibling_snapshot_key("8d8ecf164e6d/SKILL.md")
    assert is_sibling_snapshot_key("8d8ecf164e6d/scripts/x.py")
    assert not is_sibling_snapshot_key("SKILL.md")
    assert not is_sibling_snapshot_key("scripts/x.py")
    assert not is_sibling_snapshot_key("8d8ecf164e6d")  # bare file, not a subtree
    assert not is_sibling_snapshot_key("NOTHEXNOTHEX/SKILL.md")

def test_download_skips_key_that_conflicts_with_existing_directory():
    """S3ArtifactLoader should skip file keys that conflict with existing directories.
    
    Some skill artifacts have both a directory 'foo/' and a file key 'foo'
    in S3. When the directory is created first (from 'foo/bar.txt'), trying
    to download 'foo' as a file raises FileExistsError. The loader should
    skip such conflicting keys instead of crashing.
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        # Simulate S3 objects where 'js' is both a directory prefix and a file key
        objects = [
            {"Key": "clawhub/test-skill/1.0.0/js/app.js", "Size": 100},
            {"Key": "clawhub/test-skill/1.0.0/js", "Size": 50},  # conflicts with js/ dir
            {"Key": "clawhub/test-skill/1.0.0/README.md", "Size": 200},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        # js/app.js creates the js/ directory first
        # then 'js' key should be skipped because js/ directory already exists
        assert "clawhub/test-skill/1.0.0/js/app.js" in downloaded
        assert "clawhub/test-skill/1.0.0/js" not in downloaded
        assert "clawhub/test-skill/1.0.0/README.md" in downloaded
        assert (tmp / "js").is_dir()
        assert not (tmp / "js").is_file()

    finally:
        shutil.rmtree(tmp)


def test_download_does_not_skip_normal_file_keys():
    """S3ArtifactLoader should still download normal file keys correctly."""
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            {"Key": "clawhub/test-skill/1.0.0/README.md", "Size": 200},
            {"Key": "clawhub/test-skill/1.0.0/SKILL.md", "Size": 300},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        assert "clawhub/test-skill/1.0.0/README.md" in downloaded
        assert "clawhub/test-skill/1.0.0/SKILL.md" in downloaded
        assert result.object_count == 2

    finally:
        shutil.rmtree(tmp)

@pytest.mark.skipif(sys.platform == "win32", reason="Path handling differs on Windows")
def test_download_unlinks_file_when_parent_path_is_file():
    """S3ArtifactLoader should remove a file that conflicts with a needed directory.
    
    When '.claude' is downloaded as a file first, then '.claude/settings.json'
    tries to create '.claude/' as a directory — the file should be removed
    and replaced with a directory.
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            {"Key": "clawhub/test-skill/1.0.0/.claude", "Size": 50},
            {"Key": "clawhub/test-skill/1.0.0/.claude/settings.json", "Size": 100},
            {"Key": "clawhub/test-skill/1.0.0/README.md", "Size": 200},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        # .claude/settings.json should be downloaded successfully
        assert "clawhub/test-skill/1.0.0/.claude/settings.json" in downloaded
        assert "clawhub/test-skill/1.0.0/README.md" in downloaded
        # .claude should now be a directory, not a file
        assert (tmp / ".claude").is_dir()
        assert (tmp / ".claude" / "settings.json").is_file()

    finally:
        shutil.rmtree(tmp)


@pytest.mark.skipif(sys.platform == "win32", reason="Path handling differs on Windows")
def test_download_handles_data_directory_conflict():
    """S3ArtifactLoader should handle 'data' file vs 'data/' directory conflict."""
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            {"Key": "clawhub/test-skill/1.0.0/data", "Size": 50},
            {"Key": "clawhub/test-skill/1.0.0/data/config.json", "Size": 100},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        assert "clawhub/test-skill/1.0.0/data/config.json" in downloaded
        assert (tmp / "data").is_dir()
        assert (tmp / "data" / "config.json").is_file()

    finally:
        shutil.rmtree(tmp)


@pytest.mark.skipif(sys.platform == "win32", reason="Path handling differs on Windows")
def test_download_handles_both_conflict_patterns():
    """S3ArtifactLoader should handle both conflict patterns in the same artifact.

    Pattern 1: file key conflicts with existing directory (directory created first)
    Pattern 2: file key needs to become a directory (file downloaded first)
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            # Pattern 2: 'assets' file downloaded before 'assets/logo.png'
            {"Key": "clawhub/test-skill/1.0.0/assets", "Size": 50},
            {"Key": "clawhub/test-skill/1.0.0/assets/logo.png", "Size": 200},
            # Pattern 1: 'js/app.js' creates 'js/' dir, then 'js' file key conflicts
            {"Key": "clawhub/test-skill/1.0.0/js/app.js", "Size": 100},
            {"Key": "clawhub/test-skill/1.0.0/js", "Size": 30},
            {"Key": "clawhub/test-skill/1.0.0/README.md", "Size": 300},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        # assets/logo.png should be downloaded
        assert "clawhub/test-skill/1.0.0/assets/logo.png" in downloaded
        assert (tmp / "assets").is_dir()
        # js/app.js should be downloaded, js file key skipped
        assert "clawhub/test-skill/1.0.0/js/app.js" in downloaded
        assert "clawhub/test-skill/1.0.0/js" not in downloaded
        assert (tmp / "js").is_dir()
        assert "clawhub/test-skill/1.0.0/README.md" in downloaded

    finally:
        shutil.rmtree(tmp)


@pytest.mark.skipif(sys.platform == "win32", reason="Path handling differs on Windows")
def test_download_handles_claude_plugin_conflict():
    """S3ArtifactLoader should handle .claude-plugin file vs directory conflict."""
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            {"Key": "clawhub/test-skill/1.0.0/.claude-plugin", "Size": 50},
            {"Key": "clawhub/test-skill/1.0.0/.claude-plugin/manifest.json", "Size": 100},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/test-skill/1.0.0/", tmp
            )

        assert "clawhub/test-skill/1.0.0/.claude-plugin/manifest.json" in downloaded
        assert (tmp / ".claude-plugin").is_dir()
        assert (tmp / ".claude-plugin" / "manifest.json").is_file()

    finally:
        shutil.rmtree(tmp)

def test_real_world_vsp_skill_zero_byte_directory_markers():
    """Mimics exact S3 structure of clawhub/vsp/0.1.0/eb24a8728038/.
    
    Zero-byte objects are directory markers (.claude, .codex, assets, benchmark,
    scripts/wechat_fetch). Real files have non-zero sizes.
    This was the exact pattern causing FileExistsError in runs #82-#85.
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            # Zero-byte directory markers
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/.claude", "Size": 0},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/.codex", "Size": 0},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/assets", "Size": 0},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/benchmark", "Size": 0},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch", "Size": 0},
            # Real files
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/.claude/CLAUDE.md", "Size": 11237},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/.codex/instructions.md", "Size": 11822},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/.gitignore", "Size": 430},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/SKILL.md", "Size": 16832},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/assets/report-template.md", "Size": 3127},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/benchmark/README.md", "Size": 2182},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch.py", "Size": 3782},
            {"Key": "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch/wx-article-fetch.js", "Size": 9547},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"fake content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/vsp/0.1.0/eb24a8728038/", tmp
            )

        # Zero-byte directory markers should NOT be downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/.claude" not in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/.codex" not in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/assets" not in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/benchmark" not in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch" not in downloaded

        # Real files should be downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/.claude/CLAUDE.md" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/.codex/instructions.md" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/.gitignore" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/SKILL.md" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/assets/report-template.md" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/benchmark/README.md" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch.py" in downloaded
        assert "clawhub/vsp/0.1.0/eb24a8728038/scripts/wechat_fetch/wx-article-fetch.js" in downloaded

        # Directories should be created
        assert (tmp / ".claude").is_dir()
        assert (tmp / ".codex").is_dir()
        assert (tmp / "assets").is_dir()
        assert (tmp / "benchmark").is_dir()
        assert (tmp / "scripts" / "wechat_fetch").is_dir()

        # object_count should not include zero-byte markers
        assert result.object_count == 8

    finally:
        shutil.rmtree(tmp)


def test_real_world_email_swipe_nested_directory_markers():
    """Mimics clawhub/email-swipe/0.1.0/53b11dc289b0/.
    
    Has nested zero-byte markers: assets (0) and assets/ui (0).
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            # Zero-byte directory markers (nested)
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/assets", "Size": 0},
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui", "Size": 0},
            # Real files
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/.gitignore", "Size": 426},
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/SKILL.md", "Size": 9363},
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui/app.js", "Size": 102485},
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui/index.html", "Size": 22191},
            {"Key": "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui/styles.css", "Size": 37566},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"fake content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/email-swipe/0.1.0/53b11dc289b0/", tmp
            )

        # Nested zero-byte markers not downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/assets" not in downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui" not in downloaded

        # Real files downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/.gitignore" in downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/SKILL.md" in downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui/app.js" in downloaded
        assert "clawhub/email-swipe/0.1.0/53b11dc289b0/assets/ui/index.html" in downloaded

        # Nested directories created correctly
        assert (tmp / "assets").is_dir()
        assert (tmp / "assets" / "ui").is_dir()
        assert result.object_count == 5

    finally:
        shutil.rmtree(tmp)


def test_real_world_postnext_skill_non_zero_file_with_directory_name():
    """Mimics clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/.
    
    Has 'postnext' as a real non-zero file (10544 bytes) — not a directory marker.
    Also has 'references' as zero-byte directory marker.
    Critical: non-zero files that look like directories must still be downloaded.
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            # Real non-zero file that looks like a directory name
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/postnext", "Size": 10544},
            # Zero-byte directory marker
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references", "Size": 0},
            # Real files
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/.gitignore", "Size": 22},
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/SKILL.md", "Size": 3736},
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references/analytics.md", "Size": 2492},
            {"Key": "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references/channels.md", "Size": 1836},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"fake content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/", tmp
            )

        # 'postnext' is non-zero → should be downloaded as a file
        assert "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/postnext" in downloaded
        assert (tmp / "postnext").is_file()

        # 'references' is zero-byte with children → directory marker, not downloaded
        assert "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references" not in downloaded
        assert (tmp / "references").is_dir()

        # Real files downloaded
        assert "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references/analytics.md" in downloaded
        assert "clawhub/postnext-social-manager/0.1.0/2d3a5cf2d42f/references/channels.md" in downloaded
        assert result.object_count == 5

    finally:
        shutil.rmtree(tmp)


def test_real_world_gpt_image_skill_gitkeep_preserved():
    """Mimics clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.
    
    Has 'references/.gitkeep' which is zero-byte but NOT a directory marker
    (no children with 'references/.gitkeep/' prefix). Must be downloaded.
    Also has .claude-plugin, public, references, scripts as zero-byte dir markers.
    """
    import tempfile
    import shutil
    from unittest.mock import MagicMock, patch

    tmp = Path(tempfile.mkdtemp())
    try:
        objects = [
            # Zero-byte directory markers
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.claude-plugin", "Size": 0},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/public", "Size": 0},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/references", "Size": 0},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/scripts", "Size": 0},
            # Zero-byte real file (not a directory marker — no children)
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/references/.gitkeep", "Size": 0},
            # Real files
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.claude-plugin/marketplace.json", "Size": 472},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.gitignore", "Size": 65},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/SKILL.md", "Size": 15300},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/public/cover.png", "Size": 353237},
            {"Key": "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/scripts/setup.js", "Size": 2540},
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": objects}]
        mock_client.get_paginator.return_value = mock_paginator

        downloaded = []
        def mock_download(bucket, key, path):
            downloaded.append(key)
            Path(path).write_bytes(b"fake content")

        mock_client.download_file = mock_download

        with patch("artifacts.s3_loader.boto3.client", return_value=mock_client):
            loader = S3ArtifactLoader(bucket_name=BUCKET, region_name="us-east-1")
            result = loader.download_prefix(
                f"s3://{BUCKET}/clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/", tmp
            )

        # Zero-byte directory markers NOT downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.claude-plugin" not in downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/public" not in downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/references" not in downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/scripts" not in downloaded

        # .gitkeep IS downloaded (zero-byte but no children — real file)
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/references/.gitkeep" in downloaded

        # Real files downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/.claude-plugin/marketplace.json" in downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/public/cover.png" in downloaded
        assert "clawhub/gpt-image-2-prompts-skill/0.1.0/a27e9a6b5a44/scripts/setup.js" in downloaded

        # Directories created
        assert (tmp / ".claude-plugin").is_dir()
        assert (tmp / "public").is_dir()
        assert (tmp / "references").is_dir()
        assert (tmp / "scripts").is_dir()

        # .gitkeep is a file inside references/
        assert (tmp / "references" / ".gitkeep").is_file()

        # object_count: excludes 4 dir markers, includes .gitkeep + 5 real files = 6
        assert result.object_count == 6

    finally:
        shutil.rmtree(tmp)