"""Check detected dependencies for a set of skills from the corpus.

Usage:
    python scripts/check_dynamic_deps.py

Validates the dependency detector against a sample of LLM-confirmed critical/high skills with shell scripts.
"""
from __future__ import annotations

import sys
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv()

from config import get_settings
from artifacts.s3_loader import S3ArtifactLoader
from analyzers.dynamic.deps import detect_required_packages, format_apt_install_cmd

# Sample of skills to validate against
SAMPLE_SKILLS = [
    ("klyc-pmm",                "s3://openclaw-skill-artifacts/clawhub/klyc-pmm/8.3.1/e8720642db8d/"),
    ("auto-deploy",             "s3://openclaw-skill-artifacts/clawhub/auto-deploy/1.0.0/"),
    ("tool-governance",         "s3://openclaw-skill-artifacts/clawhub/tool-governance/2.4.0/"),
    ("signa-ai",                "s3://openclaw-skill-artifacts/clawhub/signa-ai/1.0.2/"),
    ("claude-audit",            "s3://openclaw-skill-artifacts/clawhub/claude-audit/1.0.0/"),
    ("good-memory",             "s3://openclaw-skill-artifacts/clawhub/good-memory/2.0.1/"),
    ("neuralpool",              "s3://openclaw-skill-artifacts/clawhub/neuralpool/1.0.2/"),
    ("ai-agent-runtime",        "s3://openclaw-skill-artifacts/clawhub/ai-agent-runtime/1.2.0/"),
    ("skill-sentinel",          "s3://openclaw-skill-artifacts/clawhub/skill-sentinel/1.0.0/"),
    ("base-stable-arb-radar",   "s3://openclaw-skill-artifacts/clawhub/base-stable-arb-radar/0.1.6/"),
]


def main() -> None:
    settings = get_settings()
    loader = S3ArtifactLoader(
        bucket_name=settings.s3_bucket,
        region_name=settings.aws_region,
    )

    print(f"{'Skill':<35} {'Packages detected':<50} {'Install cmd'}")
    print("-" * 120)

    for skill_id, artifact_uri in SAMPLE_SKILLS:
        tmp = tempfile.mkdtemp(prefix="openclaw-deps-")
        try:
            loader.download_prefix(artifact_uri, Path(tmp))
            packages = detect_required_packages(Path(tmp))
            install_cmd = format_apt_install_cmd(packages)
            print(f"{skill_id:<35} {str(packages):<50} {install_cmd[:40] if install_cmd else 'none'}")
        except Exception as exc:
            print(f"{skill_id:<35} ERROR: {exc}")
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    main()