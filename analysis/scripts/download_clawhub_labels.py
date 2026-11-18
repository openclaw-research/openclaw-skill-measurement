"""Download the live ClawHub Security Signals dataset from HuggingFace.

Pulls OpenClaw/clawhub-security-signals-live (single `latest` split, ~67K rows).
Uses streaming mode so the ~2 GB source parquet is never fully materialized
on disk. Keeps only the scanner-verdict fields we need for validation; drops
skill_md_content and skill_bundle_content because we already have those in
our S3 artifacts.

Output: <out-dir>/clawhub_live_latest.jsonl (~40 MB).

The frozen paper snapshot (OpenClaw/clawhub-security-signals) is not covered
here. That dataset is intentionally immutable and pinned to the paper's
May 31 2026 export. Use HuggingFace's `datasets.load_dataset` directly if
you need it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from datasets import load_dataset

DATASET_NAME = "OpenClaw/clawhub-security-signals-live"
SPLIT_NAME = "latest"

# Fields kept per row. Scanner-verdict columns and identifiers only; dropping the two large content fields to keep the output under 50 MB.
KEEP_FIELDS = (
    "id",
    "skill_slug",
    "skill_version",
    "clawscan_verdict",
    "clawscan_confidence",
    "static_status",
    "static_finding_count",
    "static_reason_codes",
    "virustotal_status",
    "virustotal_malicious_count",
    "virustotal_suspicious_count",
    "skillspector_status",
    "skillspector_score",
    "skillspector_severity",
    "skillspector_issue_count",
    "skillspector_issue_codes",
    "skillspector_issue_categories",
    "split",
)


def download(out_dir: Path, limit: int | None = None) -> Path:
    print(f"Streaming {DATASET_NAME} (split={SPLIT_NAME})...")

    ds = load_dataset(
        DATASET_NAME,
        name="default",
        split=SPLIT_NAME,
        streaming=True,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"clawhub_live_{SPLIT_NAME}.jsonl"

    verdict_counts = {"clean": 0, "suspicious": 0, "malicious": 0, "unknown": 0, "other": 0}
    n_written = 0

    with out_path.open("w") as f:
        for row in ds:
            trimmed = {k: row.get(k) for k in KEEP_FIELDS}
            f.write(json.dumps(trimmed, default=str) + "\n")
            n_written += 1

            v = row.get("clawscan_verdict") or "unknown"
            if v not in verdict_counts:
                v = "other"
            verdict_counts[v] += 1

            if n_written % 5000 == 0:
                print(f"  written {n_written} rows...")

            if limit is not None and n_written >= limit:
                print(f"  reached --limit {limit}, stopping")
                break

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"\nDone. {n_written} rows written to {out_path} ({size_mb:.1f} MB)")
    print(f"Verdict distribution: {verdict_counts}")

    return out_path


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("tests/validation_data"),
        help="Directory for the output JSONL (default: tests/validation_data)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after N rows (useful for smoke tests). Default: pull all rows.",
    )
    args = parser.parse_args()

    download(out_dir=args.out_dir, limit=args.limit)


if __name__ == "__main__":
    main()