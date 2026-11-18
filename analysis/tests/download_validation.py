"""Download clawhub-security-signals test+eval_holdout splits for validation.

We only pull test + eval_holdout (10,115 rows total) — these are the splits
the paper authors reserved for external evaluation. Skipping train and
validation avoids ~57K rows we don't need for this pass.
"""
from datasets import load_dataset
from pathlib import Path
import json

OUTPUT_DIR = Path("tests/validation_data")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Fields we need for join + confusion matrix + cross-scanner comparison.
# We do NOT keep skill_md_content or skill_bundle_content — too large,
# and we have those already in our S3 artifacts.
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


def download_split(split_name: str) -> Path:
    print(f"\n[{split_name}] loading from HuggingFace...")
    ds = load_dataset(
        "OpenClaw/clawhub-security-signals",
        name="default",
        split=split_name,
        verification_mode="no_checks",
    )
    print(f"[{split_name}] rows: {len(ds)}")

    out_path = OUTPUT_DIR / f"clawhub_{split_name}.jsonl"
    verdict_counts = {"clean": 0, "suspicious": 0, "malicious": 0, "other": 0}

    with out_path.open("w") as f:
        for row in ds:
            trimmed = {k: row.get(k) for k in KEEP_FIELDS}
            f.write(json.dumps(trimmed, default=str) + "\n")

            v = row.get("clawscan_verdict") or "other"
            verdict_counts[v if v in verdict_counts else "other"] += 1

    size_mb = out_path.stat().st_size / (1024 * 1024)
    print(f"[{split_name}] saved to {out_path} ({size_mb:.1f} MB)")
    print(f"[{split_name}] verdict distribution: {verdict_counts}")

    return out_path


def main():
    for split in ("test", "eval_holdout"):
        download_split(split)

    print("\nDone. Files ready at:")
    for p in sorted(OUTPUT_DIR.glob("clawhub_*.jsonl")):
        print(f"  {p}")


if __name__ == "__main__":
    main()