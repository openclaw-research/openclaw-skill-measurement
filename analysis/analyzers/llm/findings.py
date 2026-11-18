from __future__ import annotations

def build_findings(scored_result: dict) -> list[dict]:
    findings = []
    for f in scored_result.get("findings", []):
        findings.append({
            "category": f.get("category", "unknown"),
            "severity": f.get("severity", "medium"),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "evidence_json": {"evidence": f.get("evidence", "")}
        })
    return findings
    