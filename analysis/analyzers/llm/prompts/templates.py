from __future__ import annotations
from pathlib import Path

def build_user_prompt(
    rule_based_risk: str,
    rule_based_summary: str,
    result_json: dict,
    root_path: Path | None = None,
) -> str:
    
    prompt = f"Rule-based analyzer flagged this skill as: {rule_based_risk}\n"
    prompt += f"Summary: {rule_based_summary}\n"
        
    skill_md = result_json.get("parsed_files", {}).get("skill_md") or {}
    headings = skill_md.get("headings", [])
    
    
    if not headings and root_path is not None:
        for name in ["SKILL.md", "skill.md"]:
            path = root_path / name
            if path.exists():
                content = path.read_text(errors="ignore")
                headings = [
                    {"text": line.strip()}
                    for line in content.split("\n")
                    if line.startswith("#")
                ]
                break
            
    domains = (result_json.get("external_urls") or {}).get("domains", [])
    if domains:
        prompt += f"\nExternal domains contacted: {', '.join(domains)}\n"

    env_vars = (result_json.get("env_var_references") or {}).get("unique_names", [])
    if env_vars:
        prompt += f"\nEnvironment variables accessed: {', '.join(env_vars)}\n"
        
    file_inventory = result_json.get("file_inventory") or []
    code_files = [f for f in file_inventory if f["region"] == "bundled_code"]
    prose_files = [f for f in file_inventory if f["region"] == "prose"]
    prompt += f"\nFile structure: {len(code_files)} code files, {len(prose_files)} documentation files\n"
    if code_files:
        prompt += "Code files:\n"
        for f in code_files:
            prompt += f"  {f['path']} ({f['extension']}, {f['size_bytes']} bytes)\n"
    
    norm = result_json.get("normalization_stats") or {}
    if norm.get("homoglyphs_folded", 0) > 0:
        prompt += f"\n WARNING: {norm['homoglyphs_folded']} homoglyph characters detected — possible obfuscation\n"
    if norm.get("invisible_chars_stripped", 0) > 0:
        prompt += f"\n WARNING: {norm['invisible_chars_stripped']} invisible characters detected — possible obfuscation\n"

    indicators = result_json.get("indicators") or {}
    prompt += "\nEvidence by category (code only, weight=1.0):\n"
    for category, data in indicators.items():
        count = data.get("count", 0)
        if count == 0:
            continue
        # code_evidence = [e for e in data.get("evidence", []) if e["weight"] == 1.0]
        # if not code_evidence:
        #     continue
        
        code_evidence = []
        for e in data.get("evidence", []):
            path = e.get('path', '')
            extension = path.split('.')[-1] if '.' in path else ''
            doc_extensions = {'md', 'txt', 'rst'}
            default_weight = 0.1 if extension in doc_extensions else 1.0
            weight = e.get('weight', default_weight)
            if weight == 1.0:
                code_evidence.append(e)

        if not code_evidence:
            continue
        
        prompt += f"\n{category} ({count} hits):\n" 
        
        for e in code_evidence:
            line = e.get('line', '?')
            path = e.get('path', '?')
            snippet = e.get('snippet', e.get('indicator', ''))
            prompt += f"  line {line} in {path}: {snippet}\n"
        # for e in code_evidence:
        #     line = e.get('line', '?')
        #     path = e.get('path', '?')
        #     snippet = e.get('snippet', e.get('indicator', ''))
        #     extension = path.split('.')[-1] if '.' in path else ''
        #     doc_extensions = {'md', 'txt', 'rst'}
        #     default_weight = 0.1 if extension in doc_extensions else 1.0
        #     weight = e.get('weight', default_weight)
        #     prompt += f"  line {line} in {path}: {snippet}\n"
    
    return prompt