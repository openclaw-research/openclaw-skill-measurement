from __future__ import annotations
from pathlib import Path
from analyzers.llm.file_filter import filter_files
from analyzers.llm.ast_parser import parse_file
from analyzers.llm.semantics import analyze_skill
from analyzers.llm.scoring import score_result
from analyzers.llm.findings import build_findings
from analyzers.llm.intent import analyze_intent

def analyze(
    root_path: Path,
    result_json: dict,
    risk_level: str,
    summary: str,
    api_key: str
) -> dict:
    
    # filtered_files = filter_files(root_path, result_json)
    # print(f"filtered files : {filtered_files}")
    # parsed_files = [parse_file(f) for f in filtered_files]
    # print(f"parsed_files : {parsed_files}")
    # evidence = result_json.get("indicators", {})  
    llm1_response = analyze_skill(risk_level, summary, result_json, api_key, root_path=root_path)
    parse_error = llm1_response.get("parse_error", False)
    scored = score_result(llm1_response)
    findings = build_findings(scored)
    
    intent_result = analyze_intent(root_path, api_key)
    
    final_risk = scored["risk_label"]
    intent_risk = None
    manipulation_detected = False
    
    if intent_result is not None:
        intent_risk = intent_result.get("intent_risk","low")
        manipulation_detected = intent_result.get("manipulation_detected", False)
        if manipulation_detected:
            if final_risk in ("low", "medium"):
                final_risk = "high"
    
    human_escalation = False
    confidence = scored.get("confidence", 0.0)
    
    # disagreement-based escalation
    if confidence < 0.7:
        human_escalation = True
    if parse_error:
        human_escalation = True
    if final_risk == "high" and intent_result is not None and not manipulation_detected and intent_risk == "low":
        human_escalation = True
    if final_risk == "medium" and intent_risk == "low":
        human_escalation = True
    if final_risk == "low" and manipulation_detected:
        human_escalation = True
    
    return {
        "risk_label": final_risk,
        "confidence": confidence,
        "explanation": scored["explanation"],
        "false_positives": scored["false_positives"],
        "findings": findings,
        "intent_analysis": intent_result,
        "human_escalation": human_escalation,
        "status": "success"
    }