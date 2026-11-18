from __future__ import annotations
VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}

def score_result(llm_response: dict) -> dict:
   
    risk_label = llm_response.get("risk_label", "unknown")
    risk_label = risk_label.lower().strip()  
    if risk_label not in VALID_RISK_LEVELS:
        risk_label = "unknown"  
    
    
    confidence = llm_response.get("confidence", 0.0)
    if not isinstance(confidence, (int, float)):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))  
    
    
    return {
        "risk_label": risk_label,
        "confidence": confidence,
        "explanation": llm_response.get("explanation", ""),
        "false_positives": llm_response.get("false_positives", []),
        "findings": llm_response.get("findings", [])
    }