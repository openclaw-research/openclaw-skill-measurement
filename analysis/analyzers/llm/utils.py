from __future__ import annotations
import re
import json


def safe_parse_json(content: str) -> dict:
    """
    Robustly parse JSON from LLM response.
    Tries multiple strategies before falling back to a safe default.
    """
    content = content.strip()

    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    content = content.strip()


    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    
    try:
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            return json.loads(match.group())
    except json.JSONDecodeError:
        pass

    
    try:
        fixed = content.replace('\u201c', '"').replace('\u201d', '"')
        fixed = fixed.replace('\u2018', "'").replace('\u2019', "'")
        return json.loads(fixed)
    except json.JSONDecodeError:
        pass

    try:
        last_comma = content.rfind(',')
        if last_comma > 0:
            truncated = content[:last_comma] + "}"
            return json.loads(truncated)
    except json.JSONDecodeError:
        pass
    
    return {
        "risk_label": "medium",
        "confidence": 0.5,
        "explanation": "JSON parsing failed after all strategies — defaulting to medium risk for human review",
        "false_positives": [],
        "findings": [],
        "parse_error": True
    }