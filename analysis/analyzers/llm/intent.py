from __future__ import annotations
import json
from pathlib import Path
from groq import Groq
# from mistralai.client import MistralClient
# from mistralai.models.chat_completion import ChatMessage
from analyzers.llm.prompts.intent_system import INTENT_SYSTEM_PROMPT
from analyzers.llm.prompts.intent_template import build_intent_prompt
from analyzers.llm.utils import safe_parse_json

def analyze_intent(root_path: Path, api_key: str) -> dict | None:
    """
    LLM 2 — analyzes SKILL.md for prompt injection and behavioral manipulation.
    Returns None if SKILL.md doesn't exist.
    """
    
    skill_md_path = None
    for name in ["SKILL.md", "skill.md"]:
        candidate = root_path / name
        if candidate.exists():
            skill_md_path = candidate
            break
    
    if skill_md_path is None:
        return None

    prompt = build_intent_prompt(skill_md_path)
    if prompt is None:
        return None

    # client = MistralClient(api_key=api_key)
    # response = client.chat(
    #     model="mistral-small-latest",
    #     messages=[
    #         ChatMessage(role="system", content=INTENT_SYSTEM_PROMPT),
    #         ChatMessage(role="user", content=prompt)
    #     ]
    # )
    
    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",  
        messages=[
            {"role": "system", "content": INTENT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=1024,
    )

    content = response.choices[0].message.content
    result = safe_parse_json(content)
    return result