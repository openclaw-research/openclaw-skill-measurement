# import google.genai as genai
# from openai import OpenAI
# from mistralai.client import MistralClient
# from mistralai.models.chat_completion import ChatMessage
from groq import Groq
import json
from pathlib import Path


from analyzers.llm.prompts.system import SYSTEM_PROMPT
from analyzers.llm.prompts.templates import build_user_prompt
from analyzers.llm.utils import safe_parse_json


def analyze_skill(
    rule_based_risk: str,
    rule_based_summary: str,
    result_json: dict,
    api_key: str,
    root_path: Path | None = None,
) -> dict:
    prompt = build_user_prompt(
        rule_based_risk, rule_based_summary, result_json, root_path
    )
    # client = genai.Client(api_key=api_key)
    # response = client.models.generate_content(
    #     model="gemini-2.0-flash-lite",
    #     contents=prompt,
    #     config=genai.types.GenerateContentConfig(
    #         system_instruction=SYSTEM_PROMPT
    #     )
    # )
    # result = json.loads(response.text)

    # client = OpenAI(
    #     base_url="https://openrouter.ai/api/v1",
    #     api_key=api_key,
    # )

    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",  # check console.groq.com/docs/models for current list
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=1024,
    )

    # result = json.loads(response.choices[0].message.content)

    # client = MistralClient(api_key=api_key)
    # response = client.chat(
    #     model="mistral-small-latest",
    #     messages=[
    #         ChatMessage(role="system", content=SYSTEM_PROMPT),
    #         ChatMessage(role="user", content=prompt)
    #     ]
    # )

    content = response.choices[0].message.content
    result = safe_parse_json(content)

    # content = content.strip()
    # if content.startswith("```"):
    #     content = content.split("```")[1]
    #     if content.startswith("json"):
    #         content = content[4:]
    # content = content.strip()

    # result = json.loads(content)

    return result
