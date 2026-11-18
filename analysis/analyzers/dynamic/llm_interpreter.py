"""LLM-based interpreter for dynamic analysis runtime evidence.

Takes structured runtime events from strace analysis and uses an LLM to interpret whether the observed behavior is consistent with the skill's stated purpose or indicates malicious intent.

Unlike the static LLM analyzer which reasons about code snippets, this interpreter reasons ONLY about observed runtime behavior — what the skill actually did, not what it looks like it might do.

Strict grounding rules enforced via prompt:
- Every claim must cite a specific observed runtime event
- LLM cannot speculate beyond observed events
- Absence of observation != evidence of safety
- Verdict is independent of static/LLM prior assessments
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
import re

from groq import Groq
from groq import AuthenticationError as GroqAuthError
from groq import RateLimitError as GroqRateLimitError

from analyzers.llm.utils import safe_parse_json

logger = logging.getLogger(__name__)

GROQ_MODEL_PRIMARY  = "qwen/qwen3.8-27b"
GROQ_MODEL_FALLBACK = "groq/compound-mini"
MAX_TOKENS = 1024
MAX_PROMPT_TOKENS = 1500


class LLMDailyLimitExceeded(Exception):
    """Both Groq API keys have exhausted their daily token limit.

    Raised when all 4 fallback tiers (key1+primary, key1+fallback,
    key2+primary, key2+fallback) have hit the daily limit.
    Pipeline should stop gracefully when this is raised.
    """
    pass

SYSTEM_PROCESS_PREFIXES = (
    "/usr/lib",
    "/lib",
    "/usr/bin/python",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/strace",
)

DYNAMIC_SYSTEM_PROMPT = """You are a security analyst classifying AI agent skill runtime behavior.
A rule-based system produced a preliminary verdict from syscall analysis.
The 'skill_md_summary' field contains the skill's SKILL.md content (key sections only).
Use it to judge whether runtime behavior is CONSISTENT with what the skill claims to do.
Pay special attention to destination mismatches — if a skill claims to be configurable
but contacts a hardcoded unknown domain, that is suspicious regardless of tool used.
Your job: output a final verdict (may downgrade, never upgrade to malicious) and contextualize.

VERDICT DEFINITIONS:
  malicious         — confirmed dangerous (credential theft, reverse shell, known exfiltration).
                      DO NOT assign this yourself — rule-based only.
  suspicious        — concerning patterns, not conclusive
  benign            — behavior consistent with stated purpose, no security concerns
  context_dependent — scripts could not execute (exit 126/127 or all non-zero)

NEW INPUT FIELDS IN V3:
  credential_reads_with_process: [{"path": "/.npmrc", "process": "/usr/bin/npm", "pid": "1234"}]
  network_calls_with_process:    [{"domain": "github.com", "process": "/usr/bin/npm", "pid": "1234"}]
  layer2_prediction.human_escalation: true means L2 flagged for human review — strong signal
  layer2_prediction.explanation: full semantic analysis from L2 LLM

DOWNGRADE RULES (apply when evidence supports):

  USE PROCESS ATTRIBUTION FIRST:
    - Check credential_reads_with_process and network_calls_with_process
    - If SAME process read credential AND made network calls → likely tool side effect
    - Known tools and their expected credentials:
        npm/node/npx/yarn → .npmrc
        git/git-remote-https → .netrc, .git-credentials
        docker → .docker/config.json
        apt/apt-get → .docker/config.json (docker config read during setup)
        pip/pip3 → .pypirc
        openssl → generates keys in /tmp (self-generated)
    - If DIFFERENT non-tool processes read credential vs made network call → suspicious

  malicious → suspicious/benign:
    - credentials are self_generated (created this run, in /tmp)
    - Process attribution shows tool read its own credential (npm→.npmrc, git→.netrc)
      AND that same tool (or a sibling tool in same setup script) made network calls

  suspicious → benign:
    - all network calls explained by skill purpose AND no credential reads AND no persistence
    - only signal is localhost/loopback AND no credential reads

DO NOT DOWNGRADE if any of these are true:
  - persistence_writes is non-empty (LaunchAgents, crontab, bashrc)
  - known_exfiltration_domains is non-empty
  - reverse_shell_processes is non-empty
  - layer2_prediction.human_escalation is true
  - Different non-tool processes read credentials vs made network calls

TRUNCATED DOMAINS: domains in network.truncated_artifacts are strace buffer
artifacts — do not treat as suspicious unknown domains.

SELF-GENERATED CREDENTIALS: files in credentials.self_generated were created
this run — reading them back is not credential theft.

OUTPUT: JSON only. No markdown. No preamble.
{
  "final_verdict": "malicious|suspicious|benign|context_dependent",
  "confidence": 0.0,
  "override_reason": "1 sentence: why you kept or changed the preliminary verdict",
  "purpose_fit": "consistent|inconsistent|unclear",
  "purpose_fit_reasoning": "1 sentence",
  "prior_agreement": "confirms|contradicts|inconclusive",
  "prior_agreement_reasoning": "1 sentence",
  "unexecuted_risk": "low|medium|high",
  "unexecuted_risk_reasoning": "1 sentence",
  "analysis_notes": "1 sentence: key observation"
}"""


@dataclass(frozen=True)
class LLMInterpretation:
    """Structured interpretation of dynamic analysis results by LLM.

    The LLM acts as joint classifier and contextualizer:
    - Outputs a final_verdict that can DOWNGRADE the rule-based verdict
    - Cannot UPGRADE to malicious (rule-based must fire first)
    - Contextualizes by answering three specific questions
    """
    purpose_fit: str
    purpose_fit_reasoning: str
    prior_agreement: str
    prior_agreement_reasoning: str
    unexecuted_risk: str
    unexecuted_risk_reasoning: str
    overall_confidence: float
    analysis_notes: str
    final_verdict: str
    override_reason: str
    raw_response: str


def _filter_processes(processes: list[str]) -> list[str]:
    """Remove system/library processes — keep only skill-relevant ones."""
    return [
        p for p in processes
        if not any(p.startswith(prefix) for prefix in SYSTEM_PROCESS_PREFIXES)
    ][:10]


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text to stay within token budget."""
    return text[:max_chars] if len(text) > max_chars else text


def build_dynamic_prompt(
    skill_source_id: str,
    skill_purpose: str,
    static_risk: str,
    dynamic_verdict: str,
    strace_summary: dict,
    llm_prior: str | None,
) -> str:
    """Build compact JSON prompt with enriched context for LLM classification.

    Derives additional context from existing strace data:
    - Self-generated vs pre-existing credentials
    - Full vs truncated network domains
    - File write categorization
    - Known tool process detection
    """
    # --- Credential classification ---
    file_writes_set  = set(strace_summary.get("file_writes", []))
    cred_reads       = strace_summary.get("credential_paths_read", [])
    gen_creds        = strace_summary.get("generated_credential_paths", [])

    # Also catch pre-existing reads: in credential_paths_read but not in file_writes
    pre_existing = [p for p in cred_reads if p not in file_writes_set]
    self_generated = list(gen_creds)  # parser already classified these

    # --- Network domain classification ---
    all_network       = strace_summary.get("network_calls", [])
    truncated_network = strace_summary.get("truncated_network_calls", [])

    # --- Known tool detection ---
    TOOL_PROCESS_NAMES = {
        "npm", "node", "npx", "yarn",
        "git", "git-remote-https", "git-remote-http",
        "docker", "docker-credential-",
        "pip", "pip3", "python", "python3",
        "apt", "apt-get", "dpkg",
        "curl", "wget",
        "openssl",
        "cargo", "gem", "composer",
    }
    processes = strace_summary.get("processes_spawned", [])
    process_basenames = [p.split("/")[-1] for p in processes]
    known_tools = list({
        b for b in process_basenames
        if any(b == t or b.startswith(t) for t in TOOL_PROCESS_NAMES)
    })

    # --- File write categorization ---
    all_writes = [
        f for f in strace_summary.get("file_writes", [])
        if f not in ("/dev/tty", "/dev/null", "/dev/stderr", "/dev/stdout")
    ]
    tmp_writes      = [f for f in all_writes if f.startswith("/tmp/")]
    openclaw_writes = [f for f in all_writes if "/.claude/" in f or "/.openclaw/" in f]
    other_writes    = [f for f in all_writes
                       if f not in tmp_writes and f not in openclaw_writes]

    # --- Script→exit mapping ---
    scripts  = strace_summary.get("executables_run", [])
    exits    = strace_summary.get("exit_codes", [])
    script_exit = [
        {"name": s, "exit": e}
        for s, e in zip(scripts, exits)
    ]

    # --- Unexecuted files ---
    ext_counts = strace_summary.get("extension_counts", {})
    unexecuted = {
        "py":  ext_counts.get(".py", 0),
        "js":  ext_counts.get(".js", 0) + ext_counts.get(".mjs", 0) + ext_counts.get(".cjs", 0),
        "ts":  ext_counts.get(".ts", 0),
        "ps1": ext_counts.get(".ps1", 0),
    }

    import json as _json
    # Pipeline already extracts key sections — truncate to stay compact
    skill_purpose_truncated = skill_purpose[:600] if skill_purpose else skill_source_id

    payload = {
        "skill_id":            skill_source_id,
        "skill_md_summary":    skill_purpose_truncated,
        "static_risk":         static_risk,
        "preliminary_verdict": dynamic_verdict,
        "syscall_count":       strace_summary.get("syscall_count", 0),
        "scripts":             script_exit,
        "credentials": {
            "pre_existing":    pre_existing,
            "self_generated":  self_generated,
        },
        "network": {
            "full_domains":        all_network,
            "truncated_artifacts": truncated_network,
        },
        "processes":               process_basenames[:20],
        "known_tools_detected":    known_tools,
        "persistence_writes":      strace_summary.get("sensitive_writes", []),
        "known_exfiltration_domains": strace_summary.get("exfiltration_domains", []),
        "reverse_shell_processes": strace_summary.get("reverse_shell_processes", []),
        "file_writes": {
            "tmp":            tmp_writes[:10],
            "openclaw_config": openclaw_writes,
            "other":          other_writes[:10],
        },
        "unexecuted_files":    unexecuted,
        "layer2_prediction": {
            "risk_level":       llm_prior.get("risk_level", "unknown") if isinstance(llm_prior, dict) else "unknown",
            "explanation":      (llm_prior.get("explanation", "") if isinstance(llm_prior, dict) else str(llm_prior or ""))[:800],
            "human_escalation": llm_prior.get("human_escalation", False) if isinstance(llm_prior, dict) else False,
        } if llm_prior else None,
        "credential_reads_with_process": strace_summary.get("credential_reads_with_process", []),
        "network_calls_with_process":    [
            c for c in strace_summary.get("network_calls_with_process", [])
            if c.get("domain") and len(c.get("domain", "")) > 6 and "." in c.get("domain", "")
        ][:15],
    }

    return _json.dumps(payload, indent=2)

def _extract_partial_json(raw: str) -> dict:
    """Extract individual fields from a truncated JSON response."""
    result = {}
    fields = [
        "final_verdict", "confidence", "override_reason",
        "purpose_fit", "purpose_fit_reasoning",
        "prior_agreement", "prior_agreement_reasoning",
        "unexecuted_risk", "unexecuted_risk_reasoning",
        "analysis_notes",
    ]
    for field in fields:
        pattern = rf'"{field}"\s*:\s*"([^"]*)"'
        match = re.search(pattern, raw)
        if match:
            result[field] = match.group(1)
        elif field == "overall_confidence":
            num_match = re.search(rf'"{field}"\s*:\s*([0-9.]+)', raw)
            if num_match:
                result[field] = float(num_match.group(1))
    return result

def interpret(
    skill_source_id: str,
    skill_purpose: str,
    static_risk: str,
    dynamic_verdict: str,
    strace_summary: dict,
    llm_prior: dict | None = None,
    api_key: str | None = None,
) -> LLMInterpretation | None:
    """Interpret dynamic runtime evidence using an LLM.

    Args:
        skill_source_id: Skill identifier for logging.
        skill_purpose: Skill's stated purpose from SKILL.md.
        static_risk: Static analyzer risk level (context only).
        strace_summary: Structured dict of observed runtime events.
        llm_prior: Optional prior LLM assessment from Arshiya's pipeline.
        api_key: Groq API key. Falls back to API_KEY env var.

    Returns:
        LLMInterpretation or None if the API call failed.
    """
    key1 = api_key or os.environ.get("GROQ_API_KEY") or os.environ.get("API_KEY", "")
    key2 = os.environ.get("GROQ_API_KEY_2", "")

    if not key1:
        logger.error("No Groq API key available for dynamic LLM interpretation")
        return None

    prompt = build_dynamic_prompt(
        skill_source_id, skill_purpose, static_risk, dynamic_verdict, strace_summary, llm_prior
    )

    estimated_tokens = len(DYNAMIC_SYSTEM_PROMPT) // 4 + len(prompt) // 4
    if estimated_tokens > MAX_PROMPT_TOKENS:
        logger.debug(
            "Prompt for %s estimated at ~%d tokens",
            skill_source_id, estimated_tokens,
        )

    import time

    # 4-tier fallback: key1+primary, key1+fallback, key2+primary, key2+fallback
    # Malicious verdicts use fallback model first to conserve primary tokens
    if dynamic_verdict == "malicious":
        tiers = [
            (key1, GROQ_MODEL_FALLBACK),
            (key1, GROQ_MODEL_PRIMARY),
        ]
    else:
        tiers = [
            (key1, GROQ_MODEL_PRIMARY),
            (key1, GROQ_MODEL_FALLBACK),
        ]

    if key2:
        if dynamic_verdict == "malicious":
            tiers += [(key2, GROQ_MODEL_FALLBACK), (key2, GROQ_MODEL_PRIMARY)]
        else:
            tiers += [(key2, GROQ_MODEL_PRIMARY), (key2, GROQ_MODEL_FALLBACK)]

    daily_limit_count = 0
    raw = ""

    for tier_idx, (tier_key, tier_model) in enumerate(tiers):
        try:
            client = Groq(api_key=tier_key)
            for attempt in range(2):
                try:
                    response = client.chat.completions.create(
                        model=tier_model,
                        messages=[
                            {"role": "system", "content": DYNAMIC_SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        max_tokens=MAX_TOKENS,
                        temperature=0.1,
                    )
                    raw = response.choices[0].message.content or ""
                    logger.info(
                        "LLM interpretation for %s via tier %d (%s): %d chars",
                        skill_source_id, tier_idx + 1, tier_model, len(raw),
                    )
                    break
                except Exception as exc:
                    err_str = str(exc).lower()
                    if "tokens per day" in err_str or "tpd" in err_str:
                        daily_limit_count += 1
                        logger.warning(
                            "Daily limit hit on tier %d (%s/%s) — trying next tier",
                            tier_idx + 1, tier_key[:8], tier_model,
                        )
                        break
                    if "rate_limit" in err_str and attempt == 0:
                        wait = 60
                        logger.warning(
                            "Rate limit for %s on tier %d — waiting %ds",
                            skill_source_id, tier_idx + 1, wait,
                        )
                        time.sleep(wait)
                    else:
                        logger.warning(
                            "Tier %d failed for %s: %s",
                            tier_idx + 1, skill_source_id, exc,
                        )
                        break
            if raw:
                break
        except Exception as exc:
            logger.warning("Tier %d client error: %s", tier_idx + 1, exc)
            continue

    # All tiers exhausted due to daily limits — raise to stop pipeline
    if not raw and daily_limit_count >= len(tiers):
        logger.error(
            "All %d Groq tiers hit daily token limit — pipeline should stop",
            len(tiers),
        )
        raise LLMDailyLimitExceeded(
            f"All {len(tiers)} Groq tiers exhausted daily token limit"
        )

    if not raw:
        logger.error("All LLM tiers failed for %s — no response", skill_source_id)
        return None

    parsed = safe_parse_json(raw)

    # If safe_parse_json failed or returned wrong keys, try manual extraction
    if not parsed or "purpose_fit" not in parsed:
        parsed = _extract_partial_json(raw)

    if not parsed or "purpose_fit" not in parsed:
        logger.warning(
            "Failed to parse LLM response for %s: %s",
            skill_source_id, raw[:200],
        )
        return None

    return LLMInterpretation(
        purpose_fit=parsed.get("purpose_fit", "unclear"),
        purpose_fit_reasoning=parsed.get("purpose_fit_reasoning", ""),
        prior_agreement=parsed.get("prior_agreement", "inconclusive"),
        prior_agreement_reasoning=parsed.get("prior_agreement_reasoning", ""),
        unexecuted_risk=parsed.get("unexecuted_risk", "low"),
        unexecuted_risk_reasoning=parsed.get("unexecuted_risk_reasoning", ""),
        overall_confidence=float(parsed.get("confidence", parsed.get("overall_confidence", 0.0))),
        analysis_notes=parsed.get("analysis_notes", ""),
        final_verdict=parsed.get("final_verdict", ""),
        override_reason=parsed.get("override_reason", ""),
        raw_response=raw,
    )