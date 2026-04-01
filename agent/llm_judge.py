"""
agent/llm_judge.py - Stateless LLM security judge (Strategy 3).

Uses a completely fresh LLM context (no memory of the fix-generation conversation)
to independently review whether the proposed fix correctly eliminates the vulnerability.
This prevents self-confirmation bias where the fix author validates their own work.
"""
import json
import re
from typing import Dict, Any

from langchain_core.messages import HumanMessage, SystemMessage


JUDGE_SYSTEM_PROMPT = """You are an expert security code reviewer.
You will be shown a vulnerability type, the original vulnerable code, and a proposed fix.
Your ONLY job is to determine whether the fix correctly eliminates the vulnerability.
You have no memory of how the fix was generated. Review it objectively and critically.

Respond in this EXACT JSON format (no markdown, no explanation outside the JSON):
{
  "verdict": "SAFE",
  "confidence": 0.95,
  "reason": "one sentence explanation"
}

Allowed verdict values:
- "SAFE"       → fix definitively eliminates the vulnerability
- "VULNERABLE" → fix is insufficient, vulnerability still present
- "UNCERTAIN"  → cannot determine with confidence (e.g. fix is context-dependent)
"""


def _response_to_text(response_content: Any) -> str:
    """Normalize provider-specific response content into plain text."""
    if response_content is None:
        return ""

    if isinstance(response_content, str):
        return response_content

    if isinstance(response_content, list):
        parts = []
        for item in response_content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif item.get("type") == "text" and isinstance(item.get("content"), str):
                    parts.append(item["content"])
            else:
                text_attr = getattr(item, "text", None)
                if isinstance(text_attr, str):
                    parts.append(text_attr)
                else:
                    parts.append(str(item))
        return "\n".join(part for part in parts if part)

    text_attr = getattr(response_content, "text", None)
    if isinstance(text_attr, str):
        return text_attr

    return str(response_content)


def run_llm_judge(
    vuln_type: str,
    fix_strategy: str,
    original_code: str,
    fixed_code: str,
) -> Dict[str, Any]:
    """
    Run an independent LLM judge to verify the fix.

    Returns a dict with:
      verdict:    "SAFE" | "VULNERABLE" | "UNCERTAIN"
      confidence: float 0.0-1.0
      reason:     str explanation
      error:      str (only if call failed)
    """
    try:
        from config.llm_factory import get_llm

        llm = get_llm()

        user_message = f"""Vulnerability Type: {vuln_type}
Fix Strategy: {fix_strategy}

ORIGINAL VULNERABLE CODE:
```
{original_code[:3000]}
```

PROPOSED FIX:
```
{fixed_code[:3000]}
```

Does the fix correctly eliminate the {vuln_type} vulnerability?
Respond with JSON only."""

        # Fresh context — no history from fix generation
        messages = [
            SystemMessage(content=JUDGE_SYSTEM_PROMPT),
            HumanMessage(content=user_message),
        ]

        print(f"  [Judge] Asking LLM to independently review the fix...")
        response = llm.invoke(messages)
        raw = _response_to_text(getattr(response, "content", response))

        return _parse_judge_response(raw)

    except Exception as e:
        return {
            "verdict": "UNCERTAIN",
            "confidence": 0.0,
            "reason": f"Judge call failed: {e}",
            "error": str(e),
        }


def _parse_judge_response(raw: str) -> Dict[str, Any]:
    """Extract the JSON verdict from the LLM response."""
    # Strip markdown code fences if present
    clean = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip()

    # Try to find a JSON object anywhere in the response
    match = re.search(r'\{[^{}]+\}', clean, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            verdict = data.get("verdict", "UNCERTAIN").upper()
            if verdict not in ("SAFE", "VULNERABLE", "UNCERTAIN"):
                verdict = "UNCERTAIN"
            return {
                "verdict": verdict,
                "confidence": float(data.get("confidence", 0.5)),
                "reason": str(data.get("reason", "No reason provided")),
            }
        except (json.JSONDecodeError, ValueError):
            pass

    # Fallback: look for keywords in free-form text
    upper = raw.upper()
    if "VULNERABLE" in upper:
        return {"verdict": "VULNERABLE", "confidence": 0.6, "reason": raw[:200]}
    if "SAFE" in upper:
        return {"verdict": "SAFE", "confidence": 0.6, "reason": raw[:200]}

    return {
        "verdict": "UNCERTAIN",
        "confidence": 0.0,
        "reason": f"Could not parse judge response: {raw[:200]}",
    }
