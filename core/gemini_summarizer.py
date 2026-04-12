"""Gemini AI assistant for Vulnix — reads credentials from config.py only."""

from __future__ import annotations

import logging
import config
from google import genai
from google.genai import types

LOGGER = logging.getLogger(__name__)

# Fallback order defined in config.py; these are the display labels.
_LABEL_MAP: dict[str, str] = {
    "gemini-2.5-flash-lite": "Gemini 2.5 Flash Lite",
    "gemini-2.0-flash":      "Gemini 2.0 Flash",
    "gemini-1.5-flash":      "Gemini 1.5 Flash",
}

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=config.GEMINI_API_KEY.strip())
    return _client


def _model_failover_sequence() -> list[tuple[str, str]]:
    ids = getattr(config, "GEMINI_MODEL_FALLBACK", None) or list(_LABEL_MAP)
    return [(_LABEL_MAP.get(mid, mid), mid) for mid in ids]


def _extract_text(response) -> str:
    text = getattr(response, "text", None)
    if text:
        return text.strip()
    return ""


def _generate_with_fallback(
    prompt: str, max_output_tokens: int = 300, temperature: float = 0.3
) -> str:
    client = _get_client()
    errors: list[str] = []
    for model_label, model_id in _model_failover_sequence():
        try:
            resp = client.models.generate_content(
                model=model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=max_output_tokens,
                    temperature=temperature,
                ),
            )
            text = _extract_text(resp)
            if text:
                return text
            errors.append(f"{model_label}: empty response")
        except Exception as exc:
            LOGGER.warning("Gemini model %s failed: %s", model_id, exc)
            errors.append(f"{model_label}: {exc}")
    raise RuntimeError("All configured Gemini models failed. " + " | ".join(errors))


def is_configured() -> bool:
    """Return True only if a real API key has been set."""
    key = config.GEMINI_API_KEY.strip()
    return bool(key) and key != "YOUR_GEMINI_API_KEY_HERE"


def ask_about_cve(
    cve_id: str, description: str, severity: str, cvss_score: float | None
) -> str:
    """
    Generate a structured threat brief for a single CVE.
    Both cve_id and description are expected to have already been sanitized
    by xml_engine._sanitize_for_prompt() before reaching here.
    """
    if not is_configured():
        return "AI assistant is not configured. Set GEMINI_API_KEY in .env."

    # Defence-in-depth: cap description length even if caller forgot
    safe_description = (description or "")[:2000]
    safe_cve_id      = (cve_id or "")[:32]
    safe_severity    = (severity or "")[:16]
    safe_score       = cvss_score if cvss_score is not None else "N/A"

    prompt = (
        "You are a cybersecurity analyst. "
        "Provide a concise threat brief for the vulnerability below.\n\n"
        "---BEGIN VULNERABILITY DATA---\n"
        f"CVE ID: {safe_cve_id}\n"
        f"Severity: {safe_severity}\n"
        f"CVSS Score: {safe_score}\n"
        f"Description: {safe_description}\n"
        "---END VULNERABILITY DATA---\n\n"
        "Respond in this exact format:\n"
        "**Risk Summary:** (1 sentence, the core danger)\n"
        "**Attack Vector:** (how an attacker would exploit this)\n"
        "**Impact:** (what an attacker gains)\n"
        "**Recommended Action:** (1-2 specific mitigations)\n\n"
        "Keep each field to 1-2 sentences. Be direct and technical."
    )

    try:
        return _generate_with_fallback(prompt, max_output_tokens=300, temperature=0.3)
    except Exception as exc:
        LOGGER.warning("Gemini error: %s", exc)
        return f"AI request failed: {exc}"


def explain_text(query: str, context: str = "") -> str:
    """
    Generate a concise analyst-style explanation for user questions.
    query and context are validated/capped by the Pydantic model in server.py.
    """
    if not is_configured():
        return "Gemini is not configured. Set GEMINI_API_KEY in .env."

    safe_query   = (query   or "")[:1000]
    safe_context = (context or "")[:4096]

    prompt = (
        "You are a cybersecurity assistant for a CVE triage dashboard.\n\n"
        "---BEGIN USER QUESTION---\n"
        f"{safe_query}\n"
        "---END USER QUESTION---\n\n"
        "---BEGIN SCAN CONTEXT---\n"
        f"{safe_context or 'No additional context provided.'}\n"
        "---END SCAN CONTEXT---\n\n"
        "Answer format:\n"
        "- Give a short, direct explanation in plain English.\n"
        "- If relevant, include 3 bullets: Risk, Why it matters, What to do next.\n"
        "- Keep it practical and under 220 words.\n"
    )

    try:
        return _generate_with_fallback(prompt, max_output_tokens=300, temperature=0.25)
    except Exception as exc:
        LOGGER.warning("Gemini explain error: %s", exc)
        return f"AI request failed: {exc}"
