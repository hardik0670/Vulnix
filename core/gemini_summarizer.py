"""Gemini AI assistant for Vulnix — reads credentials from config.py only."""

from __future__ import annotations
import logging
import config
from google import genai
from google.genai import types

LOGGER = logging.getLogger(__name__)

MODEL_FALLBACK_ORDER = [
    ("Gemini 3.1 Flash Lite", "gemini-3.1-flash-lite-preview"),
    ("Gemini 2.5 Flash Lite", "gemini-2.5-flash-lite"),
]

_client = None


def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=config.GEMINI_API_KEY.strip())
    return _client


def _model_failover_sequence() -> list[tuple[str, str]]:
    ids = getattr(config, "GEMINI_MODEL_FALLBACK", None) or [m[1] for m in MODEL_FALLBACK_ORDER]
    labels = {
        "gemini-3.1-flash-lite-preview": "Gemini 3.1 Flash Lite",
        "gemini-3-flash-preview": "Gemini 3 Flash",
        "gemini-2.5-flash": "Gemini 2.5 Flash",
        "gemini-2.5-flash-lite": "Gemini 2.5 Flash Lite",
    }
    return [(labels.get(mid, mid), mid) for mid in ids]


def _extract_text(response) -> str:
    text = getattr(response, "text", None)
    if text:
        return text.strip()
    return ""


def _generate_with_fallback(prompt: str, max_output_tokens: int = 300, temperature: float = 0.3) -> str:
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
    """Return True only if a real API key has been set in config.py."""
    key = config.GEMINI_API_KEY.strip()
    return bool(key) and key != "YOUR_GEMINI_API_KEY_HERE"


def ask_about_cve(cve_id: str, description: str, severity: str, cvss_score) -> str:
    """
    Generate a structured threat brief for a single CVE.
    Called from the dashboard 'Ask AI' button per-CVE.
    """
    if not is_configured():
        return "AI assistant is not configured. Set GEMINI_API_KEY in config.py."

    prompt = f"""You are a cybersecurity analyst. Provide a concise threat brief for:

CVE ID: {cve_id}
Severity: {severity}
CVSS Score: {cvss_score if cvss_score is not None else 'N/A'}
Description: {description}

Respond in this exact format:
**Risk Summary:** (1 sentence, the core danger)
**Attack Vector:** (how an attacker would exploit this)
**Impact:** (what an attacker gains)
**Recommended Action:** (1-2 specific mitigations)

Keep each field to 1-2 sentences. Be direct and technical."""

    try:
        return _generate_with_fallback(prompt, max_output_tokens=300, temperature=0.3)
    except Exception as exc:
        LOGGER.warning("Gemini error: %s", exc)
        return f"AI request failed: {exc}"


def summarize_all(records: list[dict]) -> list[str]:
    """
    Generate one-line summaries for all CVEs (batch, used in export).
    """
    if not is_configured():
        return ["AI not configured." for _ in records]

    results = []
    for r in records:
        prompt = (
            f"CVE {r['cve_id']} ({r['severity']}): {r['description']}\n"
            "Write ONE sentence (max 25 words) summarizing the core risk. No preamble."
        )
        try:
            results.append(_generate_with_fallback(prompt, max_output_tokens=80, temperature=0.2))
        except Exception as exc:
            results.append(f"Error: {exc}")
    return results


def explain_text(query: str, context: str = "") -> str:
    """
    Generate a concise analyst-style explanation for user questions.
    """
    if not is_configured():
        return "Gemini is not configured. Set GEMINI_API_KEY in config.py."

    prompt = f"""You are a cybersecurity assistant for a CVE triage dashboard.

User question:
{query}

Optional context from current scan:
{context or "No additional context provided."}

Answer format:
- Give a short, direct explanation in plain English.
- If relevant, include 3 bullets: Risk, Why it matters, What to do next.
- Keep it practical and under 220 words.
"""

    try:
        return _generate_with_fallback(prompt, max_output_tokens=300, temperature=0.25)
    except Exception as exc:
        LOGGER.warning("Gemini explain error: %s", exc)
        return f"AI request failed: {exc}"
