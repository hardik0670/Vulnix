"""Vulnix FastAPI server."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from core.xml_engine import XMLSanitizationError, sanitize_and_extract
import core.gemini_summarizer as ai
import config

app = FastAPI(title="Vulnix", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

BASE   = Path(__file__).parent
STATIC = BASE / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ── Frontend ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    p = STATIC / "index.html"
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>Vulnix</h1>")


# ── Health / capability check ─────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {"ok": True, "ai_enabled": ai.is_configured()}


# ── Parse + scan XML ──────────────────────────────────────────────────────
@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    """Parse XML, extract CVEs, return full result immediately."""
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    try:
        result = sanitize_and_extract(data)
    except XMLSanitizationError as e:
        raise HTTPException(422, str(e))
    except Exception as e:
        raise HTTPException(500, f"Unexpected error: {e}")

    return JSONResponse({
        "records":           result.records,
        "cve_records":       result.cve_records,
        "finding_records":   result.finding_records,
        "raw_xml":           result.raw_xml,
        "cleaned_xml":       result.cleaned_xml,
        "fixed_error_count": result.fixed_error_count,
        "total":             len(result.records),
        "totals": {
            "cve":      len(result.cve_records),
            "findings": len(result.finding_records),
        },
        "ai_enabled":        ai.is_configured(),
    })


# ── Per-CVE AI brief (the small assistant button) ─────────────────────────
@app.post("/api/ai/brief")
async def ai_brief(payload: dict):
    """
    Called when user clicks 'Ask AI' on a single CVE card.
    Returns a structured threat brief from Gemini.
    """
    if not ai.is_configured():
        raise HTTPException(503, "AI assistant not configured on server.")

    cve_id      = payload.get("cve_id", "")
    description = payload.get("description", "")
    severity    = payload.get("severity", "")
    cvss_score  = payload.get("cvss_score")

    loop = asyncio.get_event_loop()
    brief = await loop.run_in_executor(
        None, ai.ask_about_cve, cve_id, description, severity, cvss_score
    )
    return {"brief": brief}


@app.post("/api/ai/explain")
async def ai_explain(payload: dict):
    """
    Called from the Gemini explanation panel in the UI.
    Returns a concise analyst-style explanation for freeform queries.
    """
    if not ai.is_configured():
        raise HTTPException(503, "Gemini assistant not configured on server.")

    query = (payload.get("query") or "").strip()
    context = (payload.get("context") or "").strip()
    if not query:
        raise HTTPException(400, "Query cannot be empty.")

    loop = asyncio.get_event_loop()
    explanation = await loop.run_in_executor(None, ai.explain_text, query, context)
    return {"explanation": explanation}


# ── Run ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host=config.HOST, port=config.PORT, reload=config.RELOAD)
