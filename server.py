"""Vulnix FastAPI server."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from core.xml_engine import XMLSanitizationError, sanitize_and_extract
from core.ml_predictor import predictor
import config

app = FastAPI(title="Vulnix", version="3.1.0")

# ── CORS ──────────────────────────────────────────────────────────────────
# Restrict to configured origins. Defaults to localhost only.
# Set ALLOWED_ORIGINS in config.py when deploying to production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

BASE   = Path(__file__).parent
STATIC = BASE / "static"
if STATIC.exists():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ── Frontend ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    p = STATIC / "index.html"
    return HTMLResponse(p.read_text(encoding="utf-8") if p.exists() else "<h1>Vulnix</h1>")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    from fastapi.responses import FileResponse
    return FileResponse(STATIC / "favicon.png")


# ── Health / capability check ─────────────────────────────────────────────
@app.get("/api/status")
async def status():
    return {
        "ok": True,
        "ml_enabled": predictor.is_ready
    }


# ── Parse + scan XML ──────────────────────────────────────────────────────
@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    """Parse XML, extract CVEs, return full result immediately."""

    # Enforce file size limit
    data = await file.read()
    if not data:
        raise HTTPException(400, "Empty file.")
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"File too large. Maximum allowed size is "
            f"{config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.",
        )

    # Loosely enforce XML content-type
    content_type = (file.content_type or "").lower()
    if content_type and "xml" not in content_type and "octet" not in content_type and "text" not in content_type:
        raise HTTPException(415, "Only XML files are accepted.")

    try:
        result = sanitize_and_extract(data)
        
        # ── ML Automatic Prediction ──────────────────────────────────────
        # If a record has no score, try to predict it locally.
        for rec in result.records:
            if rec.get("cvss_score") is None:
                pred = predictor.predict(rec.get("description", ""))
                if pred is not None:
                    rec["cvss_score"] = pred
                    rec["ml_predicted"] = True
                    
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
        "ml_enabled": predictor.is_ready,
    })


# ── Run ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host=config.HOST, port=config.PORT, reload=config.RELOAD)
