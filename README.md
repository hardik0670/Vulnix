# Vulnix v3.1 — CVE XML Threat Analyzer

Professional CVE XML scanner with AI-powered threat briefs.  
FastAPI backend · Single-page HTML frontend · Dark & Light mode

---

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env          # then fill in your Gemini API key
python server.py
```

Open → **http://localhost:8000**

---

## Environment Setup

All secrets and runtime config live in `.env` (never committed).  
Copy `.env.example` → `.env` and edit:

```env
GEMINI_API_KEY=your-key-here        # https://aistudio.google.com/app/apikey
ALLOWED_ORIGINS=http://localhost:8000
MAX_UPLOAD_MB=10
```

If no key is set the app works fully — charts, tables, exports all function.  
The **🤖 Ask AI** button per CVE is greyed out until a key is configured.

---

## Production Checklist

| Setting | Dev default | Production value |
|---------|-------------|-----------------|
| `RELOAD` in `config.py` | `True` | `False` |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | Your real frontend URL |
| `MAX_UPLOAD_MB` | `10` | Adjust to your needs |
| Gemini key | in `.env` | Env var injected by host |

---

## What Users See

1. **Upload** — drag & drop or click to pick a `.xml` CVE feed
2. **Scan** — instant parse, repair, extract
3. **Dashboard** — 4 charts + critical CVE table
4. **Intelligence** — full sortable/filterable table with per-CVE AI brief button
5. **XML Diff** — raw vs cleaned XML side by side
6. **Export** — CSV report or cleaned XML download
7. **Dark / Light** mode toggle in top-right corner

---

## Project Structure

```
vulnix/
├── .env.example           ← Copy to .env, add real key (safe to commit)
├── config.py              ← Runtime config, reads from .env
├── server.py              ← FastAPI app — run this
├── requirements.txt
├── assets/
│   └── sample_nvd_feed.xml
├── static/
│   └── index.html         ← Entire frontend
└── core/
    ├── xml_engine.py      ← XML parse, sanitize, XXE-safe, CVE extract
    ├── gemini_summarizer.py ← Gemini AI with model failover
    └── __init__.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Frontend |
| GET | `/api/status` | Health + AI availability |
| POST | `/api/scan` | Upload XML (max 10 MB), get all CVEs |
| POST | `/api/ai/brief` | AI threat brief for one CVE |
| POST | `/api/ai/explain` | Freeform analyst explanation |

---

## Security Notes

- **CORS** is restricted to `ALLOWED_ORIGINS` — not wildcard in any mode.
- **XXE** is prevented: entity resolution and network access disabled in lxml parser.
- **Upload size** is capped at `MAX_UPLOAD_MB` (default 10 MB) server-side.
- **Prompt injection** from CVE descriptions is stripped before AI calls.
- **API keys** are loaded from environment only — never hardcoded.
