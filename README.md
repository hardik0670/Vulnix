# Vulnix v3.1 — CVE XML Threat Analyzer

Professional CVE XML scanner and analysis tool.  
FastAPI backend · Single-page HTML frontend · Dark & Light mode

---

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
python server.py
```

Open → **http://localhost:8000**

---

## Environment Setup

All runtime config lives in `.env` (never committed).  
Copy `.env.example` → `.env` and edit:

```env
ALLOWED_ORIGINS=http://localhost:8000
MAX_UPLOAD_MB=10
```

---

## Production Checklist

| Setting | Dev default | Production value |
|---------|-------------|-----------------|
| `RELOAD` in `config.py` | `True` | `False` |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | Your real frontend URL |
| `MAX_UPLOAD_MB` | `10` | Adjust to your needs |

---

## What Users See

1. **Upload** — drag & drop or click to pick a `.xml` CVE feed
2. **Scan** — instant parse, repair, extract
3. **Dashboard** — 4 charts + critical CVE table
4. **Intelligence** — full sortable/filterable table
5. **XML Diff** — raw vs cleaned XML side by side
6. **Export** — CSV report or cleaned XML download
7. **Dark / Light** mode toggle in top-right corner

---

## Project Structure

```
vulnix/
├── .env.example           ← Copy to .env (safe to commit)
├── config.py              ← Runtime config, reads from .env
├── server.py              ← FastAPI app — run this
├── requirements.txt
├── assets/
│   └── sample_nvd_feed.xml
├── static/
│   └── index.html         ← Entire frontend
└── core/
    ├── xml_engine.py      ← XML parse, sanitize, XXE-safe, CVE extract
    └── __init__.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Frontend |
| GET | `/api/status` | Health check |
| POST | `/api/scan` | Upload XML (max 10 MB), get all CVEs |

---

## Security Notes

- **CORS** is restricted to `ALLOWED_ORIGINS` — not wildcard in any mode.
- **XXE** is prevented: entity resolution and network access disabled in lxml parser.
- **Upload size** is capped at `MAX_UPLOAD_MB` (default 10 MB) server-side.
- **API keys** are loaded from environment only — never hardcoded.
