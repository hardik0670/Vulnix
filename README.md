# Vulnix v3 — CVE XML Threat Analyzer

Professional CVE XML scanner with AI-powered threat briefs.  
FastAPI backend · Single-page HTML frontend · Dark & Light mode

---

## Quick Start

```bash
pip install -r requirements.txt
python server.py
```

Open → **http://localhost:8000**

---

## Setup for AI Threat Briefs (optional)

Edit `config.py`:

```python
GEMINI_API_KEY = "your-key-here"   # https://aistudio.google.com/app/apikey
GEMINI_MODEL   = "gemini-1.5-flash"
```

If no key is set the app works fully — charts, tables, exports all function.  
The **🤖 Ask AI** button per CVE is greyed out until a key is configured.

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
vulnix_v3/
├── config.py              ← Set Gemini key here (backend only)
├── server.py              ← FastAPI app — run this
├── requirements.txt
├── assets/
│   └── sample_nvd_feed.xml
├── static/
│   └── index.html         ← Entire frontend
└── core/
    ├── xml_engine.py
    ├── gemini_summarizer.py
    └── __init__.py
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Frontend |
| GET | `/api/status` | Health + AI availability |
| POST | `/api/scan` | Upload XML, get all CVEs |
| POST | `/api/ai/brief` | AI threat brief for one CVE |
