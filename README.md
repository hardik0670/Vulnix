# Vulnix v3.1 - CVE XML Threat Analyzer

<<<<<<< HEAD
Professional CVE XML scanner and analysis tool.  
FastAPI backend · Single-page HTML frontend · Dark & Light mode
=======
Professional CVE XML scanner with AI-powered threat briefs.
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)

FastAPI backend, single-page HTML frontend, dark/light mode, safe XML parsing, OWASP ZAP report support, and optional local CVSS prediction.

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
python server.py
```

Open `http://localhost:8000`.

## Environment Setup

<<<<<<< HEAD
All runtime config lives in `.env` (never committed).  
Copy `.env.example` → `.env` and edit:

```env
ALLOWED_ORIGINS=http://localhost:8000
=======
All secrets and runtime config live in `.env`, which is intentionally ignored by git.

```env
GEMINI_API_KEY=your-key-here
ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)
MAX_UPLOAD_MB=10
CVSS_MODEL_PATH=core/models/cvss_model.joblib
```

<<<<<<< HEAD
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
=======
If no Gemini key is set, scanning, charts, tables, exports, and local CVSS prediction still work. The AI brief actions are disabled until a key is configured.

## Features

1. Upload and parse CVE XML feeds and OWASP ZAP reports.
2. Repair malformed XML before parsing.
3. Extract CVE records and per-instance web findings.
4. Block XXE-style entity and network access during XML parsing.
5. Sanitize CVE descriptions before sending text to AI prompts.
6. Classify severity, CWE, and OWASP Top 10 categories where possible.
7. Predict missing CVSS scores with a local scikit-learn model when available.
8. Export CSV reports and cleaned XML.
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)

## Project Structure

```text
vulnix/
<<<<<<< HEAD
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
=======
|-- .env.example
|-- config.py
|-- server.py
|-- requirements.txt
|-- assets/
|   `-- sample_nvd_feed.xml
|-- core/
|   |-- xml_engine.py
|   |-- gemini_summarizer.py
|   |-- ml_predictor.py
|   |-- data_processor.py
|   `-- models/
|       `-- cvss_model.joblib
|-- scripts/
|   `-- train_cvss.py
`-- static/
    `-- index.html
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)
```

## API Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/` | Frontend |
<<<<<<< HEAD
| GET | `/api/status` | Health check |
| POST | `/api/scan` | Upload XML (max 10 MB), get all CVEs |
=======
| GET | `/api/status` | Health and AI availability |
| POST | `/api/scan` | Upload XML and return extracted records |
| POST | `/api/ai/brief` | AI threat brief for one CVE |
| POST | `/api/ai/explain` | Analyst-style explanation for a question |
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)

## Optional CVSS Predictor

Vulnix can fill in missing CVSS scores from vulnerability descriptions using `core/models/cvss_model.joblib`.

To retrain the model with local CSV or JSON datasets:

```bash
python scripts/train_cvss.py --dir datasets
```

The default model path is configured by `CVSS_MODEL_PATH`. Local training datasets are ignored by git because they can be large and environment-specific.

## Production Checklist

| Setting | Dev default | Production value |
| --- | --- | --- |
| `RELOAD` in `config.py` | `True` | `False` |
| `ALLOWED_ORIGINS` | localhost URLs | Your real frontend URL |
| `MAX_UPLOAD_MB` | `10` | Adjust to your needs |
| Gemini key | `.env` | Host-managed secret |
| CVSS model | local joblib file | Versioned artifact or configured path |

## Security Notes

<<<<<<< HEAD
- **CORS** is restricted to `ALLOWED_ORIGINS` — not wildcard in any mode.
- **XXE** is prevented: entity resolution and network access disabled in lxml parser.
- **Upload size** is capped at `MAX_UPLOAD_MB` (default 10 MB) server-side.
- **API keys** are loaded from environment only — never hardcoded.
=======
- CORS is restricted to `ALLOWED_ORIGINS`.
- XXE is mitigated by disabling entity resolution, DTD loading, and network access in the XML parser.
- Upload size is capped by `MAX_UPLOAD_MB`.
- Prompt-injection patterns in vulnerability descriptions are redacted before AI calls.
- API keys are read from environment variables only.
>>>>>>> d8fe507 (Analyze project and update core components for CVE XML Threat Analyzer)
