import os
from pathlib import Path
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

# ── Gemini AI Configuration ──────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
# Ordered failover list — first model tried first, then fallback in sequence.
# Verify current model IDs at: https://ai.google.dev/gemini-api/docs/models
GEMINI_MODEL_FALLBACK: list[str] = [
    "gemini-2.5-flash-lite",       # primary  (fast, cheap)
    "gemini-2.0-flash",            # fallback (more capable)
]

# ── Server Configuration ─────────────────────────────────────────────────
HOST:   str  = "127.0.0.1"
PORT:   int  = 8000
RELOAD: bool = True   # Set False in production

# ── CORS ─────────────────────────────────────────────────────────────────
# In production replace with your real frontend URL, e.g.:
#   ALLOWED_ORIGINS = ["https://vulnix.yourdomain.com"]
ALLOWED_ORIGINS: list[str] = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
).split(",")

# ── Upload Limits ─────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024  # default 10 MB

# ── ML Configuration ─────────────────────────────────────────────────────
# ML CVSS predictor
CVSS_MODEL_PATH: str = os.getenv(
    "CVSS_MODEL_PATH",
    str(BASE_DIR / "core" / "models" / "cvss_model.joblib"),
)
