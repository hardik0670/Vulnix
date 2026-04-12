import os
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

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
CVSS_MODEL_PATH: str = os.path.join("core", "models", "cvss_model.joblib")
