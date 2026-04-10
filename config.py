"""
Vulnix Backend Configuration
=============================
Set your Gemini API key and preferred model here.
This file is never exposed to the frontend or end users.
"""

import os
from dotenv import load_dotenv

# Load variables from .env if present
load_dotenv()

# ── Gemini AI Configuration ──────────────────────────────────────────────
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

# Ordered failover list (first model tried first, then fallback in sequence)
# Valid models: gemini-3.1-flash-lite-preview, gemini-2.5-flash-lite
GEMINI_MODEL_FALLBACK: list[str] = [
    "gemini-3.1-flash-lite-preview",
    "gemini-2.5-flash-lite",
]

# ── Server Configuration ─────────────────────────────────────────────────
HOST: str = "127.0.0.1"
PORT: int = 8000
RELOAD: bool = True   # Set False in production
