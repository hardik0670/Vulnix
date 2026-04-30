"""Optional CVSS score predictor backed by a local scikit-learn model."""

from __future__ import annotations

import logging
from pathlib import Path

import joblib

import config

LOGGER = logging.getLogger("vulnix.ml")


class CVSSPredictor:
    def __init__(self) -> None:
        self.model = None
        self.vectorizer = None
        self.is_ready = False
        self._load_model()

    def _load_model(self) -> None:
        """Load the model and vectorizer from the configured path."""
        path = Path(config.CVSS_MODEL_PATH)
        if not path.exists():
            LOGGER.info("ML model file not found at %s. Predictions will be disabled.", path)
            return

        try:
            data = joblib.load(path)
            self.model = data.get("model") if isinstance(data, dict) else None
            self.vectorizer = data.get("vectorizer") if isinstance(data, dict) else None
            self.is_ready = self.model is not None and self.vectorizer is not None
            if self.is_ready:
                LOGGER.info("ML model loaded successfully from %s", path)
            else:
                LOGGER.warning("ML model file at %s did not contain model/vectorizer.", path)
        except Exception as exc:
            LOGGER.error("Failed to load ML model: %s", exc)

    def predict(self, description: str) -> float | None:
        """
        Predict a CVSS score based on the description text.
        Returns: float (0.0 - 10.0) or None if prediction fails.
        """
        if not self.is_ready or not description:
            return None

        try:
            x = self.vectorizer.transform([description])
            score = self.model.predict(x)[0]
            return round(max(0.0, min(10.0, float(score))), 1)
        except Exception as exc:
            LOGGER.error("Prediction error: %s", exc)
            return None


# Singleton instance
predictor = CVSSPredictor()
