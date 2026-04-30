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
        results = self.predict_batch([description])
        return results[0] if results else None

    def predict_batch(self, descriptions: list[str]) -> list[float | None]:
        """
        Predict CVSS scores for a batch of descriptions.
        Returns a list of floats (0.0 - 10.0) or Nones for empty descriptions or failures.
        """
        if not self.is_ready or not descriptions:
            return [None] * len(descriptions)

        results: list[float | None] = [None] * len(descriptions)
        
        # Identify non-empty strings to predict
        valid_indices = [i for i, desc in enumerate(descriptions) if desc and str(desc).strip()]
        
        if not valid_indices:
            return results

        valid_descriptions = [descriptions[i] for i in valid_indices]

        try:
            x = self.vectorizer.transform(valid_descriptions)
            scores = self.model.predict(x)
            
            for idx, score in zip(valid_indices, scores):
                results[idx] = round(max(0.0, min(10.0, float(score))), 1)
                
        except Exception as exc:
            LOGGER.error("Batch prediction error: %s", exc)
            # Retain None values on error

        return results


# Singleton instance
predictor = CVSSPredictor()
