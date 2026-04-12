"""
CVSS Score Predictor — Local ML Inference
=========================================
Uses a trained scikit-learn pipeline (TF-IDF + Ridge) to predict CVSS scores.
"""

import os
import joblib
import logging

import config

LOGGER = logging.getLogger("vulnix.ml")

class CVSSPredictor:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_ready = False
        self._load_model()

    def _load_model(self):
        """Load the model and vectorizer from the configured path."""
        path = config.CVSS_MODEL_PATH
        if not os.path.exists(path):
            LOGGER.info("ML model file not found at %s. Predictions will be disabled.", path)
            return

        try:
            data = joblib.load(path)
            self.model = data.get("model")
            self.vectorizer = data.get("vectorizer")
            self.is_ready = self.model is not None and self.vectorizer is not None
            if self.is_ready:
                LOGGER.info("ML model loaded successfully from %s", path)
        except Exception as e:
            LOGGER.error("Failed to load ML model: %s", e)

    def predict(self, description: str) -> float | None:
        """
        Predict a CVSS score based on the description text.
        Returns: float (0.0 - 10.0) or None if prediction fails.
        """
        if not self.is_ready or not description:
            return None

        try:
            # Transform text
            x = self.vectorizer.transform([description])
            # Predict
            score = self.model.predict(x)[0]
            # Clip to valid CVSS range
            return round(max(0.0, min(10.0, float(score))), 1)
        except Exception as e:
            LOGGER.error("Prediction error: %s", e)
            return None

# Singleton instance
predictor = CVSSPredictor()
