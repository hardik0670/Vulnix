"""AI summarization utilities for Vulnix."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Any

from transformers import pipeline


LOGGER = logging.getLogger(__name__)

# Persistent executor to avoid thread creation overhead per request
_EXECUTOR = ThreadPoolExecutor(max_workers=1)


@dataclass(slots=True)
class SummarizationConfig:
    """Runtime configuration for HuggingFace summarization."""

    model_name: str = "sshleifer/distilbart-cnn-12-6"
    max_length: int = 80
    min_length: int = 20
    timeout_seconds: int = 20


class AISummarizationError(Exception):
    """Raised when summarization cannot be completed safely."""


class AISummarizer:
    """Wraps a HuggingFace summarization pipeline with defensive handling."""

    def __init__(self, config: SummarizationConfig | None = None) -> None:
        self.config = config or SummarizationConfig()
        self._pipeline: Any | None = None

    def _get_pipeline(self):
        """Lazily initialize and cache pipeline to reduce startup cost."""
        if self._pipeline is None:
            self._pipeline = pipeline(
                task="summarization",
                model=self.config.model_name,
                tokenizer=self.config.model_name,
            )
        return self._pipeline

    def summarize(self, description: str) -> str:
        """Generate a concise executive summary from technical CVE text."""
        text = (description or "").strip()
        if not text:
            return "No description available for summarization."

        # Skip expensive model invocation for already-short descriptions.
        if len(text.split()) < 25:
            return text

        summarizer = self._get_pipeline()

        def _run_inference() -> str:
            output = summarizer(
                text,
                max_length=self.config.max_length,
                min_length=self.config.min_length,
                do_sample=False,
                truncation=True,
            )
            if not output or "summary_text" not in output[0]:
                raise AISummarizationError("Model returned invalid summary payload.")
            return output[0]["summary_text"].strip()

        try:
            future = _EXECUTOR.submit(_run_inference)
            return future.result(timeout=self.config.timeout_seconds)
        except FutureTimeoutError:
            LOGGER.warning("Summarization timed out for a CVE description.")
            return "Summary generation timed out. Review raw description manually."
        except Exception as exc:  # noqa: BLE001 - defensive fallback for UI reliability
            LOGGER.exception("Summarization failed: %s", exc)
            return "Summary unavailable due to model/runtime error."

