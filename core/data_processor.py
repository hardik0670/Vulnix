"""Data processing helpers for Vulnix — metrics, chart data, exports."""

from __future__ import annotations

from io import StringIO
from typing import Any

import pandas as pd

EXPECTED_COLUMNS = ["cve_id", "severity", "cvss_score", "published_date", "description", "cwe"]
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def records_to_dataframe(records: list[dict[str, Any]]) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=EXPECTED_COLUMNS)
    df = pd.DataFrame(records)
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[EXPECTED_COLUMNS].copy()
    df["severity"] = df["severity"].fillna("UNKNOWN").astype(str).str.upper()
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")
    df["description"] = df["description"].fillna("").astype(str)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    return df


def build_metrics(df: pd.DataFrame, fixed_error_count: int) -> dict[str, Any]:
    if df.empty:
        return {
            "total": 0, "critical": 0, "high": 0,
            "avg_cvss": None, "fixed_errors": fixed_error_count,
        }
    scored = df["cvss_score"].dropna()
    return {
        "total": len(df),
        "critical": int((df["severity"] == "CRITICAL").sum()),
        "high": int((df["severity"] == "HIGH").sum()),
        "avg_cvss": round(float(scored.mean()), 1) if not scored.empty else None,
        "fixed_errors": int(fixed_error_count),
    }


def severity_distribution(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["severity", "count"])
    counts = (
        df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
    )
    counts["severity"] = pd.Categorical(counts["severity"], categories=SEVERITY_ORDER, ordered=True)
    return counts.sort_values("severity").reset_index(drop=True)


def monthly_trend(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty or df["published_date"].isna().all():
        return pd.DataFrame(columns=["month", "count"])
    tmp = df.copy()
    tmp["month"] = tmp["published_date"].dt.to_period("M").astype(str)
    result = tmp.groupby("month").size().reset_index(name="count")
    return result.sort_values("month")


def cvss_histogram_data(df: pd.DataFrame) -> pd.DataFrame:
    scored = df["cvss_score"].dropna()
    if scored.empty:
        return pd.DataFrame(columns=["range", "count"])
    bins = [0, 2, 4, 6, 8, 10]
    labels = ["0-2", "2-4", "4-6", "6-8", "8-10"]
    bucketed = pd.cut(scored, bins=bins, labels=labels, include_lowest=True)
    counts = bucketed.value_counts().reindex(labels, fill_value=0).reset_index()
    counts.columns = ["range", "count"]
    return counts


def dataframe_to_csv_bytes(df: pd.DataFrame) -> bytes:
    buf = StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")
