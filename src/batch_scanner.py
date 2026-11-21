"""Safe CSV batch scanning helper for PhishGuard AI V3."""
from __future__ import annotations

import pandas as pd

from src.prediction import predict_multimodal


def _detect_column(df: pd.DataFrame) -> tuple[str | None, str | None]:
    normalized = {str(column).strip().lower(): str(column) for column in df.columns}
    for name in ("url", "text", "email"):
        if name in normalized:
            return normalized[name], name
    return None, None


def scan_csv_batch(df: pd.DataFrame, policy_mode: str = "Balanced", max_rows: int = 500) -> pd.DataFrame:
    """Scan up to max_rows rows, auto-detecting url/text/email input columns."""
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame.")
    if df.empty:
        raise ValueError("CSV contains no data rows.")

    column, kind = _detect_column(df)
    if column is None:
        raise ValueError("CSV must contain a url, text, or email column.")

    rows = []
    for value in df[column].fillna("").astype(str).head(max_rows):
        value = value.strip()
        if not value:
            continue
        kwargs = {"url": value} if kind == "url" else {"text": value}
        try:
            result = predict_multimodal(policy_mode=policy_mode, **kwargs)
            top_indicator = result["indicators"][0] if result["indicators"] else "No strong indicator"
            rows.append({
                "input_preview": value[:160].replace("\n", " "),
                "final_label": result["final_label"],
                "risk_score": result["risk_score"],
                "modalities_used": ", ".join(result["modalities_used"]),
                "top_indicator": top_indicator,
            })
        except Exception as exc:
            rows.append({
                "input_preview": value[:160].replace("\n", " "),
                "final_label": "Suspicious",
                "risk_score": 0.50,
                "modalities_used": kind,
                "top_indicator": f"Row scan failed safely: {type(exc).__name__}",
            })

    if not rows:
        raise ValueError("CSV has no non-empty supported input values.")
    return pd.DataFrame(rows)
