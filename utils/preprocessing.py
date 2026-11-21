"""Cleaning and splitting helpers for the project's real URL and email data."""
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

LABEL_MAP = {"good": 0, "legitimate": 0, "safe": 0, "ham": 0, "0": 0,
             "bad": 1, "phishing": 1, "spam": 1, "1": 1}

def _standardize_label(values: pd.Series) -> pd.Series:
    """Map supported source labels to 0=safe and 1=phishing; reject unknowns."""
    normalized = values.astype("string").str.strip().str.lower()
    mapped = normalized.map(LABEL_MAP)
    if mapped.isna().any():
        unknown = sorted(normalized[mapped.isna()].dropna().unique().tolist())
        raise ValueError(f"Unsupported label values: {unknown}")
    return mapped.astype("int64")

def clean_dataset(frame: pd.DataFrame, content_column: str, label_column: str) -> tuple[pd.DataFrame, dict]:
    """Return normalized content/label rows and accurate cleaning counts."""
    if content_column not in frame or label_column not in frame:
        raise ValueError(f"Expected columns {content_column!r} and {label_column!r}; got {list(frame.columns)}")
    original = len(frame)
    data = frame[[content_column, label_column]].copy()
    data.columns = ["text", "label"]
    data["text"] = data["text"].astype("string").str.strip()
    null_mask = data["text"].isna() | data["label"].isna()
    nulls = int(null_mask.sum())
    data = data.loc[~null_mask].copy()
    blank_mask = data["text"].eq("")
    blanks = int(blank_mask.sum())
    data = data.loc[~blank_mask].copy()
    data["label"] = _standardize_label(data["label"])
    duplicates = int(data.duplicated(keep="first").sum())
    data = data.drop_duplicates(keep="first").reset_index(drop=True)
    return data, {"original_rows": original, "null_rows_removed": nulls,
                  "whitespace_rows_removed": blanks, "duplicate_rows_removed": duplicates,
                  "final_rows": len(data), "source_columns": list(frame.columns)}

def split_dataset(data: pd.DataFrame, output_dir: str | Path, prefix: str, random_state: int = 42) -> dict:
    """Write stratified 70/15/15 splits, retaining both safe and phishing classes."""
    if data["label"].nunique() != 2 or data["label"].value_counts().min() < 3:
        raise ValueError("Stratified train/validation/test splitting requires both classes with at least 3 rows each.")
    train, holdout = train_test_split(data, test_size=0.30, random_state=random_state, stratify=data["label"])
    val, test = train_test_split(holdout, test_size=0.50, random_state=random_state, stratify=holdout["label"])
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    result = {}
    for name, part in (("train", train), ("val", val), ("test", test)):
        part = part.reset_index(drop=True)
        part.to_csv(output / f"{prefix}_{name}.csv", index=False)
        result[name] = {"rows": len(part), "class_counts": {str(k): int(v) for k, v in part["label"].value_counts().sort_index().items()}}
    return result
