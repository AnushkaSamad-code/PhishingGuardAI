"""Train the upgraded URL model without changing the existing text model."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

# Avoid loky's Windows physical-core probe, which depends on legacy `wmic`.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(min(4, os.cpu_count() or 1)))

import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.url_analyzer import extract_url_feature_rows, FEATURE_NAMES
from utils.metrics import classification_metrics
from src.webpage_analyzer import DEFAULT_WEIGHTS

DATA = ROOT / "data" / "processed"
MODELS = ROOT / "models"

def _load_split(name: str, modality: str) -> tuple[pd.Series, pd.Series]:
    """Read one prepared split and validate its expected columns."""
    frame = pd.read_csv(DATA / f"{modality}_{name}.csv")
    if list(frame.columns) != ["text", "label"]:
        raise ValueError(f"Expected text,label columns in {modality}_{name}.csv; found {list(frame.columns)}")
    return frame["text"].fillna("").astype(str), frame["label"].astype(int)

def _evaluate(model, x, y) -> dict:
    return classification_metrics(y, model.predict(x))

def train_models() -> dict:
    """Select a histogram gradient-boosting URL model using train/validation data.

    The held-out test split is intentionally not used here. The existing text
    model artifact is left untouched.
    """
    MODELS.mkdir(parents=True, exist_ok=True)
    url_train, y_url_train = _load_split("train", "url")
    url_val, y_url_val = _load_split("val", "url")
    x_url_train = extract_url_feature_rows(url_train)
    x_url_val = extract_url_feature_rows(url_val)
    assert list(x_url_train.columns) == FEATURE_NAMES

    candidates = [
        {"max_leaf_nodes": 15, "max_iter": 120, "learning_rate": 0.10},
        {"max_leaf_nodes": 31, "max_iter": 120, "learning_rate": 0.08},
    ]
    selection = []
    best_model = None
    best_metrics = None
    best_parameters = None
    for parameters in candidates:
        candidate = HistGradientBoostingClassifier(
            **parameters, max_bins=255, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.10,
            n_iter_no_change=12, class_weight="balanced", random_state=42)
        candidate.fit(x_url_train, y_url_train)
        metrics = _evaluate(candidate, x_url_val, y_url_val)
        selection.append({"parameters": parameters, "validation": metrics,
                          "iterations_used": int(candidate.n_iter_)})
        if best_metrics is None or metrics["f1"] > best_metrics["f1"]:
            best_model, best_metrics, best_parameters = candidate, metrics, parameters

    joblib.dump(best_model, MODELS / "url_model.pkl", compress=3)
    results = {
        "url": {"validation": best_metrics, "selected_parameters": best_parameters,
                "iterations_used": int(best_model.n_iter_), "candidate_runs": selection,
                "training_rows": len(y_url_train), "validation_rows": len(y_url_val)},
        "text_model": "Existing text_model.pkl was not retrained or overwritten.",
    }

    config = {
        "analyzer": "static_html_rules_v1", "parser": "BeautifulSoup with Python html.parser; no scripts or external resources are executed/fetched",
        "score_range": [0.0, 1.0], "score_method": "weighted additive indicators, capped at 1.0",
        "weights": DEFAULT_WEIGHTS,
        "features": ["total_links", "external_links", "internal_links", "external_link_ratio", "form_count",
                     "password_input_count", "hidden_input_count", "iframe_count", "script_count",
                     "external_form_count", "inline_event_attribute_count"],
    }
    (MODELS / "web_analyzer_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    (MODELS / "training_metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
    return results

if __name__ == "__main__":
    train_models()
