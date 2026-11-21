"""Late fusion for independent modality risks with confidence-aware weighting."""
from __future__ import annotations
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = {
    "weights": {"text": 0.45, "url": 0.35, "html": 0.20, "header": 0.12},
    "thresholds": {"legitimate_upper": 0.35, "suspicious_upper": 0.65},
    "confidence": {"default": 1.0, "html_rule_based": 0.65, "email_header_rule_based": 0.80},
    "escalation": {"enabled": True, "url_score_minimum": 0.90,
                   "requires_password_input": True, "requires_external_form": True,
                   "risk_score_floor": 0.85},
}

def load_fusion_config(path: str | Path | None = None) -> dict:
    """Load fusion settings or fall back to documented defaults."""
    config_path = Path(path) if path else ROOT / "models" / "fusion_config.json"
    if not config_path.is_file():
        return json.loads(json.dumps(DEFAULT_CONFIG))
    with config_path.open(encoding="utf-8") as handle:
        return json.load(handle)

class MultimodalFusionEngine:
    """Aggregate available modality scores; weights renormalize for each request.

    Confidence scales a modality's configured weight only when multiple inputs
    are available. With one input, its score is returned unchanged. Scores are
    evidence estimates, not calibrated probabilities or proof of phishing.
    """
    def __init__(self, config: dict | None = None):
        self.config = config or load_fusion_config()

    @staticmethod
    def _validate_score(name: str, score: float | None) -> None:
        if score is not None and (not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 1):
            raise ValueError(f"{name} must be None or a finite number between 0 and 1.")

    def label_for(self, score: float) -> str:
        thresholds = self.config["thresholds"]
        if score < thresholds["legitimate_upper"]:
            return "Legitimate"
        if score < thresholds["suspicious_upper"]:
            return "Suspicious"
        return "Phishing"

    def fuse(self, url_score: float | None = None, text_score: float | None = None,
             html_score: float | None = None, header_score: float | None = None,
             confidences: dict | None = None,
             availability: dict | None = None, severe_pair: bool = False) -> dict:
        """Fuse optional scores and return risk, decision, contributing weights.

        `availability` can explicitly disable a score. Missing confidence values
        use 1.0. For multiple modalities, normalized weight = base weight × confidence.
        If all confidences are zero, base weights are used to avoid a zero denominator.
        """
        scores = {"url": url_score, "text": text_score, "html": html_score, "header": header_score}
        confidence_defaults = {name: self.config["confidence"]["default"] for name in scores}
        confidence_defaults["html"] = self.config["confidence"].get("html_rule_based", confidence_defaults["html"])
        confidence_defaults["header"] = self.config["confidence"].get("email_header_rule_based", confidence_defaults["header"])
        confidence_values = {**confidence_defaults, **(confidences or {})}
        availability = availability or {}
        active = {}
        for name, score in scores.items():
            self._validate_score(f"{name}_score", score)
            confidence = confidence_values[name]
            if not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
                raise ValueError(f"{name} confidence must be a finite number between 0 and 1.")
            if score is not None and availability.get(name, True):
                active[name] = {"score": float(score), "confidence": float(confidence)}
        if not active:
            raise ValueError("At least one available modality score is required.")

        if len(active) == 1:
            name = next(iter(active))
            weighted = {name: 1.0}
            risk = active[name]["score"]
        else:
            raw_weights = {name: self.config["weights"][name] * data["confidence"] for name, data in active.items()}
            if sum(raw_weights.values()) == 0:
                raw_weights = {name: self.config["weights"][name] for name in active}
            total = sum(raw_weights.values())
            weighted = {name: weight / total for name, weight in raw_weights.items()}
            risk = sum(active[name]["score"] * weighted[name] for name in active)

        escalation = self.config["escalation"]
        # `severe_pair` means the caller observed a password form and external
        # form action; also require both modalities and the configured URL score.
        escalated = bool(severe_pair and escalation["enabled"] and
                         "url" in active and "html" in active and
                         active["url"]["score"] >= escalation["url_score_minimum"])
        if escalated:
            risk = max(risk, escalation["risk_score_floor"])
        risk = min(max(float(risk), 0.0), 1.0)
        return {"risk_score": risk, "final_label": self.label_for(risk),
                "modalities_used": list(active),
                "modality_breakdown": {name: {**data, "label": self.label_for(data["score"])} for name, data in active.items()},
                "normalized_weights": weighted, "escalated": escalated}

def fuse_predictions(predictions: dict) -> dict:
    """Compatibility wrapper accepting score fields and optional confidences."""
    return MultimodalFusionEngine().fuse(
        url_score=predictions.get("url_score"), text_score=predictions.get("text_score"),
        html_score=predictions.get("html_score"), header_score=predictions.get("header_score"),
        confidences=predictions.get("confidences"),
        availability=predictions.get("availability"), severe_pair=predictions.get("severe_pair", False))
