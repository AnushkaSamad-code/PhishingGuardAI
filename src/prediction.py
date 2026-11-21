"""Lazy-loading multimodal prediction pipeline with static email parsing."""
from __future__ import annotations
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re

# Avoid loky's Windows physical-core probe, which depends on legacy `wmic`.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(min(4, os.cpu_count() or 1)))

import joblib

ROOT = Path(__file__).resolve().parents[1]

@lru_cache(maxsize=1)
def _load_artifacts():
    """Load model and JSON artifacts once per process; clear cache to reload."""
    from src.multimodal_fusion import load_fusion_config
    url_model = joblib.load(ROOT / "models" / "url_model.pkl")
    text_model = joblib.load(ROOT / "models" / "text_model.pkl")
    with (ROOT / "models" / "web_analyzer_config.json").open(encoding="utf-8") as handle:
        html_config = json.load(handle)
    return url_model, text_model, html_config, load_fusion_config()

def clear_artifact_cache() -> None:
    """Clear cached artifacts, useful after deliberately replacing model files."""
    _load_artifacts.cache_clear()

POLICY_THRESHOLDS = {
    "Balanced": (0.35, 0.65),
    "Strict SOC": (0.25, 0.50),
    "Lenient": (0.45, 0.75),
}

def _policy_label(score: float, policy_mode: str) -> str:
    legitimate_upper, suspicious_upper = POLICY_THRESHOLDS[policy_mode]
    if score < legitimate_upper:
        return "Legitimate"
    if score < suspicious_upper:
        return "Suspicious"
    return "Phishing"

def _highlighted_url_tokens(url: str) -> list[dict]:
    from src.url_analyzer import explain_url_features, extract_url_features
    features = extract_url_features(url)
    tokens = []
    if features["has_ip"]:
        host = re.findall(r"(?:https?://)?(?:\[?[0-9a-f:.]+\]?)", url.lower())
        tokens.extend({"token": item, "kind": "IP", "severity": "high"} for item in host if item)
    lowered = url.lower()
    for token in ("login", "verify", "update", "secure", "account", "banking",
                  "confirm", "signin", "paypal", "support", "free"):
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered):
            tokens.append({"token": token, "kind": "suspicious-token", "severity": "high"})
    host = re.sub(r"^https?://", "", lowered).split("/", 1)[0]
    if "." in host:
        tld = host.rstrip(".").rsplit(".", 1)[-1]
        if features["high_risk_tld_flag"]:
            tokens.append({"token": "." + tld, "kind": "TLD", "severity": "high"})
    if features["brand_impersonation_score"] >= 0.72:
        tokens.append({"token": host, "kind": "brand-lookalike", "severity": "high"})
    return list({(item["token"], item["kind"]): item for item in tokens}.values())

def predict_multimodal(url: str = "", text: str = "", html: str = "", policy_mode: str = "Balanced") -> dict:
    """Analyze explicit inputs and automatically extract email URLs/HTML safely."""
    if policy_mode not in POLICY_THRESHOLDS:
        raise ValueError("policy_mode must be Balanced, Strict SOC, or Lenient.")
    from src.multimodal_fusion import MultimodalFusionEngine
    from src.url_analyzer import extract_url_feature_rows, explain_url_features
    from src.text_analyzer import analyze_text
    from src.webpage_analyzer import analyze_html
    from src.email_parser import extract_embedded_urls, parse_email

    supplied = {"url": url, "text": text, "html": html}
    for key, value in supplied.items():
        if not isinstance(value, str):
            raise ValueError(f"{key} input must be a string.")
    cleaned = {key: value.strip() for key, value in supplied.items()}
    if not any(cleaned.values()):
        raise ValueError("Provide at least one non-empty URL, text, or static HTML input.")

    url_model, text_model, html_config, fusion_config = _load_artifacts()
    scores = {"url": None, "text": None, "html": None, "header": None}
    confidences = {}
    breakdown_details = {}
    indicators = []

    # Treat RFC-like headers as a pasted email/EML. Ordinary text is retained
    # as message content and is still scanned for embedded URLs below.
    looks_like_email = bool(cleaned["text"] and re.search(
        r"(?im)^(?:from|to|subject|date|reply-to|return-path|mime-version):\s*", cleaned["text"][:20000]))
    email_info = parse_email(cleaned["text"]) if looks_like_email else None
    message_text = cleaned["text"]
    message_html = ""
    if email_info is not None:
        pieces = [f"Subject: {email_info['subject']}" if email_info["subject"] else "",
                  email_info["plain_text"]]
        message_text = "\n".join(piece for piece in pieces if piece).strip()
        message_html = email_info["html_body"]
        scores["header"] = float(email_info["header_risk_score"])
        confidences["header"] = float(fusion_config["confidence"].get("email_header_rule_based", 0.80))
        header_indicators = email_info["header_indicators"]
        indicators.extend(header_indicators)
        breakdown_details["header"] = {"indicators": header_indicators,
                                        "authentication_failures": email_info["authentication_failures"]}

    candidate_urls = []
    if cleaned["url"]:
        candidate_urls.append(cleaned["url"])
    candidate_urls.extend(extract_embedded_urls(cleaned["text"], cleaned["html"]))
    if email_info is not None:
        candidate_urls.extend(email_info["embedded_urls"])
    candidate_urls = list(dict.fromkeys(candidate_urls))
    if candidate_urls:
        url_features = extract_url_feature_rows(candidate_urls)
        url_probabilities = url_model.predict_proba(url_features)[:, 1]
        selected_index = int(url_probabilities.argmax())
        selected_url = candidate_urls[selected_index]
        probability = float(url_probabilities[selected_index])
        scores["url"] = probability
        confidences["url"] = min(1.0, abs(2.0 * probability - 1.0))
        url_indicators = explain_url_features(selected_url)
        indicators.extend(url_indicators)
        breakdown_details["url"] = {"indicators": url_indicators, "analyzed_url": selected_url,
                                     "candidate_url_count": len(candidate_urls)}

    if message_text:
        text_result = analyze_text(message_text, text_model)
        probability = float(text_result["probabilities"][1])
        scores["text"] = probability
        confidences["text"] = min(1.0, abs(2.0 * probability - 1.0))
        text_indicators = [f"Learned text signal: {item['term']}" for item in text_result["indicators"]]
        indicators.extend(text_indicators)
        breakdown_details["text"] = {"indicators": text_indicators}

    html_parts = [part for part in (cleaned["html"], message_html) if part]
    combined_html = "\n".join(html_parts)
    html_result = None
    if combined_html:
        page_url = cleaned["url"] or (candidate_urls[0] if candidate_urls else None)
        html_result = analyze_html(combined_html, page_url=page_url)
        scores["html"] = float(html_result["html_risk_score"])
        confidences["html"] = float(fusion_config["confidence"].get("html_rule_based", 0.65))
        indicators.extend(html_result["indicators"])
        breakdown_details["html"] = {"indicators": html_result["indicators"], "features": html_result["features"]}

    escalation = fusion_config["escalation"]
    severe_pair = bool(scores["url"] is not None and html_result and
        scores["url"] >= escalation["url_score_minimum"] and
        html_result["features"]["password_input_count"] > 0 and
        html_result["features"]["external_form_count"] > 0)
    if severe_pair:
        indicators.append("High-risk combination: phishing-like URL score with an external password form")

    fused = MultimodalFusionEngine(fusion_config).fuse(
        url_score=scores["url"], text_score=scores["text"], html_score=scores["html"],
        header_score=scores["header"],
        confidences=confidences, severe_pair=severe_pair)
    final_label = _policy_label(fused["risk_score"], policy_mode)
    for name, detail in fused["modality_breakdown"].items():
        detail["label"] = _policy_label(detail["score"], policy_mode)

    highlighted_tokens = []
    if cleaned["url"]:
        highlighted_tokens.extend(_highlighted_url_tokens(cleaned["url"]))
    if candidate_urls:
        for candidate_url in candidate_urls:
            if candidate_url != cleaned["url"]:
                highlighted_tokens.extend(_highlighted_url_tokens(candidate_url))
    if message_text:
        text_result = analyze_text(message_text, text_model)
        for item in text_result["indicators"]:
            term = item["term"].strip()
            if term:
                highlighted_tokens.append({"token": term, "kind": "phishing-trigger", "severity": "amber"})
    highlighted_tokens = list({(item["token"].lower(), item["kind"]): item
                               for item in highlighted_tokens}.values())

    extracted_links = list(html_result["extracted_links"]) if html_result else []
    if email_info is not None:
        extracted_links.extend(email_info["extracted_links"])
    extracted_links = list({(item["actual_href"], item["display_text"]): item
                            for item in extracted_links}.values())
    deceptive_links = [item for item in extracted_links if item["is_mismatch"]]
    if deceptive_links:
        indicators.append("[HTML][LINK] High-severity deceptive link discrepancy found")

    fingerprint_source = "\n".join(f"{key}:{cleaned[key]}" for key in ("url", "text", "html"))
    input_fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8", errors="replace")).hexdigest()
    return {
        "final_label": final_label, "risk_score": fused["risk_score"],
        "risk_percentage": round(100.0 * fused["risk_score"], 2),
        "policy_mode": policy_mode,
        "modalities_used": fused["modalities_used"],
        "modality_breakdown": {name: {**details, **fused["modality_breakdown"][name]}
                               for name, details in breakdown_details.items()},
        "normalized_weights": fused["normalized_weights"], "escalated": fused["escalated"],
        "indicators": list(dict.fromkeys(indicators)),
        "highlighted_tokens": highlighted_tokens,
        "extracted_links": extracted_links,
        "input_sha256": input_fingerprint,
        "email_metadata": ({key: email_info[key] for key in
                            ("subject", "from_domain", "reply_to_domain", "return_path_domain")}
                           if email_info is not None else None),
        "disclaimer": "This prediction is decision support based on available model and heuristic evidence, not definitive proof of phishing. Verify suspicious messages or sites through trusted channels.",
    }

def predict(value: str, modality: str) -> dict:
    """Backward-compatible single-input wrapper for one modality."""
    if modality not in {"url", "text", "html"}:
        raise ValueError("modality must be 'url', 'text', or 'html'.")
    return predict_multimodal(**{modality: value})
