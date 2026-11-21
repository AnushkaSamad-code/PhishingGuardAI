"""Tests for late fusion rules and the safe unified prediction entry point."""
import math
import pytest
from src.multimodal_fusion import MultimodalFusionEngine, load_fusion_config
from src.prediction import predict_multimodal

@pytest.fixture(scope="module")
def engine():
    return MultimodalFusionEngine(load_fusion_config())

@pytest.mark.parametrize("kwargs,expected", [
    ({"url_score": 0.21}, "Legitimate"),
    ({"text_score": 0.52}, "Suspicious"),
    ({"html_score": 0.86}, "Phishing"),
])
def test_single_modality_score_passes_through(engine, kwargs, expected):
    result = engine.fuse(**kwargs)
    assert result["final_label"] == expected
    assert result["risk_score"] == next(iter(kwargs.values()))
    assert len(result["modalities_used"]) == 1

@pytest.mark.parametrize("scores,expected", [
    ((0.08, 0.12, 0.10), "Legitimate"),
    ((0.20, 0.50, 0.40), "Suspicious"),
    ((0.90, 0.82, 0.88), "Phishing"),
])
def test_three_modality_fusion_decision_classes(engine, scores, expected):
    result = engine.fuse(url_score=scores[0], text_score=scores[1], html_score=scores[2])
    assert result["final_label"] == expected
    assert math.isclose(sum(result["normalized_weights"].values()), 1.0)
    assert set(result["modalities_used"]) == {"url", "text", "html"}

def test_confidence_and_availability_change_contribution(engine):
    result = engine.fuse(url_score=1.0, text_score=0.0,
                         confidences={"url": 1.0, "text": 0.0})
    assert result["risk_score"] == 1.0
    unavailable = engine.fuse(url_score=1.0, text_score=0.0,
                              availability={"url": False, "text": True})
    assert unavailable["risk_score"] == 0.0
    assert unavailable["modalities_used"] == ["text"]

def test_escalation_and_invalid_scores(engine):
    result = engine.fuse(url_score=0.95, html_score=0.1, severe_pair=True)
    assert result["escalated"] is True
    assert result["risk_score"] >= 0.85
    no_url_context = engine.fuse(text_score=0.1, html_score=0.1, severe_pair=True)
    assert no_url_context["escalated"] is False
    with pytest.raises(ValueError, match="between 0 and 1"):
        engine.fuse(url_score=1.2)

@pytest.mark.parametrize("inputs,expected_modality", [
    ({"url": "https://example.org/about"}, "url"),
    ({"text": "A routine project update for this afternoon."}, "text"),
    ({"html": "<html><body><h1>Page</h1></body></html>"}, "html"),
])
def test_unified_prediction_single_modality(inputs, expected_modality):
    result = predict_multimodal(**inputs)
    assert result["modalities_used"] == [expected_modality]
    assert result["final_label"] in {"Legitimate", "Suspicious", "Phishing"}
    assert 0.0 <= result["risk_score"] <= 1.0
    assert 0.0 <= result["risk_percentage"] <= 100.0
    assert result["disclaimer"]

def test_unified_prediction_all_modalities_and_empty_input():
    result = predict_multimodal(
        url="http://192.0.2.10/verify/account",
        text="Urgent: verify your account now.",
        html='<form action="https://outside.example/login"><input type="password"></form>')
    assert set(result["modalities_used"]) == {"url", "text", "html"}
    assert set(result["modality_breakdown"]) == {"url", "text", "html"}
    assert isinstance(result["indicators"], list)
    with pytest.raises(ValueError, match="at least one non-empty"):
        predict_multimodal("  ", "", "\n")

def test_embedded_urls_are_analyzed_and_raw_email_adds_header_modality():
    message = "Please verify your account at https://paypa1-security.example/login"
    result = predict_multimodal(text=message)
    assert "url" in result["modalities_used"]
    assert result["modality_breakdown"]["url"]["analyzed_url"].startswith("https://paypa1")

    raw_email = """From: Billing <billing@paypal.example>
Reply-To: collect@outside.example
Subject: Verify now
Authentication-Results: mx.example; dmarc=fail

Please verify at https://paypa1.example/login
"""
    parsed_result = predict_multimodal(text=raw_email)
    assert {"url", "text", "header"}.issubset(parsed_result["modalities_used"])
    assert parsed_result["email_metadata"]["reply_to_domain"] == "outside.example"
    assert any(item.startswith("[HEADER]") for item in parsed_result["indicators"])
