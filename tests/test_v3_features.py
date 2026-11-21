"""Regression coverage for PhishGuard AI V3 features."""
from html import escape

import pandas as pd

from src.batch_scanner import scan_csv_batch
from src.email_parser import parse_email
from src.prediction import _policy_label
from src.webpage_analyzer import analyze_html, extract_link_audits


def test_deceptive_anchor_text_href_mismatch_is_detected():
    html = '<a href="https://evil.example/login">https://paypal.com/verify</a>'
    audits = extract_link_audits(html)
    assert len(audits) == 1
    assert audits[0]["is_mismatch"] is True
    assert "paypal" in audits[0]["risk_note"].lower() or "different" in audits[0]["risk_note"].lower()

    result = analyze_html(html)
    assert result["extracted_links"][0]["is_mismatch"] is True
    assert any("[LINK]" in indicator for indicator in result["indicators"])


def test_eml_parser_includes_deceptive_link_audit():
    raw = """From: Sender <sender@paypal.example>
Subject: Verify
MIME-Version: 1.0
Content-Type: text/html

<a href="https://collect.example/login">https://paypal.com/verify</a>
"""
    parsed = parse_email(raw)
    assert parsed["extracted_links"]
    assert parsed["extracted_links"][0]["is_mismatch"] is True


def test_policy_thresholds_move_classification_boundaries():
    strict = _policy_label
    assert strict(0.24, "Strict SOC") == "Legitimate"
    assert strict(0.40, "Strict SOC") == "Suspicious"
    assert strict(0.50, "Strict SOC") == "Phishing"
    assert strict(0.40, "Lenient") == "Legitimate"
    assert strict(0.70, "Lenient") == "Suspicious"
    assert strict(0.75, "Lenient") == "Phishing"


def test_malicious_script_text_is_escaped_for_html_rendering():
    malicious = '<script>alert("xss")</script>'
    escaped = escape(malicious, quote=False)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
    assert "&lt;/script&gt;" in escaped


def test_csv_batch_scanner_auto_detects_columns_and_is_capped():
    df = pd.DataFrame({
        "Text": ["Routine project update", "Urgent verify your account now"],
    })
    result = scan_csv_batch(df, policy_mode="Balanced", max_rows=500)
    assert list(result.columns) == [
        "input_preview", "final_label", "risk_score", "modalities_used", "top_indicator",
    ]
    assert len(result) == 2
    assert set(result["final_label"]) <= {"Legitimate", "Suspicious", "Phishing"}

    large = pd.DataFrame({"url": [f"https://example{i}.org" for i in range(550)]})
    capped = scan_csv_batch(large, max_rows=500)
    assert len(capped) == 500
