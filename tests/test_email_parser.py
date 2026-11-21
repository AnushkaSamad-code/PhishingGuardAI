"""Tests for safe raw-email parsing and static URL feature indicators."""
from src.email_parser import parse_email
from src.url_analyzer import explain_url_features, extract_url_features


def test_eml_parser_extracts_text_html_and_urls_without_visiting_them():
    raw = """From: Sender <sender@example.test>
Subject: Review this
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="test-boundary"

--test-boundary
Content-Type: text/plain; charset="utf-8"

Please review https://paypa1.example/login.
--test-boundary
Content-Type: text/html; charset="utf-8"

<html><body><a href="https://other.example/verify">Review</a></body></html>
--test-boundary--
"""
    result = parse_email(raw)
    assert "Please review" in result["plain_text"]
    assert "<html>" in result["html_body"]
    assert result["embedded_urls"] == [
        "https://paypa1.example/login", "https://other.example/verify"]


def test_header_domain_mismatch_and_auth_failures_are_reported():
    raw = """From: Billing <billing@paypal.example>
Reply-To: collect@outside.example
Return-Path: <bounce@outside.example>
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
Subject: Verify account

Please review the attached notice.
"""
    result = parse_email(raw)
    assert result["reply_to_domain"] == "outside.example"
    assert result["return_path_domain"] == "outside.example"
    assert set(result["authentication_failures"]) == {"spf", "dkim", "dmarc"}
    assert result["header_risk_score"] == 1.0
    assert any("From domain" in item and "Reply-To" in item
               for item in result["header_indicators"])


def test_typosquatting_and_punycode_flags_are_exposed():
    typo_url = "https://paypa1-account.example/login"
    punycode_url = "https://xn--pple-43d.example/"
    assert extract_url_features(typo_url)["brand_impersonation_score"] >= 0.72
    assert extract_url_features(punycode_url)["punycode_flag"] == 1
    assert "Possible targeted-brand impersonation in registered domain" in explain_url_features(typo_url)
    assert "Contains punycode hostname label" in explain_url_features(punycode_url)

