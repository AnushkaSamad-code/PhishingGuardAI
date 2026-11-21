"""Phase 2 checks for static analyzers and saved baseline text model."""
from pathlib import Path
import joblib
from src.url_analyzer import extract_url_features, explain_url_features
from src.text_analyzer import normalize_text
from src.webpage_analyzer import analyze_html

ROOT = Path(__file__).resolve().parents[1]

def test_url_features_and_suspicious_indicators():
    url = "http://192.168.1.10/login/verify?id=123&user=x"
    features = extract_url_features(url)
    assert features["url_length"] == len(url)
    assert features["hostname_length"] == len("192.168.1.10")
    assert features["path_length"] == len("/login/verify")
    assert features["has_ip"] == 1
    assert features["is_https"] == 0
    assert features["digit_count"] > 0
    assert features["suspicious_token_count"] == 2
    indicators = explain_url_features(url)
    assert "Uses IP address instead of domain" in indicators
    assert "Contains suspicious keyword: verify" in indicators

def test_url_brand_punycode_and_tld_features():
    typo = extract_url_features("https://paypa1-security.xyz/login")
    punycode = extract_url_features("https://xn--pple-43d.example/path")
    assert typo["brand_impersonation_score"] >= 0.72
    assert typo["high_risk_tld_flag"] == 1
    assert punycode["punycode_flag"] == 1
    assert "Possible targeted-brand impersonation in registered domain" in explain_url_features(
        "https://paypa1-security.xyz/login")

def test_text_normalization_and_saved_prediction():
    assert normalize_text("<p>URGENT!!!</p>   Verify NOW?") == "urgent!!! verify now?"
    model_path = ROOT / "models" / "text_model.pkl"
    assert model_path.is_file(), "Run src/train_models.py before these model integration tests."
    model = joblib.load(model_path)
    prediction = model.predict(["Urgent: verify your account now!"])
    assert int(prediction[0]) in (0, 1)

def test_static_html_detects_fields_without_running_script():
    html = '''<html><body><script>window.__ran = true;</script>
      <form action="https://other.example/submit"><input type="password">
      <input type="hidden" value="x"></form><img onerror="alert(1)"></body></html>'''
    result = analyze_html(html, page_url="https://safe.example/")
    assert result["features"]["password_input_count"] == 1
    assert result["features"]["hidden_input_count"] == 1
    assert result["features"]["script_count"] == 1
    assert result["features"]["external_form_count"] == 1
    assert result["html_risk_score"] > 0
    assert "Password input field detected" in result["indicators"]
    # Static parsing finds the script element but never evaluates its JavaScript.
