"""End-to-end checks for the Streamlit interface and real prediction backend."""
from pathlib import Path
from streamlit.testing.v1 import AppTest
from src.prediction import predict_multimodal

ROOT = Path(__file__).resolve().parents[1]

def test_app_compiles_renders_and_has_required_assets():
    app_path = ROOT / "app.py"
    source = app_path.read_text(encoding="utf-8")
    compile(source, str(app_path), "exec")
    for relative in (
        "models/url_model.pkl", "models/text_model.pkl", "models/web_analyzer_config.json",
        "models/fusion_config.json", "models/experiment_metrics.json",
        "documentation/dataset_log.md", "documentation/charts/model_comparison.png",
        "documentation/charts/confusion_matrices.png",
    ):
        assert (ROOT / relative).is_file(), f"Missing app asset: {relative}"

    app = AppTest.from_file(str(app_path)).run(timeout=45)
    assert not app.exception, [exception.message for exception in app.exception]
    assert len(app.radio) == 0, "Product scanner should not expose academic navigation tabs."

def test_backend_prediction_returns_displayable_result():
    result = predict_multimodal(
        url="https://www.example.org/about",
        text="The project meeting is scheduled for Thursday. Please review the agenda.",
    )
    assert result["final_label"] in {"Legitimate", "Suspicious", "Phishing"}
    assert 0.0 <= result["risk_score"] <= 1.0
    assert set(result["modalities_used"]) == {"url", "text"}
    assert set(result["modality_breakdown"]) == {"url", "text"}

def test_empty_scanner_form_displays_validation_warning():
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=45)
    app.button(key="scan_url").click().run(timeout=45)
    assert any("Enter a URL, message, email, or static HTML" in item.value for item in app.warning)

def test_single_screen_scanner_has_presets_and_no_academic_navigation():
    app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=45)
    assert not app.exception, [exception.message for exception in app.exception]
    assert len(app.radio) == 0
    button_labels = {button.label for button in app.button}
    assert {"Safe Corporate Email", "Typosquatted URL", "Spoofed .eml Phishing Attack", "Reset"}.issubset(button_labels)
    input_labels = {item.label for item in app.text_input}
    assert "URL to inspect" in input_labels
