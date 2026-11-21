"""Text normalization, TF-IDF baseline construction, and model explanations."""
import re
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

def normalize_text(text: str) -> str:
    """Lowercase and remove markup while preserving punctuation and urgency cues."""
    if text is None:
        return ""
    # Parse markup only; scripts are treated as text nodes and never executed.
    source = str(text)
    plain = BeautifulSoup(source, "html.parser").get_text(" ", strip=True) if "<" in source and ">" in source else source
    plain = re.sub(r"\s+", " ", plain).strip().lower()
    return plain

def build_text_pipeline(max_features: int = 15000) -> Pipeline:
    """Create a fast sparse TF-IDF + logistic regression classification pipeline."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(max_features=max_features, ngram_range=(1, 2),
                                  stop_words="english", sublinear_tf=True,
                                  preprocessor=normalize_text, dtype="float32")),
        ("classifier", LogisticRegression(solver="liblinear", max_iter=300,
                                           class_weight="balanced", random_state=42)),
    ])

def explain_text_features(text: str, model_pipeline: Pipeline, top_n: int = 8) -> list[dict]:
    """Return high-weight learned terms present in text (supporting evidence only)."""
    vectorizer = model_pipeline.named_steps["tfidf"]
    classifier = model_pipeline.named_steps["classifier"]
    if not hasattr(classifier, "coef_"):
        raise ValueError("The supplied pipeline must be fitted LogisticRegression.")
    vector = vectorizer.transform([text])
    names = vectorizer.get_feature_names_out()
    coefficients = classifier.coef_[0]
    present = vector.indices
    # Positive coefficient points toward class 1; only return matched phishing-indicating terms.
    scored = sorted(((names[i], float(coefficients[i] * vector[0, i])) for i in present if coefficients[i] > 0),
                    key=lambda item: item[1], reverse=True)
    return [{"term": term, "contribution": score} for term, score in scored[:top_n]]

def analyze_text(text: str, model_pipeline: Pipeline | None = None) -> dict:
    """Normalize text and optionally return a baseline prediction and explanations."""
    normalized = normalize_text(text)
    result = {"normalized_text": normalized}
    if model_pipeline is not None:
        result["prediction"] = int(model_pipeline.predict([normalized])[0])
        result["probabilities"] = model_pipeline.predict_proba([normalized])[0].tolist()
        result["indicators"] = explain_text_features(normalized, model_pipeline)
    return result
