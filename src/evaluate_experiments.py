"""Run E1–E5 using held-out data and explicit, non-paired benchmark protocols."""
from __future__ import annotations
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

# Avoid loky's Windows physical-core probe, which depends on legacy `wmic`.
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(min(4, os.cpu_count() or 1)))

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from src.url_analyzer import extract_url_feature_rows, extract_url_features
from src.webpage_analyzer import analyze_html
from src.multimodal_fusion import MultimodalFusionEngine, load_fusion_config
from utils.metrics import classification_metrics

DATA = ROOT / "data" / "processed"
MODELS = ROOT / "models"
CHARTS = ROOT / "documentation" / "charts"

def _read_test(modality: str):
    frame = pd.read_csv(DATA / f"{modality}_test.csv")
    return frame["text"].fillna("").astype(str), frame["label"].astype(int).to_numpy()

def _risk_from_probabilities(probabilities: np.ndarray) -> np.ndarray:
    return probabilities[:, 1].astype(float)

def _fuse_arrays(url_scores, text_scores, url_conf, text_conf, config):
    """Vectorized equivalent of confidence-weighted URL/text fusion."""
    url_weight = config["weights"]["url"] * url_conf
    text_weight = config["weights"]["text"] * text_conf
    denominator = url_weight + text_weight
    all_uncertain = denominator == 0
    url_weight = np.where(all_uncertain, config["weights"]["url"], url_weight)
    text_weight = np.where(all_uncertain, config["weights"]["text"], text_weight)
    denominator = url_weight + text_weight
    return (url_scores * url_weight + text_scores * text_weight) / denominator

def _metrics_with_labels(y_true, scores, engine):
    # For a binary comparison only, the midpoint 0.5 separates class 0/1.
    # This is distinct from the user-facing three-way thresholds in the engine.
    labels = (np.asarray(scores) >= 0.5).astype(int)
    return classification_metrics(y_true, labels)

def _html_fixtures():
    """Small authored structural sanity fixtures; not samples from a labeled corpus."""
    return [
        {"name": "benign_static_article", "expected": "benign",
         "page_url": "https://news.example/article",
         "html": '<html><body><h1>Community news</h1><a href="/about">About</a><p>Local story.</p></body></html>'},
        {"name": "benign_plain_page", "expected": "benign",
         "page_url": "https://shop.example/",
         "html": '<html><body><h1>Welcome</h1><a href="/catalog">Catalog</a></body></html>'},
        {"name": "credential_harvesting_template", "expected": "phishing_fixture",
         "page_url": "https://brand-login.example/",
         "html": '<html><body><form action="https://collect.example/submit"><input type="password"><input type="hidden" value="x"></form><iframe src="https://other.example/frame"></iframe><img onerror="noop()"></body></html>'},
        {"name": "external_credential_form", "expected": "phishing_fixture",
         "page_url": "https://account-check.example/",
         "html": '<html><body><form action="https://outside.example/auth"><input type="email"><input type="password"></form></body></html>'},
    ]

def _top_error_samples(values, truth, predictions, error_kind, limit=4):
    mask = (truth == 0) & (predictions == 1) if error_kind == "FP" else (truth == 1) & (predictions == 0)
    indices = np.flatnonzero(mask)
    return indices[:limit]

def _safe_excerpt(value: str, limit: int = 240) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit] + ("…" if len(value) > limit else "")

def _error_analysis(modality, values, truth, predicted, scores):
    """Summarize measured error traits and provide real, short held-out examples."""
    result = {}
    for kind in ("FP", "FN"):
        idx = np.flatnonzero((truth == 0) & (predicted == 1) if kind == "FP" else (truth == 1) & (predicted == 0))
        examples = [{"row_index_in_test_split": int(i), "true_label": int(truth[i]),
                     "predicted_label": int(predicted[i]), "phishing_score": float(scores[i]),
                     "excerpt": _safe_excerpt(values.iloc[i])} for i in idx[:4]]
        if modality == "url":
            no_tokens = sum(extract_url_features(values.iloc[i])["suspicious_token_count"] == 0 for i in idx)
            median_length = float(np.median([len(values.iloc[i]) for i in idx])) if len(idx) else 0.0
            result[kind] = {"count": int(len(idx)), "median_url_length": median_length,
                            "errors_without_explicit_suspicious_token": int(no_tokens),
                            "errors_without_explicit_suspicious_token_fraction": float(no_tokens / len(idx)) if len(idx) else 0.0,
                            "examples": examples}
        else:
            lengths = [len(values.iloc[i]) for i in idx]
            token_counter = Counter(token for i in idx for token in re.findall(r"[a-z]{3,}", values.iloc[i].lower()))
            result[kind] = {"count": int(len(idx)), "median_character_length": float(np.median(lengths)) if lengths else 0.0,
                            "most_common_tokens_in_errors": token_counter.most_common(8), "examples": examples}
    return result

def _save_charts(url_metrics, text_metrics):
    CHARTS.mkdir(parents=True, exist_ok=True)
    metric_names = ["accuracy", "precision", "recall", "f1"]
    x = np.arange(len(metric_names))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8, 4.8))
    for offset, (name, metrics) in enumerate((("URL", url_metrics), ("Text", text_metrics))):
        bars = ax.bar(x + (offset - 0.5) * width, [metrics[key] for key in metric_names], width, label=name)
        ax.bar_label(bars, fmt="%.3f", padding=2, fontsize=8)
    ax.set_xticks(x, [name.title() for name in metric_names])
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("Held-out test score")
    ax.set_title("Baseline model comparison (independent test sets)")
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(CHARTS / "model_comparison.png", dpi=170)
    plt.close(fig)

def _save_confusion_chart(url_metrics, text_metrics):
    fig, axes = plt.subplots(1, 2, figsize=(8.5, 4))
    for ax, (name, metrics) in zip(axes, (("URL", url_metrics), ("Text", text_metrics))):
        matrix = np.array(metrics["confusion_matrix"])
        ax.imshow(matrix, cmap="Blues")
        ax.set_title(f"{name} test confusion matrix")
        ax.set_xlabel("Predicted label")
        ax.set_ylabel("True label")
        ax.set_xticks([0, 1], ["Safe", "Phishing"])
        ax.set_yticks([0, 1], ["Safe", "Phishing"])
        for (row, col), value in np.ndenumerate(matrix):
            ax.text(col, row, f"{value:,}", ha="center", va="center",
                    color="white" if value > matrix.max() * 0.55 else "black")
    fig.tight_layout()
    fig.savefig(CHARTS / "confusion_matrices.png", dpi=170)
    plt.close(fig)

def run_experiments() -> dict:
    """Execute held-out modality evaluations, fixture checks, and controlled E4 pairings."""
    url_model = joblib.load(MODELS / "url_model.pkl")
    text_model = joblib.load(MODELS / "text_model.pkl")
    engine = MultimodalFusionEngine(load_fusion_config())

    # E1: actual URL held-out test rows.
    urls, y_url = _read_test("url")
    p_url = _risk_from_probabilities(url_model.predict_proba(extract_url_feature_rows(urls)))
    pred_url = (p_url >= 0.5).astype(int)
    e1 = classification_metrics(y_url, pred_url)

    # E2: actual email/text held-out test rows.
    texts, y_text = _read_test("text")
    p_text = _risk_from_probabilities(text_model.predict_proba(texts))
    pred_text = (p_text >= 0.5).astype(int)
    e2 = classification_metrics(y_text, pred_text)

    # E3: authored deterministic fixtures are behavior checks, not population metrics.
    fixtures = []
    for fixture in _html_fixtures():
        result = analyze_html(fixture["html"], fixture["page_url"])
        passed = (result["html_risk_score"] < 0.35 if fixture["expected"] == "benign"
                  else result["features"]["password_input_count"] > 0 and result["features"]["external_form_count"] > 0
                  and result["html_risk_score"] >= 0.65)
        fixtures.append({"name": fixture["name"], "expected_structural_behavior": fixture["expected"],
                         "risk_score": result["html_risk_score"], "indicators": result["indicators"], "fixture_check_passed": bool(passed)})

    # E4: controlled combinations of real held-out rows. Since datasets are
    # unpaired, same-label rows are aligned only by label and source row order.
    # These are exploratory pair scenarios, not naturally paired multimodal accuracy.
    url_conf = np.abs(2 * p_url - 1)
    text_conf = np.abs(2 * p_text - 1)
    index_groups = {}
    for modality_labels, modality in ((y_url, "url"), (y_text, "text")):
        index_groups[modality] = {label: np.flatnonzero(modality_labels == label) for label in (0, 1)}

    concordant_scores, concordant_truth = [], []
    component_url_preds, component_text_preds = [], []
    concordant_counts = {}
    for label in (0, 1):
        count = min(len(index_groups["url"][label]), len(index_groups["text"][label]))
        ui, ti = index_groups["url"][label][:count], index_groups["text"][label][:count]
        fused_scores = _fuse_arrays(p_url[ui], p_text[ti], url_conf[ui], text_conf[ti], engine.config)
        concordant_scores.extend(fused_scores.tolist())
        concordant_truth.extend([label] * count)
        component_url_preds.extend(pred_url[ui].tolist())
        component_text_preds.extend(pred_text[ti].tolist())
        concordant_counts[str(label)] = int(count)
    concordant_scores = np.asarray(concordant_scores)
    concordant_truth = np.asarray(concordant_truth)
    concordant_url_only = classification_metrics(concordant_truth, np.asarray(component_url_preds))
    concordant_text_only = classification_metrics(concordant_truth, np.asarray(component_text_preds))
    concordant_fusion = _metrics_with_labels(concordant_truth, concordant_scores, engine)

    cross_results = {}
    for url_label, text_label, name in ((0, 1, "url_safe_text_phishing"), (1, 0, "url_phishing_text_safe")):
        count = min(len(index_groups["url"][url_label]), len(index_groups["text"][text_label]))
        ui, ti = index_groups["url"][url_label][:count], index_groups["text"][text_label][:count]
        scores = _fuse_arrays(p_url[ui], p_text[ti], url_conf[ui], text_conf[ti], engine.config)
        labels = [engine.label_for(float(score)) for score in scores]
        cross_results[name] = {"pair_count": int(count), "mean_fused_score": float(np.mean(scores)),
                               "decision_counts": {key: labels.count(key) for key in ("Legitimate", "Suspicious", "Phishing")},
                               "ground_truth": "conflicting source labels; no single pair-level ground truth is assigned"}

    # E5: error analysis computed from each true test label and baseline decision.
    errors = {"url": _error_analysis("url", urls, y_url, pred_url, p_url),
              "text": _error_analysis("text", texts, y_text, pred_text, p_text)}

    _save_charts(e1, e2)
    _save_confusion_chart(e1, e2)
    results = {
        "protocol": {"e1_e2": "Metrics from the provided held-out URL and text test splits.",
                     "e3": "Four deterministic authored HTML fixtures; fixture checks only, not a labeled dataset or population metrics.",
                     "e4": "Exploratory controlled pairing of real held-out URL and text rows by class and source row order. No rows were added to training. The test datasets have no linkage, so this does not estimate naturally paired multimodal performance. Cross-class pairs have conflicting labels and are descriptive only.",
                     "e4_html": "No held-out paired HTML examples exist; no three-modality accuracy is claimed.",
                     "binary_decision": "For E1/E2 and concordant E4 summaries, scores >= 0.5 map to phishing class 1; lower scores map to 0. This binary midpoint is separate from the user-facing 0.35/0.65 three-way decisions."},
        "E1_url_test": e1, "E2_text_test": e2, "E3_html_fixtures": fixtures,
        "E4_controlled_unpaired_pairs": {"same_label_pair_counts": concordant_counts,
            "url_only_on_selected_rows": concordant_url_only, "text_only_on_selected_rows": concordant_text_only,
            "late_fusion_on_selected_rows": concordant_fusion, "cross_class_scenarios": cross_results},
        "E5_error_analysis": errors,
    }
    (MODELS / "experiment_metrics.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    _write_report(results)
    print(json.dumps({"E1_url_test": e1, "E2_text_test": e2,
                      "E3_fixture_checks_passed": sum(item["fixture_check_passed"] for item in fixtures),
                      "E3_fixture_checks_total": len(fixtures),
                      "E4_controlled_unpaired_pairs": results["E4_controlled_unpaired_pairs"],
                      "E5_error_counts": {modality: {kind: info["count"] for kind, info in kinds.items()}
                                          for modality, kinds in errors.items()}}, indent=2))
    return results

def _write_report(results: dict) -> None:
    """Write the scientific protocol, exact metrics, fixture outcomes, and real errors."""
    lines = ["# Phase 3 Research Experiments (E1–E5)", "",
        "All E1/E2 metrics and errors below are recomputed by `python src/evaluate_experiments.py` on the held-out processed test splits.",
        "URL and email datasets are unpaired. E4 pairings are controlled exploratory combinations of actual test rows; they are not naturally paired examples, and no rows were used for training.",
        "The fusion weights are specified design defaults, not tuned against these test results. The HTML fixtures are authored deterministic checks, not representative labeled observations.", ""]
    for title, key in (("E1 — URL-only test evaluation", "E1_url_test"), ("E2 — Text-only test evaluation", "E2_text_test")):
        m = results[key]
        lines += [f"## {title}", "", "| Accuracy | Precision | Recall | F1-score | False positive rate | Confusion matrix `[[TN,FP],[FN,TP]]` |",
                  "|---:|---:|---:|---:|---:|---|",
                  f"| {m['accuracy']:.6f} | {m['precision']:.6f} | {m['recall']:.6f} | {m['f1']:.6f} | {m['false_positive_rate']:.6f} | `{m['confusion_matrix']}` |", ""]
    lines += ["## E3 — Static HTML fixture checks", "", "These four authored fixtures only check structural behavior. Their pass rate is not a classifier accuracy estimate.", "",
              "| Fixture | Expected behavior | Risk score | Check | Indicators |", "|---|---|---:|---|---|"]
    for fixture in results["E3_html_fixtures"]:
        lines.append(f"| {fixture['name']} | {fixture['expected_structural_behavior']} | {fixture['risk_score']:.4f} | {'PASS' if fixture['fixture_check_passed'] else 'FAIL'} | {', '.join(fixture['indicators']) or 'None'} |")
    e4 = results["E4_controlled_unpaired_pairs"]
    lines += ["", "## E4 — Controlled URL/text fusion comparisons", "",
        "Protocol: pair the first held-out rows of matching ground-truth class in each independently shuffled test file, stopping at the smaller class count. Pairing by class and row order creates a controlled score-combination benchmark only; there is no sample-level relationship between paired URLs and emails. No training rows were fabricated or added. The reported values must not be interpreted as performance on naturally paired multimodal data.", "",
        f"Concordant pair counts: class 0 = {e4['same_label_pair_counts']['0']:,}; class 1 = {e4['same_label_pair_counts']['1']:,}.", "",
        "| Method on selected concordant pairs | Accuracy | Precision | Recall | F1-score | FPR |",
        "|---|---:|---:|---:|---:|---:|"]
    for name, key in (("URL-only", "url_only_on_selected_rows"), ("Text-only", "text_only_on_selected_rows"), ("Late fusion", "late_fusion_on_selected_rows")):
        m = e4[key]
        lines.append(f"| {name} | {m['accuracy']:.6f} | {m['precision']:.6f} | {m['recall']:.6f} | {m['f1']:.6f} | {m['false_positive_rate']:.6f} |")
    lines += ["", "### Cross-class evidence conflicts", "",
        "These cases have opposing source labels, so they are summarized without assigning a pair-level true label or calculating accuracy.", ""]
    for name, info in e4["cross_class_scenarios"].items():
        lines.append(f"- `{name}`: {info['pair_count']:,} pairs; mean fused score {info['mean_fused_score']:.6f}; decisions `{info['decision_counts']}`.")
    lines += ["", "No E4 accuracy is reported for all three modalities because the project has no held-out paired URL/text/HTML examples.", "",
        "## E5 — Held-out error analysis", "",
        "Counts below are computed from actual URL/text test-set predictions. Short examples are excerpts from the provided test CSVs; row indices refer to their respective test files.", ""]
    for modality in ("url", "text"):
        lines += [f"### {modality.title()} model", ""]
        for kind in ("FP", "FN"):
            info = results["E5_error_analysis"][modality][kind]
            lines.append(f"- **{kind}: {info['count']:,} errors.**")
            if modality == "url":
                lines.append(f"  - Median error URL length: {info['median_url_length']:.1f} characters; {info['errors_without_explicit_suspicious_token']:,} ({info['errors_without_explicit_suspicious_token_fraction']:.1%}) had no explicit token from the extractor's suspicious-token list.")
            else:
                lines.append(f"  - Median error text length: {info['median_character_length']:.1f} characters; common error tokens: `{info['most_common_tokens_in_errors']}`.")
            for example in info["examples"]:
                excerpt = json.dumps(example["excerpt"], ensure_ascii=False)
                lines.append(f"  - Test row {example['row_index_in_test_split']}: true={example['true_label']}, predicted={example['predicted_label']}, score={example['phishing_score']:.5f}; excerpt {excerpt}")
        lines.append("")
    lines += ["## Interpretation limits", "",
        "Text and URL results are from distinct source populations and are not directly comparable as a modality ablation. The controlled E4 pairing explores the configured aggregation rule, but cannot establish that fusion reduces real-world blind spots without a genuinely paired test corpus. E3 assesses implemented HTML rules on explicit fixtures only. All model outputs are decision support, not proof.", ""]
    (ROOT / "documentation" / "experiment_results.md").write_text("\n".join(lines), encoding="utf-8")

if __name__ == "__main__":
    run_experiments()
