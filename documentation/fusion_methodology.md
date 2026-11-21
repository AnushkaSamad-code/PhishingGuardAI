# Phase 3: Late Fusion Method

## Why late fusion

The URL and email corpora are independent and contain no shared sample IDs. There is no labeled paired HTML corpus. Therefore, the project does not train a joint model or claim naturally paired multimodal accuracy. Each modality produces its own phishing risk score; late fusion is applied only when inputs are jointly supplied at inference time.

## Score combination

Configured base weights are text 0.45, URL 0.35, and HTML 0.20. If only one modality is available, its score passes through unchanged. With multiple modalities, each base weight is multiplied by the modality confidence and then normalized across present modalities. URL/text confidence is `abs(2 × phishing_score − 1)`, a measure of distance from the model's 0.5 boundary (not a separately calibrated probability). The rule-based HTML analyzer uses a fixed confidence of 0.65 because no labeled HTML set is available. If all confidence values are zero, the fusion falls back to normalized base weights.

These starting weights and confidence values are design choices, not learned or empirically tuned parameters. Scores produced by the baseline logistic models are used as risk estimates; formal probability calibration has not been performed.

## Decisions and escalation

- Legitimate: risk < 0.35
- Suspicious: 0.35 ≤ risk < 0.65
- Phishing: risk ≥ 0.65

When a URL score is at least 0.90 and the supplied HTML contains both a password field and a form whose action points to a different hostname, the fused score is raised to at least 0.85. This deterministic high-risk combination is surfaced as an indicator. It is a conservative rule for review, not a calibrated risk estimate.

All URL processing is local string parsing. HTML is parsed as markup only; scripts are not executed and external resources are not fetched.
