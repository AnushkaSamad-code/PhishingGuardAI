# Methodology

## Dataset preparation

The baseline URL and email datasets were supplied as separate CSV files. Preprocessing normalizes the content column to `text` and the binary label to `label` (`0` = safe/legitimate, `1` = phishing/bad). Rows with null content or labels, whitespace-only content, and exact duplicate content/label pairs are removed. Each corpus is split independently and stratified into train, validation, and test partitions at 70%, 15%, and 15%, with random seed 42. Exact counts and class distributions are in `dataset_log.md`.

The URL and email rows are not paired. No synthetic training rows or cross-modal labels are created.

## URL feature engineering and baseline

`src/url_analyzer.py` derives 17 numeric lexical/structural values from each URL string without network access:

- Full string length, parsed hostname length, and parsed path length.
- Counts of `.`, `-`, `_`, `/`, `?`, `=`, `@`, and numeric digits.
- Subdomain estimate (`hostname labels - 2`, floored at zero), IP-literal flag, and HTTPS flag.
- Exact suspicious-token occurrence count for `login`, `verify`, `update`, `secure`, `account`, `banking`, `free`, `confirm`, `signin`, `paypal`, and `support`.
- Digit-to-character ratio and Shannon entropy of hostname characters.

Malformed host syntax is handled without discarding raw-string features. A `StandardScaler` and class-balanced logistic-regression model (`lbfgs`, seed 42) are fitted on the URL training partition. Validation and test rows are evaluated separately.

## Text feature engineering and baseline

Text is lowercased, whitespace is collapsed, and markup (when present) is converted to text with a static BeautifulSoup parser. Meaningful punctuation remains in the normalized string. The scikit-learn pipeline uses `TfidfVectorizer` with at most 15,000 features, word unigrams and bigrams (`ngram_range=(1, 2)`), English stop-word removal, and sublinear term frequency, followed by class-balanced logistic regression (`liblinear`, maximum 300 iterations, seed 42). The vectorizer and classifier are trained together on the training partition. Model scores are not formally calibrated probabilities.

## Static HTML feature extraction and rule score

There is no labeled raw-HTML corpus, so HTML is not trained as a classifier. BeautifulSoup with Python's built-in `html.parser` reads supplied markup without executing scripts or fetching external resources. Extracted counts include links, external/internal links and external-link ratio, forms, password inputs, hidden inputs, iframes, script elements, external form actions, and inline event attributes.

The HTML score is an additive heuristic, capped to `[0, 1]`, using rule weights: password input 0.25, hidden input 0.05, form 0.10, external form action 0.30, iframe 0.10, inline event handlers up to 0.10 (scaled by two attributes), and external-link ratio up to 0.10. It is a review signal, not a learned or empirically validated probability.

## Late fusion and decisions

Base weights are Text 0.45, URL 0.35, and HTML 0.20. With one modality, its score is passed through unchanged. With multiple modalities, each base weight is multiplied by confidence and normalized over available inputs. URL/text confidence is `abs(2 * phishing_score - 1)`, a distance-from-0.5 measure rather than calibrated confidence; static HTML uses a fixed heuristic confidence of 0.65 because there is no labeled HTML evaluation set. If all confidence values are zero, base weights are normalized instead. These settings are design defaults, not tuned on test data.

The user-facing thresholds are Legitimate `< 0.35`, Suspicious `0.35` to `< 0.65`, and Phishing `>= 0.65`. A severe-evidence escalation raises the score to at least 0.85 only when URL score is at least 0.90 and supplied HTML has both a password input and an external form action. This is a transparent review rule, not calibrated risk.

## Experiments and limitations

E1 evaluates the URL model on `url_test.csv`; E2 evaluates the text model on `text_test.csv`. E3 checks the HTML rules against four authored deterministic fixtures and reports fixture behavior only. E4 pairs actual test rows by matching class and source row order solely to explore late-fusion arithmetic. Since there is no shared sample identity, E4 cannot establish paired multimodal performance. E5 summarizes false positives and false negatives from the separate real test sets. Exact results and confusion matrices are reported in `experiment_results.md` and `models/experiment_metrics.json`.
