# Phase 2 Baseline Model Results

Models were fitted on training splits only. Validation and test metrics are reported separately.
Positive class is phishing (`1`). Confusion matrix order is `[[TN, FP], [FN, TP]]`.

## Url model

| Split | Accuracy | Precision | Recall | F1-score | FPR | Confusion matrix |
|---|---:|---:|---:|---:|---:|---|
| validation | 0.784500 | 0.517435 | 0.649111 | 0.575841 | 0.176112 | `[[48555, 10379], [6016, 11129]]` |
| test | 0.779111 | 0.507864 | 0.638474 | 0.565729 | 0.179978 | `[[48328, 10607], [6198, 10946]]` |

## Text model

| Split | Accuracy | Precision | Recall | F1-score | FPR | Confusion matrix |
|---|---:|---:|---:|---:|---:|---|
| validation | 0.988060 | 0.985918 | 0.991287 | 0.988595 | 0.015463 | `[[5794, 91], [56, 6371]]` |
| test | 0.985949 | 0.983756 | 0.989420 | 0.986580 | 0.017842 | `[[5780, 105], [68, 6359]]` |

## Model notes

- URL model: standardized lexical and structural URL feature vector with logistic regression.
- Text model: 15,000-feature maximum word/bigram TF-IDF with balanced logistic regression.
- The HTML analyzer remains a static rule-based structural scorer; it is not trained because no labeled HTML dataset was supplied.
- Metrics describe held-out rows from the provided processed CSVs and are not performance guarantees.
