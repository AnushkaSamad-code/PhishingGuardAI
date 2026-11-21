"""Consistent classification metrics used by the baseline model scripts."""
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

def class_balance(labels):
    """Return counts keyed by label value without making model assumptions."""
    counts = labels.value_counts().sort_index()
    return {str(key): int(value) for key, value in counts.items()}

def classification_metrics(y_true, y_pred) -> dict:
    """Calculate binary metrics with label 1 as positive and safe zero division."""
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = (int(value) for value in matrix.ravel())
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }
