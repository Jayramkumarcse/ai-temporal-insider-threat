from __future__ import annotations

from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


def calculate_classification_metrics(
    y_true: list[int],
    y_pred: list[int],
) -> dict[str, float | int]:
    """
    Calculate binary anomaly-detection classification metrics.

    Label semantics:

        0 = normal
        1 = anomaly

    Returns precision, recall, F1, and confusion-matrix counts.
    """
    if len(y_true) != len(y_pred):
        raise ValueError(
            "y_true and y_pred must have the same length"
        )

    if not y_true:
        raise ValueError(
            "y_true and y_pred cannot be empty"
        )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    true_negative = int(matrix[0, 0])
    false_positive = int(matrix[0, 1])
    false_negative = int(matrix[1, 0])
    true_positive = int(matrix[1, 1])

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_positive": true_positive,
    }
