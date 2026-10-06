from __future__ import annotations

from typing import Iterable, Sequence

from insider_threat.evaluation.metrics import (
    calculate_classification_metrics,
)
from insider_threat.evaluation.temporal_metrics import (
    rank_descending,
    threshold_counts,
)


def build_model_evaluation(
    *,
    model_name: str,
    scores: Sequence[float],
    threshold: float,
    labels: Sequence[int],
) -> dict[str, object]:
    """
    Build a standardized evaluation record for one anomaly detector.

    Score semantics:
        Higher score = more anomalous.

    Prediction semantics:
        score >= threshold -> anomaly (1)
        score < threshold  -> normal (0)
    """
    if not model_name.strip():
        raise ValueError("model_name cannot be empty")

    if not scores:
        raise ValueError("scores cannot be empty")

    if len(scores) != len(labels):
        raise ValueError(
            "scores and labels must have the same length"
        )

    predictions = [
        int(score >= threshold)
        for score in scores
    ]

    metrics = calculate_classification_metrics(
        list(labels),
        predictions,
    )

    counts = threshold_counts(
        scores,
        threshold,
    )

    return {
        "model_name": model_name,
        "threshold": float(threshold),
        "scores": [float(score) for score in scores],
        "predictions": predictions,
        "alert_count": counts["alerts"],
        "total_samples": counts["total"],
        "alert_rate": (
            counts["alerts"] / counts["total"]
        ),
        "metrics": metrics,
    }


def add_target_rank(
    evaluation: dict[str, object],
    *,
    target_index: int,
) -> dict[str, object]:
    """
    Add the descending anomaly-score rank of a known target.

    Rank 1 means the target has the highest anomaly score.
    """
    scores = evaluation["scores"]

    if not isinstance(scores, list):
        raise ValueError(
            "evaluation scores must be a list"
        )

    if not 0 <= target_index < len(scores):
        raise IndexError(
            "target_index is outside the evaluation scores"
        )

    target_score = scores[target_index]

    rank = rank_descending(
        scores,
        target_score,
    )

    return {
        **evaluation,
        "target_index": target_index,
        "target_score": float(target_score),
        "target_rank": rank,
    }


def compare_model_evaluations(
    evaluations: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    """
    Return model evaluations in a deterministic model-name order.
    """
    evaluations = list(evaluations)

    if not evaluations:
        raise ValueError(
            "evaluations cannot be empty"
        )

    return sorted(
        evaluations,
        key=lambda evaluation: str(
            evaluation["model_name"]
        ),
    )
