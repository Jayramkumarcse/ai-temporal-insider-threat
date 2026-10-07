from __future__ import annotations

from typing import Iterable


def select_max_validation_threshold(
    validation_scores: Iterable[float],
) -> float:
    """Select an anomaly threshold using validation scores only."""
    scores = [float(score) for score in validation_scores]

    if not scores:
        raise ValueError("validation scores cannot be empty")

    if not all(
        score == score
        and abs(score) != float("inf")
        for score in scores
    ):
        raise ValueError("validation scores must be finite")

    return max(scores)
