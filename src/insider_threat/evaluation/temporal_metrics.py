from __future__ import annotations

from typing import Iterable


def rank_descending(
    scores: Iterable[float],
    target_score: float,
) -> int:
    """
    Return 1-based descending rank of a target score.
    """
    scores = list(scores)

    return 1 + sum(
        score > target_score
        for score in scores
    )


def threshold_counts(
    scores: Iterable[float],
    threshold: float,
) -> dict[str, int]:
    """
    Count alerts at a score threshold.
    """
    scores = list(scores)

    alerts = sum(
        score >= threshold
        for score in scores
    )

    return {
        "total": len(scores),
        "alerts": alerts,
        "normal_or_other": len(scores) - alerts,
    }


def threshold_alert_rate(
    scores: Iterable[float],
    threshold: float,
) -> float:
    """
    Calculate the fraction of windows at or above a threshold.
    """
    scores = list(scores)

    if not scores:
        return 0.0

    alerts = sum(
        score >= threshold
        for score in scores
    )

    return alerts / len(scores)


def target_separation(
    target_score: float,
    normal_scores: Iterable[float],
) -> dict[str, float]:
    """
    Measure separation between one target score and normal scores.
    """
    normal_scores = list(normal_scores)

    if not normal_scores:
        raise ValueError(
            "normal_scores cannot be empty"
        )

    highest_normal = max(normal_scores)

    return {
        "target_score": target_score,
        "highest_normal_score": highest_normal,
        "absolute_margin": (
            target_score - highest_normal
        ),
        "ratio_to_highest_normal": (
            target_score / highest_normal
            if highest_normal > 0
            else float("inf")
        ),
    }
