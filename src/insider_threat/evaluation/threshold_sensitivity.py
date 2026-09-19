from __future__ import annotations

from typing import Iterable


def evaluate_threshold(
    scores: Iterable[float],
    target_index: int,
    threshold: float,
) -> dict[str, float | int | bool]:
    """
    Evaluate a detection threshold against ordered composite scores.

    Parameters
    ----------
    scores:
        Composite scores for evaluated windows.
    target_index:
        Index of the known anomaly in ``scores``.
    threshold:
        Alert threshold in the [0, 1] range.

    Returns
    -------
    Dictionary containing alert counts and target detection status.

    Notes
    -----
    This function is an evaluation utility. It does not determine
    whether an event is malicious.
    """

    scores = list(scores)

    if not scores:
        raise ValueError("scores cannot be empty")

    if not 0 <= target_index < len(scores):
        raise IndexError("target_index is outside scores")

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")

    alerts = [
        score >= threshold
        for score in scores
    ]

    target_detected = alerts[target_index]

    normal_alerts = sum(
        alert
        for index, alert in enumerate(alerts)
        if index != target_index
    )

    total_alerts = sum(alerts)

    alert_rate = total_alerts / len(scores)

    return {
        "threshold": threshold,
        "total_windows": len(scores),
        "alerts": total_alerts,
        "normal_alerts": normal_alerts,
        "target_detected": target_detected,
        "alert_rate": alert_rate,
    }


def evaluate_thresholds(
    scores: Iterable[float],
    target_index: int,
    thresholds: Iterable[float],
) -> list[dict[str, float | int | bool]]:
    """
    Evaluate multiple thresholds against the same score distribution.
    """

    scores = list(scores)

    return [
        evaluate_threshold(
            scores=scores,
            target_index=target_index,
            threshold=threshold,
        )
        for threshold in thresholds
    ]
