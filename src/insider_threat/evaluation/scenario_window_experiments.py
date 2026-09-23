from __future__ import annotations

from datetime import date
from typing import Any

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.temporal_windows_general import (
    SUPPORTED_WINDOW_HOURS,
)


TARGET_WINDOW_START_HOURS = {
    1: 2,
    2: 2,
    4: 0,
    6: 0,
    8: 0,
    12: 0,
    24: 0,
}


def find_target_window(
    results: list[dict],
    *,
    user_id: str,
    target_date: date,
    window_hours: int,
) -> dict:
    target_start_hour = TARGET_WINDOW_START_HOURS[window_hours]

    target_date_string = target_date.isoformat()

    matches = [
        result
        for result in results
        if (
            result["user_id"] == user_id
            and str(result["date"]) == target_date_string
            and result["window_hours"] == window_hours
            and result["window_start_hour"] == target_start_hour
        )
    ]

    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one target window, "
            f"found {len(matches)}"
        )

    return matches[0]

def calculate_window_separation(
    results: list[dict[str, Any]],
    target: dict[str, Any],
) -> dict[str, float]:
    """Calculate target-vs-normal composite separation."""
    target_score = float(
        target["composite_signal"]
    )

    normal_scores = [
        float(result["composite_signal"])
        for result in results
        if not (
            result["user_id"]
            == target["user_id"]
            and result["date"]
            == target["date"]
            and result["window_hours"]
            == target["window_hours"]
            and result["window_start_hour"]
            == target["window_start_hour"]
        )
    ]

    if not normal_scores:
        return {
            "target_score": target_score,
            "highest_normal_score": 0.0,
            "absolute_margin": target_score,
            "ratio_to_highest_normal": float("inf"),
        }

    highest_normal = max(normal_scores)

    ratio = (
        target_score / highest_normal
        if highest_normal > 0
        else float("inf")
    )

    return {
        "target_score": target_score,
        "highest_normal_score": highest_normal,
        "absolute_margin": (
            target_score - highest_normal
        ),
        "ratio_to_highest_normal": ratio,
    }


def count_threshold_alerts(
    results: list[dict[str, Any]],
    *,
    threshold: float,
    target: dict[str, Any],
) -> tuple[int, int, bool]:
    """Count alerts while excluding the exact target window."""
    alerts = [
        result
        for result in results
        if result["composite_signal"] >= threshold
    ]

    def is_target(result: dict[str, Any]) -> bool:
        return (
            result["user_id"]
            == target["user_id"]
            and result["date"]
            == target["date"]
            and result["window_hours"]
            == target["window_hours"]
            and result["window_start_hour"]
            == target["window_start_hour"]
        )

    normal_alerts = [
        result
        for result in alerts
        if not is_target(result)
    ]

    target_detected = any(
        is_target(result)
        for result in alerts
    )

    return (
        len(alerts),
        len(normal_alerts),
        target_detected,
    )


def rank_target(
    results: list[dict[str, Any]],
    target: dict[str, Any],
) -> int:
    """Return descending composite rank of the target."""
    scores = sorted(
        (
            float(result["composite_signal"])
            for result in results
        ),
        reverse=True,
    )

    target_score = float(
        target["composite_signal"]
    )

    return (
        scores.index(target_score) + 1
    )


def evaluate_scenario_window(
    events: list[Any],
    *,
    start_date: date,
    end_date: date,
    window_hours: int,
    target_user: str,
    target_date: date,
    minimum_history: int,
    threshold: float,
) -> dict[str, Any]:
    """
    Evaluate one scenario under one temporal-window size.
    """
    results = build_temporal_window_experiment_results(
        events,
        start_date=start_date,
        end_date=end_date,
        window_hours=window_hours,
        minimum_history=minimum_history,
    )

    target = find_target_window(
        results,
        user_id=target_user,
        target_date=target_date,
        window_hours=window_hours,
    )

    separation = calculate_window_separation(
        results,
        target,
    )

    (
        total_alerts,
        normal_alerts,
        target_detected,
    ) = count_threshold_alerts(
        results,
        threshold=threshold,
        target=target,
    )

    return {
        "window_hours": window_hours,
        "total_windows": len(results),
        "target": target,
        "target_rank": rank_target(
            results,
            target,
        ),
        "separation": separation,
        "threshold": threshold,
        "total_alerts": total_alerts,
        "normal_alerts": normal_alerts,
        "target_detected": target_detected,
    }
