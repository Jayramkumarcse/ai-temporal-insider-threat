from __future__ import annotations

from datetime import date
from typing import Any

from insider_threat.baseline.hourly import (
    build_dense_hourly_windows,
    get_same_hour_history,
)
from insider_threat.baseline.hourly_scoring import (
    score_hourly_window,
)
from insider_threat.detection.composite import (
    build_composite_investigation_signal,
)
from insider_threat.detection.context import (
    calculate_security_context_signal,
)
from insider_threat.detection.temporal_score import (
    build_temporal_score,
)
from insider_threat.evaluation.temporal_metrics import (
    rank_descending,
    target_separation,
)


TARGET_USER = "USR-003"
TARGET_DATE = "2026-09-16"
TARGET_HOUR = 2


def build_hourly_experiment_results(
    events: list[Any],
    *,
    start_date: date,
    end_date: date,
    minimum_history: int = 5,
) -> list[dict[str, Any]]:
    """
    Build reusable hourly temporal/context experiment results.

    Only previous same-hour observations are used as history.
    """

    windows = build_dense_hourly_windows(
        events,
        start_date=start_date,
        end_date=end_date,
    )

    results: list[dict[str, Any]] = []

    for window in windows:
        target_date = date.fromisoformat(
            window["date"]
        )

        history = get_same_hour_history(
            windows,
            user_id=window["user_id"],
            target_date=target_date,
            hour_of_day=window["hour_of_day"],
        )

        if len(history) < minimum_history:
            continue

        scored = score_hourly_window(
            current_window=window,
            historical_windows=history,
        )

        temporal = build_temporal_score(
            scored
        )

        context = calculate_security_context_signal(
            window
        )

        composite = build_composite_investigation_signal(
            temporal_signal=temporal["temporal_score"],
            context=context,
        )

        results.append(
            {
                "user_id": window["user_id"],
                "date": window["date"],
                "hour_of_day": window["hour_of_day"],
                "event_count": window["event_count"],
                "sensitive_access_count": (
                    window["sensitive_access_count"]
                ),
                "bytes_transferred": (
                    window["bytes_transferred"]
                ),
                "unique_devices": (
                    window["unique_devices"]
                ),
                "unique_ips": (
                    window["unique_ips"]
                ),
                "temporal_score": (
                    temporal["temporal_score"]
                ),
                "context_signal": (
                    composite["context_signal"]
                ),
                "composite_signal": (
                    composite["composite_signal"]
                ),
            }
        )

    return results


def find_target_result(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Find the known synthetic anomaly window.
    """

    for result in results:
        if (
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["hour_of_day"] == TARGET_HOUR
        ):
            return result

    raise ValueError(
        "known target window was not found"
    )


def evaluate_composite_experiment(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Produce ranking and separation measurements
    for the known target window.
    """

    if not results:
        raise ValueError(
            "results cannot be empty"
        )

    target = find_target_result(results)

    temporal_scores = [
        result["temporal_score"]
        for result in results
    ]

    composite_scores = [
        result["composite_signal"]
        for result in results
    ]

    normal_composite_scores = [
        result["composite_signal"]
        for result in results
        if result is not target
    ]

    temporal_rank = rank_descending(
        temporal_scores,
        target["temporal_score"],
    )

    composite_rank = rank_descending(
        composite_scores,
        target["composite_signal"],
    )

    separation = target_separation(
        target["composite_signal"],
        normal_composite_scores,
    )

    return {
        "total_windows": len(results),
        "target": target,
        "temporal_rank": temporal_rank,
        "composite_rank": composite_rank,
        "composite_separation": separation,
    }
