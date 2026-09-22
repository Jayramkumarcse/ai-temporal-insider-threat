from __future__ import annotations

from datetime import date
from typing import Any

from insider_threat.baseline.temporal import (
    TEMPORAL_BASELINE_FEATURES,
    build_dense_temporal_windows,
    get_same_window_history,
)
from insider_threat.baseline.hourly_scoring import (
    score_hourly_feature,
)
from insider_threat.detection.composite import (
    build_composite_investigation_signal,
)
from insider_threat.detection.context import (
    calculate_security_context_signal,
)
from insider_threat.detection.temporal_score import (
    combine_temporal_components,
)
from insider_threat.evaluation.temporal_metrics import (
    rank_descending,
    target_separation,
)
from insider_threat.features.temporal_windows_general import (
    SUPPORTED_WINDOW_HOURS,
    build_temporal_windows,
)


TARGET_USER = "USR-003"
TARGET_DATE = "2026-09-16"
TARGET_HOUR = 2
MINIMUM_HISTORY = 5

TARGET_WINDOW_START_HOURS = {
    1: 2,
    2: 2,
    4: 0,
    6: 0,
    8: 0,
    12: 0,
    24: 0,
}


def score_temporal_feature(
    current_value: float,
    historical_values: list[float],
) -> dict[str, Any]:
    """
    Score one generalized temporal-window feature.

    Reuses the validated statistical definition from the
    hourly baseline implementation.
    """
    return score_hourly_feature(
        current_value=current_value,
        historical_values=historical_values,
    )


def score_temporal_window(
    current_window: dict[str, Any],
    historical_windows: list[dict[str, Any]],
    feature_names: tuple[str, ...] = TEMPORAL_BASELINE_FEATURES,
) -> dict[str, Any]:
    """
    Compare one generalized temporal window against
    previous same-user, same-position observations.
    """
    if not historical_windows:
        raise ValueError(
            "historical_windows cannot be empty"
        )

    result: dict[str, Any] = {
        "user_id": current_window["user_id"],
        "date": current_window["date"],
        "window_hours": current_window["window_hours"],
        "window_start_hour": current_window[
            "window_start_hour"
        ],
        "window_start": current_window["window_start"],
        "window_end": current_window["window_end"],
    }

    for feature_name in feature_names:
        historical_values = [
            float(window[feature_name])
            for window in historical_windows
        ]

        feature_result = score_temporal_feature(
            current_value=float(
                current_window[feature_name]
            ),
            historical_values=historical_values,
        )

        for key, value in feature_result.items():
            result[
                f"{feature_name}_{key}"
            ] = value

    return result


def count_temporal_deviations(
    scored_window: dict[str, Any],
    feature_names: tuple[str, ...] = TEMPORAL_BASELINE_FEATURES,
) -> int:
    """Count generalized temporal features that deviate."""
    return sum(
        1
        for feature_name in feature_names
        if scored_window[
            f"{feature_name}_deviation"
        ]
    )


def count_temporal_zero_variance_deviations(
    scored_window: dict[str, Any],
    feature_names: tuple[str, ...] = TEMPORAL_BASELINE_FEATURES,
) -> int:
    """Count deviations caused by zero-variance baselines."""
    return sum(
        1
        for feature_name in feature_names
        if (
            scored_window[
                f"{feature_name}_zero_variance"
            ]
            and scored_window[
                f"{feature_name}_deviation"
            ]
        )
    )


def maximum_temporal_absolute_z(
    scored_window: dict[str, Any],
    feature_names: tuple[str, ...] = TEMPORAL_BASELINE_FEATURES,
) -> float:
    """Return the largest finite absolute z-score."""
    scores = [
        scored_window[
            f"{feature_name}_absolute_z_score"
        ]
        for feature_name in feature_names
        if scored_window[
            f"{feature_name}_absolute_z_score"
        ] is not None
    ]

    if not scores:
        return 0.0

    return max(float(score) for score in scores)


def build_generalized_temporal_score(
    scored_window: dict[str, Any],
    feature_names: tuple[str, ...] = TEMPORAL_BASELINE_FEATURES,
) -> dict[str, Any]:
    """
    Build the generalized temporal anomaly score.

    Uses the same weighting and bounded magnitude definition
    as the validated hourly temporal score.
    """
    feature_names = tuple(feature_names)

    if not feature_names:
        raise ValueError(
            "feature_names cannot be empty"
        )

    deviation_count = count_temporal_deviations(
        scored_window,
        feature_names,
    )

    zero_variance_count = (
        count_temporal_zero_variance_deviations(
            scored_window,
            feature_names,
        )
    )

    maximum_z = maximum_temporal_absolute_z(
        scored_window,
        feature_names,
    )

    deviation_coverage = (
        deviation_count / len(feature_names)
    )

    zero_variance_coverage = (
        zero_variance_count / len(feature_names)
    )

    magnitude_signal = (
        maximum_z / (1.0 + maximum_z)
    )

    temporal_score = combine_temporal_components(
        deviation_coverage=deviation_coverage,
        zero_variance_coverage=zero_variance_coverage,
        magnitude_signal=magnitude_signal,
    )

    return {
        "user_id": scored_window["user_id"],
        "date": scored_window["date"],
        "window_hours": scored_window["window_hours"],
        "window_start_hour": scored_window[
            "window_start_hour"
        ],
        "window_start": scored_window["window_start"],
        "window_end": scored_window["window_end"],
        "deviation_count": deviation_count,
        "zero_variance_deviation_count": (
            zero_variance_count
        ),
        "feature_count": len(feature_names),
        "deviation_coverage": deviation_coverage,
        "zero_variance_coverage": zero_variance_coverage,
        "magnitude_signal": magnitude_signal,
        "temporal_score": temporal_score,
    }


def build_temporal_window_experiment_results(
    events: list[Any],
    *,
    start_date: date,
    end_date: date,
    window_hours: int,
    minimum_history: int = MINIMUM_HISTORY,
) -> list[dict[str, Any]]:
    """
    Build generalized temporal/context experiment results.

    History is restricted to:
      - same user
      - same anchored window position
      - previous dates only
    """
    if window_hours not in SUPPORTED_WINDOW_HOURS:
        raise ValueError(
            "window_hours must be one of "
            f"{SUPPORTED_WINDOW_HOURS}"
        )

    if minimum_history < 1:
        raise ValueError(
            "minimum_history must be at least 1"
        )

    active_windows = build_temporal_windows(
        events,
        window_hours=window_hours,
    )

    users = sorted(
        {
            event.user_id
            for event in events
        }
    )

    windows = build_dense_temporal_windows(
        active_windows=active_windows,
        users=users,
        start_date=start_date,
        end_date=end_date,
        window_hours=window_hours,
    )

    results: list[dict[str, Any]] = []

    for window in windows:
        target_date = date.fromisoformat(
            window["date"]
        )

        history = get_same_window_history(
            windows,
            user_id=window["user_id"],
            target_date=target_date,
            window_start_hour=window[
                "window_start_hour"
            ],
            window_hours=window_hours,
        )

        if len(history) < minimum_history:
            continue

        scored = score_temporal_window(
            current_window=window,
            historical_windows=history,
        )

        temporal = build_generalized_temporal_score(
            scored
        )

        context = calculate_security_context_signal(
            window
        )

        composite = build_composite_investigation_signal(
            temporal_signal=temporal[
                "temporal_score"
            ],
            context=context,
        )

        results.append(
            {
                "user_id": window["user_id"],
                "date": window["date"],
                "window_hours": window[
                    "window_hours"
                ],
                "window_start_hour": window[
                    "window_start_hour"
                ],
                "window_start": window[
                    "window_start"
                ],
                "window_end": window[
                    "window_end"
                ],
                "event_count": window[
                    "event_count"
                ],
                "sensitive_access_count": window[
                    "sensitive_access_count"
                ],
                "bytes_transferred": window[
                    "bytes_transferred"
                ],
                "unique_devices": window[
                    "unique_devices"
                ],
                "unique_ips": window[
                    "unique_ips"
                ],
                "temporal_score": temporal[
                    "temporal_score"
                ],
                "deviation_count": temporal[
                    "deviation_count"
                ],
                "zero_variance_deviation_count": (
                    temporal[
                        "zero_variance_deviation_count"
                    ]
                ),
                "context_signal": composite[
                    "context_signal"
                ],
                "composite_signal": composite[
                    "composite_signal"
                ],
                "historical_count": len(history),
            }
        )

    return results


def find_target_window_result(
    results: list[dict[str, Any]],
    *,
    window_hours: int,
) -> dict[str, Any]:
    """
    Find the known target window for a given window size.
    """
    try:
        target_start_hour = TARGET_WINDOW_START_HOURS[
            window_hours
        ]
    except KeyError as exc:
        raise ValueError(
            "window_hours must be one of "
            f"{SUPPORTED_WINDOW_HOURS}"
        ) from exc

    for result in results:
        if (
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["window_hours"] == window_hours
            and result["window_start_hour"]
            == target_start_hour
        ):
            return result

    raise ValueError(
        "known target window was not found"
    )


def evaluate_temporal_window_experiment(
    results: list[dict[str, Any]],
    *,
    window_hours: int,
) -> dict[str, Any]:
    """
    Produce ranking and separation measurements
    for one temporal window size.
    """
    if not results:
        raise ValueError(
            "results cannot be empty"
        )

    target = find_target_window_result(
        results,
        window_hours=window_hours,
    )

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

    return {
        "window_hours": window_hours,
        "total_windows": len(results),
        "target": target,
        "temporal_rank": rank_descending(
            temporal_scores,
            target["temporal_score"],
        ),
        "composite_rank": rank_descending(
            composite_scores,
            target["composite_signal"],
        ),
        "composite_separation": target_separation(
            target["composite_signal"],
            normal_composite_scores,
        ),
    }
