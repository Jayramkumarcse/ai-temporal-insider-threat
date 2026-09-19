from __future__ import annotations

from math import sqrt
from statistics import mean
from typing import Iterable

from insider_threat.baseline.hourly import HOURLY_FEATURES


def calculate_mean(values: Iterable[float]) -> float:
    """Calculate the arithmetic mean."""

    values = list(values)

    if not values:
        return 0.0

    return mean(values)


def calculate_population_std(values: Iterable[float]) -> float:
    """Calculate population standard deviation."""

    values = list(values)

    if not values:
        return 0.0

    average = mean(values)

    variance = sum(
        (value - average) ** 2
        for value in values
    ) / len(values)

    return sqrt(variance)


def score_hourly_feature(
    current_value: float,
    historical_values: Iterable[float],
) -> dict:
    """
    Compare one hourly feature against previous observations.

    Zero-variance historical baselines are handled explicitly.
    """

    historical_values = list(historical_values)

    if not historical_values:
        raise ValueError(
            "historical_values cannot be empty"
        )

    historical_mean = calculate_mean(
        historical_values
    )

    historical_std = calculate_population_std(
        historical_values
    )

    deviation = current_value != historical_mean

    if historical_std == 0:

        return {
            "value": current_value,
            "historical_mean": historical_mean,
            "historical_std": 0.0,
            "z_score": None,
            "absolute_z_score": None,
            "zero_variance": True,
            "deviation": deviation,
            "historical_count": len(
                historical_values
            ),
        }

    z_score = (
        current_value - historical_mean
    ) / historical_std

    return {
        "value": current_value,
        "historical_mean": historical_mean,
        "historical_std": historical_std,
        "z_score": z_score,
        "absolute_z_score": abs(z_score),
        "zero_variance": False,
        "deviation": deviation,
        "historical_count": len(
            historical_values
        ),
    }


def score_hourly_window(
    current_window: dict,
    historical_windows: Iterable[dict],
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> dict:
    """
    Compare one hourly window against previous same-hour windows.

    The caller is responsible for ensuring historical_windows
    contain only observations from dates before current_window.
    """

    historical_windows = list(historical_windows)
    feature_names = tuple(feature_names)

    if not historical_windows:
        raise ValueError(
            "historical_windows cannot be empty"
        )

    result = {
        "user_id": current_window["user_id"],
        "date": current_window["date"],
        "hour_of_day": current_window["hour_of_day"],
        "window_start": current_window["window_start"],
        "window_end": current_window["window_end"],
    }

    for feature_name in feature_names:

        historical_values = [
            float(window[feature_name])
            for window in historical_windows
        ]

        feature_result = score_hourly_feature(
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


def count_hourly_deviations(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> int:
    """Count features that deviate from their historical mean."""

    return sum(
        1
        for feature_name in feature_names
        if scored_window[
            f"{feature_name}_deviation"
        ]
    )


def count_zero_variance_deviations(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> int:
    """
    Count deviations where the historical baseline
    had zero variance.
    """

    return sum(
        1
        for feature_name in feature_names
        if scored_window[
            f"{feature_name}_zero_variance"
        ]
        and scored_window[
            f"{feature_name}_deviation"
        ]
    )


def maximum_hourly_absolute_z(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
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
