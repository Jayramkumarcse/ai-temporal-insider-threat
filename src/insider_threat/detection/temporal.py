from __future__ import annotations

from typing import Iterable

from insider_threat.baseline.hourly import HOURLY_FEATURES
from insider_threat.baseline.hourly_scoring import (
    count_hourly_deviations,
    count_zero_variance_deviations,
    maximum_hourly_absolute_z,
)


def calculate_deviation_coverage(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> float:
    """
    Calculate the fraction of monitored features
    that deviate from the historical baseline.
    """

    feature_names = tuple(feature_names)

    if not feature_names:
        return 0.0

    deviations = count_hourly_deviations(
        scored_window,
        feature_names,
    )

    return deviations / len(feature_names)


def calculate_zero_variance_coverage(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> float:
    """
    Calculate the fraction of monitored features that both
    have zero historical variance and deviate from baseline.
    """

    feature_names = tuple(feature_names)

    if not feature_names:
        return 0.0

    deviations = count_zero_variance_deviations(
        scored_window,
        feature_names,
    )

    return deviations / len(feature_names)


def calculate_magnitude_signal(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> float:
    """
    Convert the maximum finite absolute z-score into a bounded signal.

    Zero-variance deviations are handled separately through
    zero_variance_coverage.
    """

    maximum_z = maximum_hourly_absolute_z(
        scored_window,
        feature_names,
    )

    if maximum_z < 0:
        raise ValueError(
            "maximum absolute z-score cannot be negative"
        )

    return maximum_z / (1.0 + maximum_z)


def build_temporal_anomaly_signal(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
) -> dict:
    """
    Build an interpretable hourly temporal anomaly signal.

    This is an anomaly indicator, not a determination that
    a user is malicious.
    """

    feature_names = tuple(feature_names)

    deviation_coverage = calculate_deviation_coverage(
        scored_window,
        feature_names,
    )

    zero_variance_coverage = (
        calculate_zero_variance_coverage(
            scored_window,
            feature_names,
        )
    )

    magnitude_signal = calculate_magnitude_signal(
        scored_window,
        feature_names,
    )

    return {
        "user_id": scored_window["user_id"],
        "date": scored_window["date"],
        "hour_of_day": scored_window["hour_of_day"],
        "window_start": scored_window["window_start"],
        "window_end": scored_window["window_end"],
        "deviation_count": count_hourly_deviations(
            scored_window,
            feature_names,
        ),
        "zero_variance_deviation_count": (
            count_zero_variance_deviations(
                scored_window,
                feature_names,
            )
        ),
        "feature_count": len(feature_names),
        "deviation_coverage": deviation_coverage,
        "zero_variance_coverage": zero_variance_coverage,
        "magnitude_signal": magnitude_signal,
    }
