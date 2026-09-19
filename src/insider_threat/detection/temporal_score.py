from __future__ import annotations

from typing import Iterable

from insider_threat.baseline.hourly import HOURLY_FEATURES
from insider_threat.detection.temporal import (
    build_temporal_anomaly_signal,
)


def combine_temporal_components(
    deviation_coverage: float,
    zero_variance_coverage: float,
    magnitude_signal: float,
    deviation_weight: float = 0.5,
    zero_variance_weight: float = 0.3,
    magnitude_weight: float = 0.2,
) -> float:
    """
    Combine hourly temporal anomaly components into a bounded score.

    The default weights are methodological starting points and are
    not claimed to be optimized.
    """

    components = (
        deviation_coverage,
        zero_variance_coverage,
        magnitude_signal,
    )

    if any(
        value < 0.0 or value > 1.0
        for value in components
    ):
        raise ValueError(
            "Temporal components must be between 0 and 1"
        )

    weights = (
        deviation_weight,
        zero_variance_weight,
        magnitude_weight,
    )

    if any(weight < 0.0 for weight in weights):
        raise ValueError(
            "Temporal weights cannot be negative"
        )

    total_weight = sum(weights)

    if total_weight <= 0:
        raise ValueError(
            "At least one temporal weight must be positive"
        )

    return (
        deviation_coverage * deviation_weight
        + zero_variance_coverage * zero_variance_weight
        + magnitude_signal * magnitude_weight
    ) / total_weight


def build_temporal_score(
    scored_window: dict,
    feature_names: Iterable[str] = HOURLY_FEATURES,
    deviation_weight: float = 0.5,
    zero_variance_weight: float = 0.3,
    magnitude_weight: float = 0.2,
) -> dict:
    """
    Build a bounded temporal anomaly score for one user-hour window.
    """

    signal = build_temporal_anomaly_signal(
        scored_window,
        feature_names,
    )

    score = combine_temporal_components(
        deviation_coverage=signal["deviation_coverage"],
        zero_variance_coverage=signal[
            "zero_variance_coverage"
        ],
        magnitude_signal=signal["magnitude_signal"],
        deviation_weight=deviation_weight,
        zero_variance_weight=zero_variance_weight,
        magnitude_weight=magnitude_weight,
    )

    return {
        **signal,
        "temporal_score": score,
        "deviation_weight": deviation_weight,
        "zero_variance_weight": zero_variance_weight,
        "magnitude_weight": magnitude_weight,
    }
