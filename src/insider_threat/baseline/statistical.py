from math import sqrt
from statistics import mean
from typing import Iterable


def calculate_mean(
    values: Iterable[float],
) -> float:
    """
    Calculate the arithmetic mean of numeric values.

    Returns 0.0 for an empty collection.
    """
    values = list(values)

    if not values:
        return 0.0

    return mean(values)


def calculate_population_std(
    values: Iterable[float],
) -> float:
    """
    Calculate population standard deviation.

    Population standard deviation is used because the supplied
    values represent the complete reference window available to
    the baseline at that point.

    Returns 0.0 for an empty collection.
    """
    values = list(values)

    if not values:
        return 0.0

    average = mean(values)

    variance = sum(
        (value - average) ** 2
        for value in values
    ) / len(values)

    return sqrt(variance)


def calculate_z_score(
    value: float,
    baseline_mean: float,
    baseline_std: float,
) -> float:
    """
    Calculate a standardized deviation from a baseline.

    When the baseline has zero variance:
        - return 0.0 if value equals the baseline mean
        - return positive infinity if value differs

    This avoids silently treating a meaningful deviation from a
    perfectly stable baseline as normal.
    """
    if baseline_std == 0:
        if value == baseline_mean:
            return 0.0

        return float("inf")

    return (
        (value - baseline_mean)
        / baseline_std
    )


def calculate_absolute_z_score(
    value: float,
    baseline_mean: float,
    baseline_std: float,
) -> float:
    """
    Calculate the magnitude of standardized deviation.
    """
    return abs(
        calculate_z_score(
            value,
            baseline_mean,
            baseline_std,
        )
    )


def build_baseline(
    values: Iterable[float],
) -> dict[str, float]:
    """
    Build a statistical baseline from reference observations.

    Returns:
        mean
        standard_deviation
        observation_count
    """
    values = list(values)

    return {
        "mean": calculate_mean(values),
        "standard_deviation": calculate_population_std(values),
        "observation_count": float(len(values)),
    }


def score_against_baseline(
    value: float,
    baseline: dict[str, float],
) -> dict:
    """
    Calculate standardized deviation of a value from a baseline.

    Zero-variance baselines are represented explicitly rather than
    returning infinite values in the structured scoring result.

    A statistical anomaly threshold is intentionally not applied
    here. Threshold selection belongs to the detection/evaluation
    stage.
    """
    baseline_mean = baseline["mean"]
    baseline_std = baseline["standard_deviation"]

    if baseline_std == 0:
        return {
            "z_score": None,
            "absolute_z_score": None,
            "zero_variance": True,
            "deviation_from_baseline": (
                value != baseline_mean
            ),
        }

    z_score = (
        (value - baseline_mean)
        / baseline_std
    )

    return {
        "z_score": z_score,
        "absolute_z_score": abs(z_score),
        "zero_variance": False,
        "deviation_from_baseline": (
            value != baseline_mean
        ),
    }
