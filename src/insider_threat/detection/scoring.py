from __future__ import annotations

from typing import Iterable


def bounded_z_signal(
    absolute_z_score: float | None,
) -> float:
    """
    Convert an absolute z-score into a bounded [0, 1) signal.

    Transformation:

        signal = |z| / (1 + |z|)

    None represents a zero-variance baseline for which a z-score
    cannot be meaningfully calculated.
    """
    if absolute_z_score is None:
        return 0.0

    if absolute_z_score < 0:
        raise ValueError(
            "absolute_z_score cannot be negative"
        )

    return absolute_z_score / (
        1.0 + absolute_z_score
    )


def maximum_historical_deviation(
    baseline_result: dict,
    feature_names: Iterable[str],
) -> float:
    """
    Return the largest finite absolute z-score across features.

    Zero-variance features are excluded because they do not have
    a finite z-score representation.
    """
    scores = []

    for feature_name in feature_names:
        score = baseline_result[
            f"{feature_name}_absolute_z_score"
        ]

        if score is not None:
            scores.append(float(score))

    if not scores:
        return 0.0

    return max(scores)


def count_baseline_deviations(
    baseline_result: dict,
    feature_names: Iterable[str],
) -> int:
    """
    Count requested features that deviate from the historical
    baseline.
    """
    return sum(
        1
        for feature_name in feature_names
        if baseline_result[
            f"{feature_name}_deviation"
        ] is True
    )


def count_zero_variance_deviations(
    baseline_result: dict,
    feature_names: Iterable[str],
) -> int:
    """
    Count deviations where the historical baseline had zero
    variance.

    These represent structural changes from a previously constant
    behavioral feature.
    """
    return sum(
        1
        for feature_name in feature_names
        if (
            baseline_result[
                f"{feature_name}_zero_variance"
            ] is True
            and baseline_result[
                f"{feature_name}_deviation"
            ] is True
        )
    )


def empirical_percentile(
    score: float,
    reference_scores: Iterable[float],
) -> float:
    """
    Calculate an empirical percentile in [0, 1].

    The percentile represents the fraction of reference scores
    less than or equal to the supplied score.

    Reference scores must come from the training period when this
    function is used for temporal evaluation.
    """
    scores = list(reference_scores)

    if not scores:
        raise ValueError(
            "reference_scores cannot be empty"
        )

    return sum(
        reference_score <= score
        for reference_score in scores
    ) / len(scores)


def combine_risk_signals(
    baseline_signal: float,
    isolation_forest_signal: float,
    baseline_weight: float = 0.5,
    isolation_forest_weight: float = 0.5,
) -> float:
    """
    Combine normalized behavioral signals into an experimental
    risk indicator.

    Both input signals must be in [0, 1].

    The default weighting is intentionally equal and should be
    treated as an experimental configuration rather than an
    optimized model parameter.
    """
    if not 0.0 <= baseline_signal <= 1.0:
        raise ValueError(
            "baseline_signal must be between 0 and 1"
        )

    if not 0.0 <= isolation_forest_signal <= 1.0:
        raise ValueError(
            "isolation_forest_signal must be between 0 and 1"
        )

    if baseline_weight < 0:
        raise ValueError(
            "baseline_weight cannot be negative"
        )

    if isolation_forest_weight < 0:
        raise ValueError(
            "isolation_forest_weight cannot be negative"
        )

    total_weight = (
        baseline_weight
        + isolation_forest_weight
    )

    if total_weight <= 0:
        raise ValueError(
            "At least one risk-signal weight must be positive"
        )

    return (
        baseline_signal * baseline_weight
        + isolation_forest_signal
        * isolation_forest_weight
    ) / total_weight


def build_risk_indicator(
    baseline_result: dict,
    isolation_forest_result: dict,
    feature_names: Iterable[str],
    training_if_scores: Iterable[float],
    baseline_weight: float = 0.5,
    isolation_forest_weight: float = 0.5,
) -> dict:
    """
    Build an explainable hybrid behavioral risk indicator.

    Inputs:
        baseline_result:
            Historical user-specific baseline result.

        isolation_forest_result:
            Isolation Forest result for the same user-day.

        feature_names:
            Behavioral features included in the historical baseline.

        training_if_scores:
            Isolation Forest anomaly scores calculated from the
            training period only.

    Returns:
        A structured risk indicator containing component signals
        and supporting evidence.

    Important:
        This function does not classify users as malicious.
        It produces an experimental behavioral risk indicator.
    """
    feature_names = tuple(feature_names)

    max_abs_z = maximum_historical_deviation(
        baseline_result,
        feature_names,
    )

    baseline_signal = bounded_z_signal(
        max_abs_z
    )

    if_score = float(
        isolation_forest_result[
            "anomaly_score"
        ]
    )

    if_signal = empirical_percentile(
        if_score,
        training_if_scores,
    )

    total_deviations = count_baseline_deviations(
        baseline_result,
        feature_names,
    )

    zero_variance_deviations = (
        count_zero_variance_deviations(
            baseline_result,
            feature_names,
        )
    )

    hybrid_score = combine_risk_signals(
        baseline_signal=baseline_signal,
        isolation_forest_signal=if_signal,
        baseline_weight=baseline_weight,
        isolation_forest_weight=(
            isolation_forest_weight
        ),
    )

    return {
        "user_id": isolation_forest_result[
            "user_id"
        ],
        "date": isolation_forest_result[
            "date"
        ],
        "isolation_forest_score": if_score,
        "isolation_forest_prediction": (
            isolation_forest_result[
                "prediction"
            ]
        ),
        "isolation_forest_percentile": if_signal,
        "maximum_historical_absolute_z": (
            max_abs_z
        ),
        "historical_baseline_signal": (
            baseline_signal
        ),
        "total_baseline_deviations": (
            total_deviations
        ),
        "zero_variance_deviations": (
            zero_variance_deviations
        ),
        "hybrid_score": hybrid_score,
    }
