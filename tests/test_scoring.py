import pytest

from insider_threat.detection.scoring import (
    bounded_z_signal,
    combine_risk_signals,
    count_baseline_deviations,
    count_zero_variance_deviations,
    empirical_percentile,
    maximum_historical_deviation,
)


FEATURES = (
    "event_count",
    "sensitive_access_count",
    "night_activity_count",
)


def make_baseline_result() -> dict:
    return {
        "event_count_absolute_z_score": 5.0,
        "event_count_deviation": True,
        "event_count_zero_variance": False,

        "sensitive_access_count_absolute_z_score": None,
        "sensitive_access_count_deviation": True,
        "sensitive_access_count_zero_variance": True,

        "night_activity_count_absolute_z_score": 2.0,
        "night_activity_count_deviation": False,
        "night_activity_count_zero_variance": False,
    }


def test_bounded_z_signal():
    assert bounded_z_signal(0.0) == 0.0
    assert bounded_z_signal(1.0) == pytest.approx(0.5)
    assert bounded_z_signal(5.0) == pytest.approx(
        5.0 / 6.0
    )


def test_bounded_z_signal_none():
    assert bounded_z_signal(None) == 0.0


def test_bounded_z_signal_rejects_negative():
    with pytest.raises(ValueError):
        bounded_z_signal(-1.0)


def test_maximum_historical_deviation():
    result = make_baseline_result()

    assert maximum_historical_deviation(
        result,
        FEATURES,
    ) == 5.0


def test_maximum_historical_deviation_empty():
    result = {
        "event_count_absolute_z_score": None,
        "sensitive_access_count_absolute_z_score": None,
    }

    assert maximum_historical_deviation(
        result,
        (
            "event_count",
            "sensitive_access_count",
        ),
    ) == 0.0


def test_count_baseline_deviations():
    result = make_baseline_result()

    assert count_baseline_deviations(
        result,
        FEATURES,
    ) == 2


def test_count_zero_variance_deviations():
    result = make_baseline_result()

    assert count_zero_variance_deviations(
        result,
        FEATURES,
    ) == 1


def test_empirical_percentile():
    reference = [
        0.1,
        0.2,
        0.3,
        0.4,
        0.5,
    ]

    assert empirical_percentile(
        0.3,
        reference,
    ) == pytest.approx(0.6)

    assert empirical_percentile(
        0.5,
        reference,
    ) == pytest.approx(1.0)


def test_empirical_percentile_requires_reference():
    with pytest.raises(ValueError):
        empirical_percentile(
            0.5,
            [],
        )


def test_combine_risk_signals():
    assert combine_risk_signals(
        baseline_signal=0.8,
        isolation_forest_signal=0.6,
    ) == pytest.approx(0.7)


def test_combine_custom_weights():
    result = combine_risk_signals(
        baseline_signal=1.0,
        isolation_forest_signal=0.0,
        baseline_weight=3.0,
        isolation_forest_weight=1.0,
    )

    assert result == pytest.approx(0.75)


def test_combine_rejects_invalid_signal():
    with pytest.raises(ValueError):
        combine_risk_signals(
            baseline_signal=1.2,
            isolation_forest_signal=0.5,
        )


def test_combine_rejects_zero_weights():
    with pytest.raises(ValueError):
        combine_risk_signals(
            baseline_signal=0.5,
            isolation_forest_signal=0.5,
            baseline_weight=0.0,
            isolation_forest_weight=0.0,
        )
