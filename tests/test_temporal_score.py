import pytest

from insider_threat.detection.temporal_score import (
    build_temporal_score,
    combine_temporal_components,
)


def test_temporal_components_are_combined():
    score = combine_temporal_components(
        deviation_coverage=0.8,
        zero_variance_coverage=0.6,
        magnitude_signal=0.5,
    )

    expected = (
        0.8 * 0.5
        + 0.6 * 0.3
        + 0.5 * 0.2
    )

    assert score == pytest.approx(expected)


def test_zero_weight_components_are_supported():
    score = combine_temporal_components(
        deviation_coverage=0.8,
        zero_variance_coverage=0.2,
        magnitude_signal=0.1,
        deviation_weight=1.0,
        zero_variance_weight=0.0,
        magnitude_weight=0.0,
    )

    assert score == pytest.approx(0.8)


def test_invalid_component_is_rejected():
    with pytest.raises(ValueError):
        combine_temporal_components(
            deviation_coverage=1.2,
            zero_variance_coverage=0.5,
            magnitude_signal=0.2,
        )


def test_invalid_weights_are_rejected():
    with pytest.raises(ValueError):
        combine_temporal_components(
            deviation_coverage=0.5,
            zero_variance_coverage=0.5,
            magnitude_signal=0.5,
            deviation_weight=0.0,
            zero_variance_weight=0.0,
            magnitude_weight=0.0,
        )


def test_build_temporal_score_contains_components():
    scored_window = {
        "user_id": "USR-003",
        "date": "2026-09-16",
        "hour_of_day": 2,
        "window_start": "2026-09-16T02:00:00+00:00",
        "window_end": "2026-09-16T03:00:00+00:00",
        "event_count_deviation": True,
        "event_count_zero_variance": True,
        "event_count_absolute_z_score": None,
        "sensitive_access_count_deviation": True,
        "sensitive_access_count_zero_variance": True,
        "sensitive_access_count_absolute_z_score": None,
        "unique_devices_deviation": True,
        "unique_devices_zero_variance": True,
        "unique_devices_absolute_z_score": None,
        "unique_ips_deviation": True,
        "unique_ips_zero_variance": True,
        "unique_ips_absolute_z_score": None,
        "bytes_transferred_deviation": True,
        "bytes_transferred_zero_variance": True,
        "bytes_transferred_absolute_z_score": None,
        "failed_action_count_deviation": False,
        "failed_action_count_zero_variance": True,
        "failed_action_count_absolute_z_score": None,
    }

    result = build_temporal_score(scored_window)

    assert result["deviation_count"] == 5
    assert result["zero_variance_deviation_count"] == 5
    assert result["temporal_score"] == pytest.approx(
        2 / 3
    )
