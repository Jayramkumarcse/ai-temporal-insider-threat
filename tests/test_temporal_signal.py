from insider_threat.detection.temporal import (
    build_temporal_anomaly_signal,
    calculate_deviation_coverage,
    calculate_magnitude_signal,
    calculate_zero_variance_coverage,
)


def make_scored_window():
    return {
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


def test_deviation_coverage():
    scored = make_scored_window()

    assert calculate_deviation_coverage(scored) == 5 / 6


def test_zero_variance_coverage():
    scored = make_scored_window()

    assert calculate_zero_variance_coverage(scored) == 5 / 6


def test_magnitude_signal_is_zero_without_finite_z_scores():
    scored = make_scored_window()

    assert calculate_magnitude_signal(scored) == 0.0


def test_temporal_signal_contains_interpretable_components():
    scored = make_scored_window()

    result = build_temporal_anomaly_signal(scored)

    assert result["deviation_count"] == 5
    assert result["zero_variance_deviation_count"] == 5
    assert result["feature_count"] == 6
    assert result["deviation_coverage"] == 5 / 6
    assert result["zero_variance_coverage"] == 5 / 6
    assert result["magnitude_signal"] == 0.0
