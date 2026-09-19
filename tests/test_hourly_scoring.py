from insider_threat.baseline.hourly_scoring import (
    count_hourly_deviations,
    count_zero_variance_deviations,
    maximum_hourly_absolute_z,
    score_hourly_feature,
    score_hourly_window,
)


def test_zero_variance_equal_value_is_not_deviation():
    result = score_hourly_feature(
        current_value=0,
        historical_values=[0, 0, 0],
    )

    assert result["zero_variance"] is True
    assert result["deviation"] is False
    assert result["z_score"] is None


def test_zero_variance_changed_value_is_deviation():
    result = score_hourly_feature(
        current_value=56,
        historical_values=[0, 0, 0],
    )

    assert result["zero_variance"] is True
    assert result["deviation"] is True
    assert result["z_score"] is None
    assert result["historical_mean"] == 0
    assert result["historical_count"] == 3


def test_nonzero_variance_returns_z_score():
    result = score_hourly_feature(
        current_value=5,
        historical_values=[1, 2, 3, 4, 5],
    )

    assert result["zero_variance"] is False
    assert result["deviation"] is True
    assert result["z_score"] > 0
    assert result["absolute_z_score"] > 0


def test_hourly_window_scores_multiple_features():
    current = {
        "user_id": "USR-003",
        "date": "2026-09-16",
        "hour_of_day": 2,
        "window_start": "2026-09-16T02:00:00+00:00",
        "window_end": "2026-09-16T03:00:00+00:00",
        "event_count": 56,
        "sensitive_access_count": 51,
        "unique_devices": 2,
        "unique_ips": 2,
        "bytes_transferred": 850000000,
        "failed_action_count": 0,
    }

    history = [
        {
            "event_count": 0,
            "sensitive_access_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
        }
        for _ in range(15)
    ]

    result = score_hourly_window(
        current,
        history,
    )

    assert result["event_count_deviation"] is True
    assert result["sensitive_access_count_deviation"] is True
    assert result["unique_devices_deviation"] is True
    assert result["unique_ips_deviation"] is True
    assert result["bytes_transferred_deviation"] is True
    assert result["failed_action_count_deviation"] is False


def test_deviation_counters():
    scored = {
        "event_count_deviation": True,
        "event_count_zero_variance": True,
        "sensitive_access_count_deviation": True,
        "sensitive_access_count_zero_variance": True,
        "unique_devices_deviation": False,
        "unique_devices_zero_variance": True,
        "unique_ips_deviation": True,
        "unique_ips_zero_variance": False,
        "bytes_transferred_deviation": True,
        "bytes_transferred_zero_variance": True,
        "failed_action_count_deviation": False,
        "failed_action_count_zero_variance": True,
    }

    assert count_hourly_deviations(scored) == 4
    assert count_zero_variance_deviations(scored) == 3


def test_maximum_hourly_absolute_z():
    scored = {
        "event_count_absolute_z_score": 3.5,
        "sensitive_access_count_absolute_z_score": None,
        "unique_devices_absolute_z_score": 2.0,
        "unique_ips_absolute_z_score": None,
        "bytes_transferred_absolute_z_score": 4.2,
        "failed_action_count_absolute_z_score": None,
    }

    assert maximum_hourly_absolute_z(scored) == 4.2
