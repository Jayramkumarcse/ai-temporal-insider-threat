from datetime import date

import pytest

from insider_threat.evaluation.time_of_day_experiments import (
    TARGET_WINDOW_START_HOURS,
    calculate_window_separation,
    find_target_window,
)


def test_target_window_mapping():
    assert TARGET_WINDOW_START_HOURS[1][0] == 0
    assert TARGET_WINDOW_START_HOURS[1][22] == 22

    assert TARGET_WINDOW_START_HOURS[4][2] == 0
    assert TARGET_WINDOW_START_HOURS[4][14] == 12

    assert TARGET_WINDOW_START_HOURS[8][22] == 16
    assert TARGET_WINDOW_START_HOURS[24][22] == 0


def test_find_target_window_uses_exact_time_mapping():
    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 4,
            "window_start_hour": 0,
            "composite_signal": 0.52,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 4,
            "window_start_hour": 4,
            "composite_signal": 0.10,
        },
    ]

    result = find_target_window(
        results,
        user_id="USR-003",
        target_date=date(2026, 9, 16),
        window_hours=4,
        anomaly_hour=2,
    )

    assert result["window_start_hour"] == 0
    assert result["composite_signal"] == 0.52


def test_find_target_window_rejects_missing_target():
    results = [
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 2,
            "composite_signal": 0.10,
        }
    ]

    with pytest.raises(ValueError, match="expected exactly one target window"):
        find_target_window(
            results,
            user_id="USR-003",
            target_date=date(2026, 9, 16),
            window_hours=1,
            anomaly_hour=2,
        )


def test_calculate_window_separation():
    result = calculate_window_separation(
        target_score=0.70,
        highest_normal_score=0.20,
    )

    assert result["absolute_margin"] == pytest.approx(0.50)
    assert result["ratio_to_highest_normal"] == pytest.approx(3.5)


def test_calculate_window_separation_zero_normal():
    result = calculate_window_separation(
        target_score=0.70,
        highest_normal_score=0.0,
    )

    assert result["absolute_margin"] == pytest.approx(0.70)
    assert result["ratio_to_highest_normal"] == float("inf")
