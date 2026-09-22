from scripts.run_temporal_window_comparison import (
    count_threshold_alerts,
)


def test_count_threshold_alerts_requires_exact_target_window():
    target_window = {
        "user_id": "USR-003",
        "date": "2026-09-16",
        "window_hours": 1,
        "window_start_hour": 2,
    }

    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 2,
            "composite_signal": 0.70,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 3,
            "composite_signal": 0.80,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 2,
            "composite_signal": 0.90,
        },
    ]

    total_alerts, normal_alerts, target_detected = (
        count_threshold_alerts(
            results,
            threshold=0.30,
            target_window=target_window,
        )
    )

    assert total_alerts == 3
    assert normal_alerts == 2
    assert target_detected is True


def test_count_threshold_alerts_false_when_exact_target_not_alerted():
    target_window = {
        "user_id": "USR-003",
        "date": "2026-09-16",
        "window_hours": 1,
        "window_start_hour": 2,
    }

    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 2,
            "composite_signal": 0.20,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 3,
            "composite_signal": 0.80,
        },
    ]

    total_alerts, normal_alerts, target_detected = (
        count_threshold_alerts(
            results,
            threshold=0.30,
            target_window=target_window,
        )
    )

    assert total_alerts == 1
    assert normal_alerts == 1
    assert target_detected is False
