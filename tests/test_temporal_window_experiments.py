from datetime import date, datetime, timezone

import pytest

from insider_threat.baseline.temporal import (
    TEMPORAL_BASELINE_FEATURES,
)
from insider_threat.evaluation.temporal_window_experiments import (
    build_generalized_temporal_score,
    count_temporal_deviations,
    count_temporal_zero_variance_deviations,
    evaluate_temporal_window_experiment,
    find_target_window_result,
    maximum_temporal_absolute_z,
    score_temporal_feature,
    score_temporal_window,
)


def make_window(
    *,
    user_id="USR-001",
    window_hours=1,
    window_start_hour=2,
    event_count=10,
    sensitive_access_count=0,
    unique_devices=1,
    unique_ips=1,
    bytes_transferred=0,
    failed_action_count=0,
):
    return {
        "user_id": user_id,
        "window_hours": window_hours,
        "window_start_hour": window_start_hour,
        "window_start": (
            f"2026-09-16T"
            f"{window_start_hour:02d}:00:00+00:00"
        ),
        "window_end": (
            f"2026-09-16T"
            f"{window_start_hour + window_hours:02d}:00:00+00:00"
        ),
        "date": "2026-09-16",
        "event_count": event_count,
        "sensitive_access_count": sensitive_access_count,
        "unique_devices": unique_devices,
        "unique_ips": unique_ips,
        "bytes_transferred": bytes_transferred,
        "failed_action_count": failed_action_count,
    }


def test_score_temporal_feature_reuses_zero_variance_behavior():
    result = score_temporal_feature(
        current_value=5.0,
        historical_values=[0.0, 0.0, 0.0],
    )

    assert result["historical_mean"] == 0.0
    assert result["historical_std"] == 0.0
    assert result["zero_variance"] is True
    assert result["deviation"] is True
    assert result["z_score"] is None


def test_score_temporal_window_scores_all_features():
    current = make_window(
        event_count=20,
        sensitive_access_count=5,
        unique_devices=2,
        unique_ips=2,
        bytes_transferred=100,
    )

    history = [
        make_window(),
        make_window(),
        make_window(),
    ]

    scored = score_temporal_window(
        current_window=current,
        historical_windows=history,
    )

    assert scored["user_id"] == "USR-001"

    for feature_name in TEMPORAL_BASELINE_FEATURES:
        assert f"{feature_name}_value" in scored
        assert f"{feature_name}_deviation" in scored
        assert f"{feature_name}_zero_variance" in scored


def test_count_temporal_deviations():
    current = make_window(
        event_count=20,
        sensitive_access_count=5,
        unique_devices=2,
        unique_ips=2,
        bytes_transferred=100,
    )

    history = [
        make_window(),
        make_window(),
        make_window(),
    ]

    scored = score_temporal_window(
        current_window=current,
        historical_windows=history,
    )

    assert count_temporal_deviations(scored) == 5


def test_count_zero_variance_deviations():
    current = make_window(
        event_count=20,
        sensitive_access_count=5,
        unique_devices=2,
        unique_ips=2,
        bytes_transferred=100,
    )

    history = [
        make_window(),
        make_window(),
        make_window(),
    ]

    scored = score_temporal_window(
        current_window=current,
        historical_windows=history,
    )

    assert count_temporal_zero_variance_deviations(
        scored
    ) == 5


def test_maximum_temporal_absolute_z():
    current = make_window(
        event_count=20,
    )

    history = [
        make_window(event_count=10),
        make_window(event_count=10),
        make_window(event_count=10),
    ]

    scored = score_temporal_window(
        current_window=current,
        historical_windows=history,
    )

    assert maximum_temporal_absolute_z(scored) == 0.0


def test_generalized_temporal_score_is_bounded():
    current = make_window(
        event_count=20,
        sensitive_access_count=5,
        unique_devices=2,
        unique_ips=2,
        bytes_transferred=100,
    )

    history = [
        make_window(),
        make_window(),
        make_window(),
    ]

    scored = score_temporal_window(
        current_window=current,
        historical_windows=history,
    )

    result = build_generalized_temporal_score(
        scored
    )

    assert 0.0 <= result["temporal_score"] <= 1.0
    assert result["feature_count"] == 6


def test_find_target_window_result_for_1h():
    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 1,
            "window_start_hour": 2,
            "composite_signal": 0.7,
            "temporal_score": 0.6,
        }
    ]

    result = find_target_window_result(
        results,
        window_hours=1,
    )

    assert result["window_start_hour"] == 2


def test_find_target_window_result_for_2h():
    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": 2,
            "window_start_hour": 2,
            "composite_signal": 0.7,
            "temporal_score": 0.6,
        }
    ]

    result = find_target_window_result(
        results,
        window_hours=2,
    )

    assert result["window_start_hour"] == 2


@pytest.mark.parametrize(
    ("window_hours", "expected_start_hour"),
    [
        (1, 2),
        (2, 2),
        (4, 0),
        (6, 0),
        (8, 0),
        (12, 0),
        (24, 0),
    ],
)
def test_find_target_window_result_for_all_supported_windows(
    window_hours,
    expected_start_hour,
):
    results = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "window_hours": window_hours,
            "window_start_hour": expected_start_hour,
            "composite_signal": 0.7,
            "temporal_score": 0.6,
        }
    ]

    result = find_target_window_result(
        results,
        window_hours=window_hours,
    )

    assert result["window_start_hour"] == expected_start_hour


def test_invalid_window_size_rejected():
    with pytest.raises(ValueError):
        find_target_window_result(
            [],
            window_hours=3,
        )


def test_empty_results_rejected():
    with pytest.raises(ValueError):
        evaluate_temporal_window_experiment(
            [],
            window_hours=1,
        )
