from datetime import date, datetime, timezone

import pytest

from insider_threat.baseline.temporal import (
    build_dense_temporal_windows,
    get_same_window_history,
)


def make_window(
    user_id: str,
    timestamp: str,
    window_hours: int,
    event_count: int = 0,
) -> dict:
    start = datetime.fromisoformat(timestamp)
    end = start.replace(
        hour=start.hour + window_hours,
    )

    return {
        "user_id": user_id,
        "window_hours": window_hours,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "date": start.date().isoformat(),
        "window_start_hour": start.hour,
        "event_count": event_count,
        "sensitive_access_count": 0,
        "unique_devices": 0,
        "unique_ips": 0,
        "bytes_transferred": 0,
        "failed_action_count": 0,
        "first_event_timestamp": None,
        "last_event_timestamp": None,
    }


def test_dense_one_hour_grid():
    active = [
        make_window(
            "USR-001",
            "2026-09-15T02:00:00+00:00",
            1,
            event_count=5,
        )
    ]

    windows = build_dense_temporal_windows(
        active_windows=active,
        users=["USR-001"],
        start_date=date(2026, 9, 15),
        end_date=date(2026, 9, 15),
        window_hours=1,
    )

    assert len(windows) == 24

    target = next(
        window
        for window in windows
        if window["window_start_hour"] == 2
    )

    assert target["event_count"] == 5

    zero_window = next(
        window
        for window in windows
        if window["window_start_hour"] == 3
    )

    assert zero_window["event_count"] == 0


def test_dense_two_hour_grid():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 15),
        end_date=date(2026, 9, 15),
        window_hours=2,
    )

    assert len(windows) == 12

    assert [
        window["window_start_hour"]
        for window in windows
    ] == [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22]


def test_dense_four_hour_grid():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 15),
        end_date=date(2026, 9, 15),
        window_hours=4,
    )

    assert len(windows) == 6

    assert [
        window["window_start_hour"]
        for window in windows
    ] == [0, 4, 8, 12, 16, 20]


def test_multiple_users_are_included():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001", "USR-002"],
        start_date=date(2026, 9, 15),
        end_date=date(2026, 9, 15),
        window_hours=2,
    )

    assert len(windows) == 24


def test_multiple_dates_are_included():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 14),
        end_date=date(2026, 9, 15),
        window_hours=4,
    )

    assert len(windows) == 12


def test_same_window_history_uses_previous_dates_only():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 14),
        end_date=date(2026, 9, 16),
        window_hours=2,
    )

    history = get_same_window_history(
        windows=windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        window_start_hour=2,
        window_hours=2,
    )

    assert len(history) == 2

    assert [
        window["date"]
        for window in history
    ] == [
        "2026-09-14",
        "2026-09-15",
    ]


def test_same_window_history_excludes_other_window_positions():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 14),
        end_date=date(2026, 9, 15),
        window_hours=4,
    )

    history = get_same_window_history(
        windows=windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        window_start_hour=4,
        window_hours=4,
    )

    assert len(history) == 2

    assert all(
        window["window_start_hour"] == 4
        for window in history
    )


def test_same_window_history_excludes_other_users():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001", "USR-002"],
        start_date=date(2026, 9, 14),
        end_date=date(2026, 9, 15),
        window_hours=2,
    )

    history = get_same_window_history(
        windows=windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        window_start_hour=2,
        window_hours=2,
    )

    assert len(history) == 2
    assert all(
        window["user_id"] == "USR-001"
        for window in history
    )


def test_same_window_history_is_sorted_by_date():
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 12),
        end_date=date(2026, 9, 15),
        window_hours=4,
    )

    history = get_same_window_history(
        windows=windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        window_start_hour=0,
        window_hours=4,
    )

    assert [
        window["date"]
        for window in history
    ] == [
        "2026-09-12",
        "2026-09-13",
        "2026-09-14",
        "2026-09-15",
    ]


@pytest.mark.parametrize("window_hours", [1, 2, 4])
def test_invalid_future_history_is_not_included(window_hours):
    windows = build_dense_temporal_windows(
        active_windows=[],
        users=["USR-001"],
        start_date=date(2026, 9, 14),
        end_date=date(2026, 9, 17),
        window_hours=window_hours,
    )

    history = get_same_window_history(
        windows=windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        window_start_hour=0,
        window_hours=window_hours,
    )

    assert all(
        date.fromisoformat(window["date"]) < date(2026, 9, 16)
        for window in history
    )
