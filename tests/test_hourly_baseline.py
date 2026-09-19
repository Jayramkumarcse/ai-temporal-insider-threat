from datetime import date

from insider_threat.baseline.hourly import (
    build_dense_hourly_windows,
    get_same_hour_history,
)
from insider_threat.preprocessing.processed_event import (
    ProcessedEvent,
)
from datetime import datetime


def make_event(
    event_id: str,
    timestamp: str,
    user_id: str = "USR-001",
    sensitive: bool = False,
    device_id: str = "DEV-001",
    source_ip: str = "10.0.0.1",
    bytes_transferred: int = 0,
    status: str = "success",
) -> ProcessedEvent:

    return ProcessedEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        ),
        user_id=user_id,
        event_type="file",
        action="read",
        resource="/test/file",
        device_id=device_id,
        source_ip=source_ip,
        status=status,
        sensitive=sensitive,
        bytes_transferred=bytes_transferred,
        metadata={},
        hour_of_day=2,
        day_of_week=2,
        is_weekend=False,
        is_off_hours=True,
    )


def test_dense_windows_include_inactive_hours():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
        )
    ]

    windows = build_dense_hourly_windows(
        events,
        date(2026, 9, 16),
        date(2026, 9, 16),
    )

    assert len(windows) == 24

    inactive = [
        window
        for window in windows
        if window["hour_of_day"] != 2
    ]

    assert len(inactive) == 23
    assert all(
        window["event_count"] == 0
        for window in inactive
    )


def test_active_hour_contains_behavioral_features():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
            sensitive=True,
            bytes_transferred=500,
        )
    ]

    windows = build_dense_hourly_windows(
        events,
        date(2026, 9, 16),
        date(2026, 9, 16),
    )

    target = next(
        window
        for window in windows
        if window["hour_of_day"] == 2
    )

    assert target["event_count"] == 1
    assert target["sensitive_access_count"] == 1
    assert target["bytes_transferred"] == 500


def test_dense_grid_covers_multiple_days_and_users():
    events = [
        make_event(
            "E1",
            "2026-09-15T02:13:00Z",
            user_id="USR-001",
        ),
        make_event(
            "E2",
            "2026-09-16T03:13:00Z",
            user_id="USR-002",
        ),
    ]

    windows = build_dense_hourly_windows(
        events,
        date(2026, 9, 15),
        date(2026, 9, 16),
    )

    assert len(windows) == 2 * 2 * 24


def test_same_hour_history_uses_previous_dates_only():
    events = [
        make_event(
            "E1",
            "2026-09-14T02:10:00Z",
        ),
        make_event(
            "E2",
            "2026-09-15T02:10:00Z",
        ),
        make_event(
            "E3",
            "2026-09-16T02:10:00Z",
        ),
    ]

    windows = build_dense_hourly_windows(
        events,
        date(2026, 9, 14),
        date(2026, 9, 16),
    )

    history = get_same_hour_history(
        windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        hour_of_day=2,
    )

    assert len(history) == 2
    assert [window["date"] for window in history] == [
        "2026-09-14",
        "2026-09-15",
    ]


def test_same_hour_history_preserves_zero_activity():
    events = [
        make_event(
            "E1",
            "2026-09-14T09:10:00Z",
        ),
        make_event(
            "E2",
            "2026-09-15T09:10:00Z",
        ),
    ]

    windows = build_dense_hourly_windows(
        events,
        date(2026, 9, 14),
        date(2026, 9, 16),
    )

    history = get_same_hour_history(
        windows,
        user_id="USR-001",
        target_date=date(2026, 9, 16),
        hour_of_day=2,
    )

    assert len(history) == 2
    assert all(
        window["event_count"] == 0
        for window in history
    )
