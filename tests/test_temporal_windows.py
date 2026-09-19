from datetime import datetime, timezone

from insider_threat.features.temporal_windows import (
    build_hourly_windows,
    get_hour_window_start,
)
from insider_threat.preprocessing.processed_event import (
    ProcessedEvent,
)


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


def test_hour_window_start():
    timestamp = datetime(
        2026,
        9,
        16,
        2,
        13,
        45,
        tzinfo=timezone.utc,
    )

    result = get_hour_window_start(timestamp)

    assert result == datetime(
        2026,
        9,
        16,
        2,
        0,
        0,
        tzinfo=timezone.utc,
    )


def test_events_are_grouped_into_same_hour():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
        ),
        make_event(
            "E2",
            "2026-09-16T02:30:00Z",
        ),
    ]

    windows = build_hourly_windows(events)

    assert len(windows) == 1
    assert windows[0]["event_count"] == 2


def test_different_hours_create_different_windows():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
        ),
        make_event(
            "E2",
            "2026-09-16T03:13:00Z",
        ),
    ]

    windows = build_hourly_windows(events)

    assert len(windows) == 2


def test_behavioral_features_are_aggregated():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
            sensitive=True,
            bytes_transferred=100,
        ),
        make_event(
            "E2",
            "2026-09-16T02:20:00Z",
            sensitive=True,
            device_id="DEV-002",
            source_ip="10.0.0.2",
            bytes_transferred=200,
            status="failed",
        ),
    ]

    windows = build_hourly_windows(events)

    window = windows[0]

    assert window["event_count"] == 2
    assert window["sensitive_access_count"] == 2
    assert window["unique_devices"] == 2
    assert window["unique_ips"] == 2
    assert window["bytes_transferred"] == 300
    assert window["failed_action_count"] == 1


def test_only_active_windows_are_created():
    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
        )
    ]

    windows = build_hourly_windows(events)

    assert len(windows) == 1


def test_hour_window_start_normalizes_timezone():
    timestamp = datetime.fromisoformat(
        "2026-09-16T07:13:45+05:00"
    )

    result = get_hour_window_start(timestamp)

    assert result == datetime(
        2026,
        9,
        16,
        2,
        0,
        0,
        tzinfo=timezone.utc,
    )
