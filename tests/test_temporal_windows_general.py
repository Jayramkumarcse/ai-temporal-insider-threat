from datetime import datetime, timezone

import pytest

from insider_threat.features.temporal_windows_general import (
    SUPPORTED_WINDOW_HOURS,
    build_temporal_windows,
    get_window_start,
    validate_window_hours,
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

def test_supported_window_sizes():

    assert SUPPORTED_WINDOW_HOURS == (
        1,
        2,
        4,
        6,
        8,
        12,
        24,
    )


def test_invalid_window_size_is_rejected():

    with pytest.raises(ValueError):

        validate_window_hours(3)


def test_one_hour_window_alignment():

    timestamp = datetime(
        2026,
        9,
        16,
        2,
        13,
        45,
        tzinfo=timezone.utc,
    )

    result = get_window_start(
        timestamp,
        1,
    )

    assert result == datetime(
    2026,
    9,
    16,
    2,
    0,
    0,
    tzinfo=timezone.utc,
)


def test_two_hour_window_alignment():

    timestamp = datetime(
        2026,
        9,
        16,
        3,
        13,
        tzinfo=timezone.utc,
    )

    result = get_window_start(
        timestamp,
        2,
    )

    assert result == datetime(
    2026,
    9,
    16,
    2,
    0,
    0,
    tzinfo=timezone.utc,
)

def test_four_hour_window_alignment():

    timestamp = datetime(
        2026,
        9,
        16,
        2,
        13,
        tzinfo=timezone.utc,
    )

    result = get_window_start(
        timestamp,
        4,
    )

    assert result == datetime(
        2026,
        9,
        16,
        0,
        0,
        0,
        tzinfo=timezone.utc,
    )


def test_two_events_share_two_hour_window():

    events = [
        make_event(
            "E1",
            "2026-09-16T02:13:00Z",
        ),
        make_event(
            "E2",
            "2026-09-16T03:30:00Z",
        ),
    ]

    windows = build_temporal_windows(
        events,
        window_hours=2,
    )

    assert len(windows) == 1

    assert windows[0]["window_start"] == (
        "2026-09-16T02:00:00+00:00"
    )

    assert windows[0]["window_end"] == (
        "2026-09-16T04:00:00+00:00"
    )

    assert windows[0]["event_count"] == 2


def test_events_crossing_two_hour_boundary_create_two_windows():

    events = [
        make_event(
            "E1",
            "2026-09-16T03:59:59Z",
        ),
        make_event(
            "E2",
            "2026-09-16T04:00:00Z",
        ),
    ]

    windows = build_temporal_windows(
        events,
        window_hours=2,
    )

    assert len(windows) == 2

    assert windows[0]["window_start"] == (
        "2026-09-16T02:00:00+00:00"
    )

    assert windows[1]["window_start"] == (
        "2026-09-16T04:00:00+00:00"
    )


def test_four_hour_target_window():

    events = [
        make_event(
            "E1",
            "2026-09-16T00:30:00Z",
        ),
        make_event(
            "E2",
            "2026-09-16T02:13:00Z",
            sensitive=True,
            bytes_transferred=850000000,
        ),
        make_event(
            "E3",
            "2026-09-16T03:59:59Z",
        ),
    ]

    windows = build_temporal_windows(
        events,
        window_hours=4,
    )

    assert len(windows) == 1

    window = windows[0]

    assert window["window_start"] == (
        "2026-09-16T00:00:00+00:00"
    )

    assert window["window_end"] == (
        "2026-09-16T04:00:00+00:00"
    )

    assert window["event_count"] == 3

    assert window["sensitive_access_count"] == 1

    assert window["bytes_transferred"] == 850000000


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

    windows = build_temporal_windows(
        events,
        window_hours=2,
    )

    window = windows[0]

    assert window["event_count"] == 2

    assert window["sensitive_access_count"] == 2

    assert window["unique_devices"] == 2

    assert window["unique_ips"] == 2

    assert window["bytes_transferred"] == 300

    assert window["failed_action_count"] == 1


def test_timezone_is_normalized_to_utc():

    timestamp = datetime.fromisoformat(
        "2026-09-16T07:13:45+05:00"
    )

    result = get_window_start(
        timestamp,
        4,
    )

    assert result == datetime(
        2026,
        9,
        16,
        0,
        0,
        0,
        tzinfo=timezone.utc,
    )
