from datetime import datetime, timezone

import pytest

from insider_threat.evaluation.ttd import (
    build_prefix_window,
    calculate_time_to_detection,
    find_first_detection,
)


def make_event(
    timestamp,
    *,
    user_id="USR-003",
    sensitive=False,
    bytes_transferred=0,
    device_id="DEV-001",
    source_ip="10.0.0.1",
):
    class Event:
        pass

    event = Event()
    event.user_id = user_id
    event.timestamp = datetime.fromisoformat(timestamp)
    event.sensitive = sensitive
    event.bytes_transferred = bytes_transferred
    event.device_id = device_id
    event.source_ip = source_ip
    event.status = "success"

    return event


def test_build_prefix_window():
    events = [
        make_event(
            "2026-09-16T02:13:00+00:00"
        ),
        make_event(
            "2026-09-16T02:17:00+00:00",
            sensitive=True,
        ),
        make_event(
            "2026-09-16T02:42:00+00:00",
            bytes_transferred=850_000_000,
        ),
    ]

    result = build_prefix_window(events)

    assert result["user_id"] == "USR-003"
    assert result["date"] == "2026-09-16"
    assert result["hour_of_day"] == 2
    assert result["event_count"] == 3
    assert result["sensitive_access_count"] == 1
    assert result["bytes_transferred"] == 850_000_000
    assert result["unique_devices"] == 1
    assert result["unique_ips"] == 1


def test_build_prefix_window_empty():
    with pytest.raises(ValueError):
        build_prefix_window([])


def test_find_first_detection():
    results = [
        {"event_index": 1, "composite_signal": 0.10},
        {"event_index": 2, "composite_signal": 0.25},
        {"event_index": 3, "composite_signal": 0.40},
    ]

    result = find_first_detection(
        results,
        threshold=0.30,
    )

    assert result["event_index"] == 3


def test_find_first_detection_missing():
    results = [
        {"event_index": 1, "composite_signal": 0.10},
        {"event_index": 2, "composite_signal": 0.20},
    ]

    assert (
        find_first_detection(
            results,
            threshold=0.30,
        )
        is None
    )


def test_invalid_threshold():
    with pytest.raises(ValueError):
        find_first_detection(
            [],
            threshold=1.5,
        )


def test_calculate_time_to_detection():
    first = datetime(
        2026,
        9,
        16,
        2,
        13,
        tzinfo=timezone.utc,
    )

    detected = datetime(
        2026,
        9,
        16,
        2,
        17,
        tzinfo=timezone.utc,
    )

    assert (
        calculate_time_to_detection(
            first,
            detected,
        )
        == 240
    )
