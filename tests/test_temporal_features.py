from datetime import datetime, timezone

from insider_threat.features.temporal import (
    calculate_event_rate,
    calculate_inter_event_seconds,
    extract_temporal_features,
)
from insider_threat.preprocessing.processed_event import ProcessedEvent


def make_event(
    event_id: str,
    timestamp: datetime,
) -> ProcessedEvent:
    return ProcessedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user_id="USR-001",
        event_type="file",
        action="read",
        resource="/data/test.txt",
        device_id="DEV-001",
        source_ip="10.0.0.1",
        status="success",
        sensitive=False,
        bytes_transferred=0,
        metadata={},
        hour_of_day=timestamp.hour,
        day_of_week=timestamp.weekday(),
        is_weekend=timestamp.weekday() >= 5,
        is_off_hours=timestamp.hour < 8 or timestamp.hour >= 18,
    )


def test_extract_temporal_features_normal_hours():
    event = make_event(
        "EVT-001",
        datetime(
            2026,
            9,
            1,
            10,
            30,
            tzinfo=timezone.utc,
        ),
    )

    features = extract_temporal_features(event)

    assert features["hour_of_day"] == 10
    assert features["day_of_week"] == 1
    assert features["is_weekend"] is False
    assert features["is_off_hours"] is False


def test_extract_temporal_features_off_hours():
    event = make_event(
        "EVT-002",
        datetime(
            2026,
            9,
            1,
            2,
            15,
            tzinfo=timezone.utc,
        ),
    )

    features = extract_temporal_features(event)

    assert features["hour_of_day"] == 2
    assert features["is_off_hours"] is True


def test_extract_temporal_features_weekend():
    event = make_event(
        "EVT-003",
        datetime(
            2026,
            9,
            5,
            11,
            0,
            tzinfo=timezone.utc,
        ),
    )

    features = extract_temporal_features(event)

    assert features["day_of_week"] == 5
    assert features["is_weekend"] is True


def test_calculate_inter_event_seconds():
    events = [
        make_event(
            "EVT-001",
            datetime(
                2026,
                9,
                1,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-002",
            datetime(
                2026,
                9,
                1,
                10,
                0,
                30,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-003",
            datetime(
                2026,
                9,
                1,
                10,
                2,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    intervals = calculate_inter_event_seconds(events)

    assert intervals == [None, 30.0, 90.0]


def test_calculate_inter_event_seconds_empty():
    assert calculate_inter_event_seconds([]) == []


def test_calculate_event_rate():
    rate = calculate_event_rate(
        event_count=60,
        duration_seconds=60,
    )

    assert rate == 1.0


def test_calculate_event_rate_zero_duration():
    assert calculate_event_rate(
        event_count=10,
        duration_seconds=0,
    ) == 0.0
