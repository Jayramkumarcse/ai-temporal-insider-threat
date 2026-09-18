from datetime import datetime, timezone

from insider_threat.features.builder import (
    build_user_day_features,
    group_events_by_user_and_day,
)
from insider_threat.preprocessing.processed_event import ProcessedEvent


def make_event(
    event_id: str,
    user_id: str,
    timestamp: datetime,
) -> ProcessedEvent:
    return ProcessedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user_id=user_id,
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


def test_group_events_by_user_and_day():
    events = [
        make_event(
            "EVT-001",
            "USR-001",
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
            "USR-001",
            datetime(
                2026,
                9,
                1,
                11,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-003",
            "USR-001",
            datetime(
                2026,
                9,
                2,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-004",
            "USR-002",
            datetime(
                2026,
                9,
                1,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    grouped = group_events_by_user_and_day(events)

    assert len(grouped) == 3

    assert len(
        grouped[("USR-001", datetime(2026, 9, 1).date())]
    ) == 2

    assert len(
        grouped[("USR-001", datetime(2026, 9, 2).date())]
    ) == 1

    assert len(
        grouped[("USR-002", datetime(2026, 9, 1).date())]
    ) == 1


def test_build_user_day_features():
    events = [
        make_event(
            "EVT-001",
            "USR-001",
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
            "USR-001",
            datetime(
                2026,
                9,
                1,
                10,
                1,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-003",
            "USR-002",
            datetime(
                2026,
                9,
                1,
                11,
                0,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    features = build_user_day_features(events)

    assert len(features) == 2

    first = features[0]

    assert first["user_id"] == "USR-001"
    assert first["date"] == "2026-09-01"
    assert first["event_count"] == 2
    assert first["mean_inter_event_seconds"] == 60.0


def test_build_user_day_features_sorted():
    events = [
        make_event(
            "EVT-002",
            "USR-001",
            datetime(
                2026,
                9,
                2,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-001",
            "USR-001",
            datetime(
                2026,
                9,
                1,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    features = build_user_day_features(events)

    assert features[0]["date"] == "2026-09-01"
    assert features[1]["date"] == "2026-09-02"
