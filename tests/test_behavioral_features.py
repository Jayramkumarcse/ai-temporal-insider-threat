from datetime import datetime, timezone

from insider_threat.features.behavioral import (
    aggregate_behavioral_features,
)
from insider_threat.preprocessing.processed_event import ProcessedEvent


def make_event(
    event_id: str,
    timestamp: datetime,
    event_type: str = "file",
    action: str = "read",
    sensitive: bool = False,
    device_id: str | None = "DEV-001",
    source_ip: str | None = "10.0.0.1",
    status: str = "success",
    bytes_transferred: int = 0,
) -> ProcessedEvent:
    return ProcessedEvent(
        event_id=event_id,
        timestamp=timestamp,
        user_id="USR-001",
        event_type=event_type,
        action=action,
        resource="/data/test.txt",
        device_id=device_id,
        source_ip=source_ip,
        status=status,
        sensitive=sensitive,
        bytes_transferred=bytes_transferred,
        metadata={},
        hour_of_day=timestamp.hour,
        day_of_week=timestamp.weekday(),
        is_weekend=timestamp.weekday() >= 5,
        is_off_hours=timestamp.hour < 8 or timestamp.hour >= 18,
    )


def test_empty_events():
    features = aggregate_behavioral_features([])

    assert features["event_count"] == 0
    assert features["login_count"] == 0
    assert features["event_rate"] == 0.0


def test_basic_behavioral_counts():
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
            event_type="login",
            action="login_success",
        ),
        make_event(
            "EVT-002",
            datetime(
                2026,
                9,
                1,
                10,
                1,
                tzinfo=timezone.utc,
            ),
            event_type="file",
            sensitive=True,
            bytes_transferred=500,
        ),
        make_event(
            "EVT-003",
            datetime(
                2026,
                9,
                1,
                10,
                3,
                tzinfo=timezone.utc,
            ),
            event_type="file",
            sensitive=False,
            bytes_transferred=300,
        ),
    ]

    features = aggregate_behavioral_features(events)

    assert features["event_count"] == 3
    assert features["login_count"] == 1
    assert features["file_access_count"] == 2
    assert features["sensitive_access_count"] == 1
    assert features["bytes_transferred"] == 800


def test_unique_devices_and_ips():
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
            device_id="DEV-001",
            source_ip="10.0.0.1",
        ),
        make_event(
            "EVT-002",
            datetime(
                2026,
                9,
                1,
                10,
                1,
                tzinfo=timezone.utc,
            ),
            device_id="DEV-002",
            source_ip="10.0.0.2",
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
            device_id="DEV-001",
            source_ip="10.0.0.1",
        ),
    ]

    features = aggregate_behavioral_features(events)

    assert features["unique_devices"] == 2
    assert features["unique_ips"] == 2


def test_night_and_weekend_activity():
    events = [
        make_event(
            "EVT-001",
            datetime(
                2026,
                9,
                5,
                2,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-002",
            datetime(
                2026,
                9,
                5,
                3,
                0,
                tzinfo=timezone.utc,
            ),
        ),
        make_event(
            "EVT-003",
            datetime(
                2026,
                9,
                5,
                10,
                0,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    features = aggregate_behavioral_features(events)

    assert features["night_activity_count"] == 2
    assert features["weekend_activity_count"] == 3


def test_failed_actions():
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
            status="failure",
        ),
        make_event(
            "EVT-002",
            datetime(
                2026,
                9,
                1,
                10,
                1,
                tzinfo=timezone.utc,
            ),
            status="success",
        ),
    ]

    features = aggregate_behavioral_features(events)

    assert features["failed_action_count"] == 1


def test_inter_event_statistics():
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
                1,
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
                3,
                tzinfo=timezone.utc,
            ),
        ),
    ]

    features = aggregate_behavioral_features(events)

    assert features["mean_inter_event_seconds"] == 90.0
    assert features["median_inter_event_seconds"] == 90.0
    assert features["min_inter_event_seconds"] == 60.0
    assert features["max_inter_event_seconds"] == 120.0


def test_event_rate():
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
                1,
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

    features = aggregate_behavioral_features(events)

    assert features["event_rate"] == 2 / 120


def test_single_event_has_zero_rate():
    event = make_event(
        "EVT-001",
        datetime(
            2026,
            9,
            1,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

    features = aggregate_behavioral_features([event])

    assert features["event_rate"] == 0.0
    assert features["mean_inter_event_seconds"] == 0.0
