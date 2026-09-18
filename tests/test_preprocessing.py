from datetime import datetime, timedelta, timezone

from insider_threat.ingestion.schema import EventSchema
from insider_threat.preprocessing.cleaning import (
    clean_events,
    remove_duplicate_events,
    summarize_events,
)
from insider_threat.preprocessing.normalization import (
    normalize_event,
    normalize_events,
)


def make_event(
    event_id: str,
    timestamp: datetime,
    event_type: str = "login",
    action: str = "login_success",
) -> EventSchema:
    return EventSchema(
        event_id=event_id,
        timestamp=timestamp,
        user_id="USR-001",
        event_type=event_type,
        action=action,
    )


def test_duplicate_events_are_removed():
    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event("EVT-001", timestamp),
        make_event("EVT-001", timestamp),
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=1),
        ),
    ]

    cleaned = remove_duplicate_events(events)

    assert len(cleaned) == 2
    assert [event.event_id for event in cleaned] == [
        "EVT-001",
        "EVT-002",
    ]


def test_clean_events_are_sorted():
    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=10),
        ),
        make_event(
            "EVT-001",
            timestamp,
        ),
    ]

    cleaned = clean_events(events)

    assert [
        event.event_id
        for event in cleaned
    ] == [
        "EVT-001",
        "EVT-002",
    ]


def test_event_normalization():
    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    event = make_event(
        "EVT-001",
        timestamp,
        event_type=" FILE ",
        action=" READ ",
    )

    normalized = normalize_event(event)

    assert normalized.event_type == "file"
    assert normalized.action == "read"
    assert normalized.status == "success"


def test_events_are_normalized_as_a_collection():
    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            "EVT-001",
            timestamp,
            event_type=" FILE ",
            action=" READ ",
        ),
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=1),
            event_type=" NETWORK ",
            action=" REQUEST ",
        ),
    ]

    normalized = normalize_events(events)

    assert normalized[0].event_type == "file"
    assert normalized[0].action == "read"

    assert normalized[1].event_type == "network"
    assert normalized[1].action == "request"


def test_event_summary():
    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event("EVT-001", timestamp),
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=1),
            event_type="file",
            action="read",
        ),
    ]

    summary = summarize_events(events)

    assert summary["total_events"] == 2
    assert summary["unique_event_ids"] == 2
    assert summary["unique_users"] == 1
    assert summary["event_types"]["login"] == 1
    assert summary["event_types"]["file"] == 1


def test_temporal_fields_are_derived():
    from insider_threat.preprocessing.normalization import (
        derive_temporal_fields,
    )

    timestamp = datetime(
        2026,
        9,
        5,
        2,
        13,
        tzinfo=timezone.utc,
    )

    event = make_event(
        "EVT-001",
        timestamp,
    )

    temporal = derive_temporal_fields(event)

    assert temporal["hour_of_day"] == 2
    assert temporal["day_of_week"] == 5
    assert temporal["is_weekend"] is True
    assert temporal["is_off_hours"] is True


def test_processed_event_pipeline():
    from insider_threat.preprocessing.pipeline import (
        build_processed_events,
    )

    from pathlib import Path
    import json

    dataset = [
        {
            "event_id": "EVT-002",
            "timestamp": "2026-09-01T09:15:00+00:00",
            "user_id": "USR-001",
            "event_type": " FILE ",
            "action": " READ ",
            "status": " SUCCESS ",
        },
        {
            "event_id": "EVT-001",
            "timestamp": "2026-09-01T02:13:00+00:00",
            "user_id": "USR-001",
            "event_type": " LOGIN ",
            "action": " LOGIN_SUCCESS ",
        },
    ]

    path = Path("tests") / "tmp_preprocessing_events.json"

    try:
        with path.open("w", encoding="utf-8") as file:
            json.dump(dataset, file)

        events = build_processed_events(path)

        assert len(events) == 2

        assert events[0].event_id == "EVT-001"
        assert events[1].event_id == "EVT-002"

        assert events[0].event_type == "login"
        assert events[0].action == "login_success"

        assert events[0].hour_of_day == 2
        assert events[0].is_off_hours is True

        assert events[1].hour_of_day == 9
        assert events[1].is_off_hours is False

    finally:
        if path.exists():
            path.unlink()


def test_dataset_quality_passes_for_valid_events():
    from insider_threat.preprocessing.quality import (
        validate_dataset_quality,
    )

    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event("EVT-001", timestamp),
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=1),
        ),
    ]

    report = validate_dataset_quality(events)

    assert report["total_events"] == 2
    assert report["unique_event_ids"] == 2
    assert report["duplicate_event_ids"] == []
    assert report["missing_required_fields"] == []
    assert report["negative_transfer_events"] == []
    assert report["non_utc_timestamps"] == []
    assert report["chronologically_sorted"] is True
    assert report["quality_passed"] is True


def test_dataset_quality_detects_duplicates():
    from insider_threat.preprocessing.quality import (
        validate_dataset_quality,
    )

    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event("EVT-001", timestamp),
        make_event("EVT-001", timestamp),
    ]

    report = validate_dataset_quality(events)

    assert report["duplicate_event_ids"] == ["EVT-001"]
    assert report["quality_passed"] is False


def test_dataset_quality_detects_unsorted_events():
    from insider_threat.preprocessing.quality import (
        validate_dataset_quality,
    )

    timestamp = datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            "EVT-002",
            timestamp + timedelta(minutes=5),
        ),
        make_event(
            "EVT-001",
            timestamp,
        ),
    ]

    report = validate_dataset_quality(events)

    assert report["chronologically_sorted"] is False
    assert report["quality_passed"] is False
