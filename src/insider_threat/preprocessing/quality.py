from collections import Counter
from datetime import timezone
from typing import Iterable

from insider_threat.ingestion.schema import EventSchema


REQUIRED_FIELDS = (
    "event_id",
    "timestamp",
    "user_id",
    "event_type",
    "action",
)


def find_duplicate_event_ids(
    events: Iterable[EventSchema],
) -> list[str]:
    """
    Return event IDs that occur more than once.
    """
    counts = Counter(
        event.event_id
        for event in events
    )

    return sorted(
        event_id
        for event_id, count in counts.items()
        if count > 1
    )


def find_missing_required_fields(
    events: Iterable[EventSchema],
) -> list[str]:
    """
    Return event IDs containing missing required values.
    """
    invalid_events = []

    for event in events:
        for field_name in REQUIRED_FIELDS:
            value = getattr(event, field_name, None)

            if value is None:
                invalid_events.append(event.event_id)
                break

            if isinstance(value, str) and not value.strip():
                invalid_events.append(event.event_id)
                break

    return invalid_events


def find_negative_transfers(
    events: Iterable[EventSchema],
) -> list[str]:
    """
    Return event IDs containing negative byte-transfer values.
    """
    return [
        event.event_id
        for event in events
        if event.bytes_transferred < 0
    ]


def find_non_utc_timestamps(
    events: Iterable[EventSchema],
) -> list[str]:
    """
    Return event IDs whose timestamps are not timezone-aware UTC.
    """
    invalid_events = []

    for event in events:
        timestamp = event.timestamp

        if timestamp.tzinfo is None:
            invalid_events.append(event.event_id)
            continue

        if timestamp.utcoffset() != timezone.utc.utcoffset(timestamp):
            invalid_events.append(event.event_id)

    return invalid_events


def is_chronologically_sorted(
    events: Iterable[EventSchema],
) -> bool:
    """
    Check whether events are sorted by timestamp.
    """
    events = list(events)

    timestamps = [
        event.timestamp
        for event in events
    ]

    return timestamps == sorted(timestamps)


def validate_dataset_quality(
    events: Iterable[EventSchema],
) -> dict:
    """
    Run all core data-quality checks.

    Returns a structured quality report.
    """
    events = list(events)

    duplicate_ids = find_duplicate_event_ids(events)
    missing_fields = find_missing_required_fields(events)
    negative_transfers = find_negative_transfers(events)
    non_utc_timestamps = find_non_utc_timestamps(events)

    return {
        "total_events": len(events),
        "unique_event_ids": len(
            {event.event_id for event in events}
        ),
        "duplicate_event_ids": duplicate_ids,
        "missing_required_fields": missing_fields,
        "negative_transfer_events": negative_transfers,
        "non_utc_timestamps": non_utc_timestamps,
        "chronologically_sorted": is_chronologically_sorted(
            events
        ),
        "quality_passed": (
            len(duplicate_ids) == 0
            and len(missing_fields) == 0
            and len(negative_transfers) == 0
            and len(non_utc_timestamps) == 0
            and is_chronologically_sorted(events)
        ),
    }
