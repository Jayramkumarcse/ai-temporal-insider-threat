from collections import Counter
from datetime import datetime
from typing import Iterable

from insider_threat.ingestion.schema import EventSchema


def remove_duplicate_events(
    events: Iterable[EventSchema],
) -> list[EventSchema]:
    """
    Remove duplicate events using event_id.

    The first occurrence of each event_id is retained.
    """
    seen: set[str] = set()
    cleaned: list[EventSchema] = []

    for event in events:
        if event.event_id in seen:
            continue

        seen.add(event.event_id)
        cleaned.append(event)

    return cleaned


def validate_timestamps(
    events: Iterable[EventSchema],
) -> list[EventSchema]:
    """
    Keep events with valid datetime timestamps.

    EventSchema normally guarantees a valid datetime, but this
    validation step keeps the preprocessing pipeline defensive.
    """
    return [
        event
        for event in events
        if isinstance(event.timestamp, datetime)
    ]


def sort_events(
    events: Iterable[EventSchema],
) -> list[EventSchema]:
    """
    Sort events chronologically by timestamp.
    """
    return sorted(
        events,
        key=lambda event: event.timestamp,
    )


def clean_events(
    events: Iterable[EventSchema],
) -> list[EventSchema]:
    """
    Execute the core event-cleaning pipeline.

    Processing order:
        1. Remove duplicate event IDs.
        2. Validate timestamps.
        3. Sort chronologically.
    """
    cleaned = remove_duplicate_events(events)
    cleaned = validate_timestamps(cleaned)
    cleaned = sort_events(cleaned)

    return cleaned


def summarize_events(
    events: Iterable[EventSchema],
) -> dict:
    """
    Generate basic quality statistics for an event collection.
    """
    events = list(events)

    user_counts = Counter(
        event.user_id
        for event in events
    )

    event_type_counts = Counter(
        event.event_type
        for event in events
    )

    return {
        "total_events": len(events),
        "unique_event_ids": len(
            {event.event_id for event in events}
        ),
        "unique_users": len(user_counts),
        "users": dict(user_counts),
        "event_types": dict(event_type_counts),
    }
