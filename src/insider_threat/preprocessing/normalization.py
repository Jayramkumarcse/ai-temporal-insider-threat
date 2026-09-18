from datetime import timezone
from typing import Iterable

from insider_threat.ingestion.schema import EventSchema


def normalize_text(value: str) -> str:
    """
    Normalize a text value by trimming whitespace
    and converting it to lowercase.
    """
    return value.strip().lower()


def normalize_event(event: EventSchema) -> EventSchema:
    """
    Normalize categorical fields and timestamp representation.

    Normalized fields:
        - event_type
        - action
        - status
        - timestamp -> UTC
    """
    timestamp = event.timestamp

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)

    return event.model_copy(
        update={
            "timestamp": timestamp,
            "event_type": normalize_text(event.event_type),
            "action": normalize_text(event.action),
            "status": normalize_text(event.status),
        }
    )


def derive_temporal_fields(event: EventSchema) -> dict:
    """
    Derive temporal features from an event timestamp.

    These fields will be used later for temporal behavioral
    analysis and anomaly detection.
    """
    timestamp = event.timestamp.astimezone(timezone.utc)

    hour = timestamp.hour

    return {
        "hour_of_day": hour,
        "day_of_week": timestamp.weekday(),
        "is_weekend": timestamp.weekday() >= 5,
        "is_off_hours": hour < 8 or hour >= 18,
    }


def normalize_events(
    events: Iterable[EventSchema],
) -> list[EventSchema]:
    """
    Normalize a collection of events.
    """
    return [
        normalize_event(event)
        for event in events
    ]
