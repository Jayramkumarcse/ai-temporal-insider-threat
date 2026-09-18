from datetime import datetime, timezone
from typing import Iterable

from insider_threat.preprocessing.processed_event import ProcessedEvent


def ensure_utc(timestamp: datetime) -> datetime:
    """
    Convert a timestamp to timezone-aware UTC.

    Naive timestamps are interpreted as UTC.
    """
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def extract_temporal_features(
    event: ProcessedEvent,
) -> dict:
    """
    Extract basic temporal features from a processed event.

    Features:
        - hour_of_day
        - day_of_week
        - is_weekend
        - is_off_hours
    """
    timestamp = ensure_utc(event.timestamp)

    hour = timestamp.hour
    day_of_week = timestamp.weekday()

    return {
        "hour_of_day": hour,
        "day_of_week": day_of_week,
        "is_weekend": day_of_week >= 5,
        "is_off_hours": hour < 8 or hour >= 18,
    }


def calculate_inter_event_seconds(
    events: Iterable[ProcessedEvent],
) -> list[float | None]:
    """
    Calculate the elapsed time between consecutive events.

    Events are expected to belong to the same user and should be
    chronologically ordered.

    The first event has no previous event, so its value is None.
    """
    events = list(events)

    if not events:
        return []

    timestamps = [
        ensure_utc(event.timestamp)
        for event in events
    ]

    intervals: list[float | None] = [None]

    for previous, current in zip(
        timestamps,
        timestamps[1:],
    ):
        delta = (
            current - previous
        ).total_seconds()

        intervals.append(delta)

    return intervals


def calculate_event_rate(
    event_count: int,
    duration_seconds: float,
) -> float:
    """
    Calculate event rate as events per second.

    Returns 0.0 when the observation duration is zero
    or negative.
    """
    if duration_seconds <= 0:
        return 0.0

    return event_count / duration_seconds
