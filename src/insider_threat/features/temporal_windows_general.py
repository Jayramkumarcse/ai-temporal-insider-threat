from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from insider_threat.preprocessing.processed_event import ProcessedEvent


SUPPORTED_WINDOW_HOURS = (1, 2, 4, 6, 8, 12, 24)


def ensure_utc(timestamp: datetime) -> datetime:
    """Return a timezone-aware UTC timestamp."""

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def validate_window_hours(window_hours: int) -> None:
    """Validate supported temporal window sizes."""

    if window_hours not in SUPPORTED_WINDOW_HOURS:
        raise ValueError(
            "window_hours must be one of "
            f"{SUPPORTED_WINDOW_HOURS}"
        )


def get_window_start(
    timestamp: datetime,
    window_hours: int,
) -> datetime:
    """
    Return the aligned UTC start of a temporal window.

    Supported windows:
        1 hour: 00:00, 01:00, 02:00, ...
        2 hours: 00:00, 02:00, 04:00, ...
        4 hours: 00:00, 04:00, 08:00, ...
    """

    validate_window_hours(window_hours)

    timestamp = ensure_utc(timestamp)

    aligned_hour = (
        timestamp.hour // window_hours
    ) * window_hours

    return timestamp.replace(
        hour=aligned_hour,
        minute=0,
        second=0,
        microsecond=0,
    )


def aggregate_window_events(
    window_events: list[ProcessedEvent],
) -> dict:
    """Aggregate behavioral features for one temporal window."""

    if not window_events:
        raise ValueError(
            "window_events cannot be empty"
        )

    window_events = sorted(
        window_events,
        key=lambda event: ensure_utc(
            event.timestamp
        ),
    )

    first_timestamp = ensure_utc(
        window_events[0].timestamp
    )

    last_timestamp = ensure_utc(
        window_events[-1].timestamp
    )

    return {
        "event_count": len(window_events),

        "sensitive_access_count": sum(
            1
            for event in window_events
            if event.sensitive
        ),

        "unique_devices": len({
            event.device_id
            for event in window_events
            if event.device_id is not None
        }),

        "unique_ips": len({
            event.source_ip
            for event in window_events
            if event.source_ip is not None
        }),

        "bytes_transferred": sum(
            event.bytes_transferred
            for event in window_events
        ),

        "failed_action_count": sum(
            1
            for event in window_events
            if event.status != "success"
        ),

        "first_event_timestamp": (
            first_timestamp.isoformat()
        ),

        "last_event_timestamp": (
            last_timestamp.isoformat()
        ),
    }


def build_temporal_windows(
    events: Iterable[ProcessedEvent],
    window_hours: int,
) -> list[dict]:
    """
    Build active temporal behavioral windows.

    Windows are aligned to UTC boundaries and contain
    events for one user only.

    Only active windows are returned.
    """

    validate_window_hours(window_hours)

    grouped: dict[
        tuple[str, datetime],
        list[ProcessedEvent],
    ] = defaultdict(list)

    for event in events:

        window_start = get_window_start(
            event.timestamp,
            window_hours,
        )

        grouped[
            (event.user_id, window_start)
        ].append(event)

    windows: list[dict] = []

    for (
        user_id,
        window_start,
    ), window_events in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1],
        ),
    ):

        features = aggregate_window_events(
            window_events
        )

        window_end = (
            window_start
            + timedelta(hours=window_hours)
        )

        windows.append({
            "user_id": user_id,

            "window_hours": window_hours,

            "window_start": (
                window_start.isoformat()
            ),

            "window_end": (
                window_end.isoformat()
            ),

            "date": (
                window_start.date().isoformat()
            ),

            "window_start_hour": (
                window_start.hour
            ),

            **features,
        })

    return windows
