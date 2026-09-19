from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from insider_threat.preprocessing.processed_event import ProcessedEvent


def ensure_utc(timestamp: datetime) -> datetime:
    """Return a timezone-aware UTC timestamp."""

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def get_hour_window_start(timestamp: datetime) -> datetime:
    """Return the UTC start timestamp of the event's one-hour window."""

    timestamp = ensure_utc(timestamp)

    return timestamp.replace(
        minute=0,
        second=0,
        microsecond=0,
    )


def group_events_by_hour(
    events: Iterable[ProcessedEvent],
) -> dict[tuple[str, datetime], list[ProcessedEvent]]:
    """
    Group events into active user-hour windows.

    Only windows containing at least one event are created.
    """

    grouped: dict[
        tuple[str, datetime],
        list[ProcessedEvent],
    ] = defaultdict(list)

    for event in events:

        window_start = get_hour_window_start(
            event.timestamp
        )

        grouped[
            (event.user_id, window_start)
        ].append(event)

    return dict(grouped)


def build_hourly_windows(
    events: Iterable[ProcessedEvent],
) -> list[dict]:
    """Build one-hour behavioral windows."""

    grouped = group_events_by_hour(events)

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

        windows.append(
            {
                "user_id": user_id,
                "window_start": (
                    window_start.isoformat()
                ),
                "window_end": (
                    window_start + timedelta(hours=1)
                ).isoformat(),
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
        )

    return windows
