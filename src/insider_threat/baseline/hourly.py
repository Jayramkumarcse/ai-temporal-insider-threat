from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Iterable

from insider_threat.preprocessing.processed_event import ProcessedEvent


HOURLY_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
    "failed_action_count",
)


def ensure_utc(timestamp: datetime) -> datetime:
    """Return a timezone-aware UTC timestamp."""

    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def build_active_hourly_lookup(
    events: Iterable[ProcessedEvent],
) -> dict[tuple[str, datetime], dict]:
    """
    Aggregate processed events into active user-hour windows.

    The key is:
        (user_id, UTC window start)

    Only hours containing events are included.
    """

    grouped: dict[
        tuple[str, datetime],
        list[ProcessedEvent],
    ] = defaultdict(list)

    for event in events:
        timestamp = ensure_utc(event.timestamp)

        window_start = timestamp.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        grouped[
            (event.user_id, window_start)
        ].append(event)

    lookup: dict[tuple[str, datetime], dict] = {}

    for (
        user_id,
        window_start,
    ), window_events in grouped.items():

        lookup[(user_id, window_start)] = {
            "user_id": user_id,
            "window_start": window_start.isoformat(),
            "window_end": (
                window_start + timedelta(hours=1)
            ).isoformat(),
            "hour_of_day": window_start.hour,
            "date": window_start.date().isoformat(),
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
        }

    return lookup


def build_dense_hourly_windows(
    events: Iterable[ProcessedEvent],
    start_date: date,
    end_date: date,
) -> list[dict]:
    """
    Build a complete user-date-hour grid.

    Every user has one record for every hour between start_date
    and end_date, inclusive.

    Hours with no activity are represented explicitly with zero
    behavioral values.
    """

    if end_date < start_date:
        raise ValueError("end_date cannot be earlier than start_date")

    events = list(events)

    users = sorted({
        event.user_id
        for event in events
    })

    active_lookup = build_active_hourly_lookup(events)

    windows: list[dict] = []

    current_date = start_date

    while current_date <= end_date:

        for user_id in users:

            for hour in range(24):

                window_start = datetime(
                    current_date.year,
                    current_date.month,
                    current_date.day,
                    hour,
                    tzinfo=timezone.utc,
                )

                active = active_lookup.get(
                    (user_id, window_start)
                )

                if active is not None:
                    windows.append(active)
                    continue

                windows.append({
                    "user_id": user_id,
                    "window_start": (
                        window_start.isoformat()
                    ),
                    "window_end": (
                        window_start + timedelta(hours=1)
                    ).isoformat(),
                    "hour_of_day": hour,
                    "date": current_date.isoformat(),
                    "event_count": 0,
                    "sensitive_access_count": 0,
                    "unique_devices": 0,
                    "unique_ips": 0,
                    "bytes_transferred": 0,
                    "failed_action_count": 0,
                })

        current_date += timedelta(days=1)

    return windows


def get_same_hour_history(
    hourly_windows: Iterable[dict],
    user_id: str,
    target_date: date,
    hour_of_day: int,
) -> list[dict]:
    """
    Return previous same-hour observations for one user.

    Only observations strictly before target_date are included.
    """

    if not 0 <= hour_of_day <= 23:
        raise ValueError("hour_of_day must be between 0 and 23")

    history = []

    for window in hourly_windows:

        if window["user_id"] != user_id:
            continue

        if window["hour_of_day"] != hour_of_day:
            continue

        window_date = date.fromisoformat(
            window["date"]
        )

        if window_date >= target_date:
            continue

        history.append(window)

    return sorted(
        history,
        key=lambda window: window["date"],
    )
