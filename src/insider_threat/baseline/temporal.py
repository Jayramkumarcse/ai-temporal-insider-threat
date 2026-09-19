from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Iterable

from insider_threat.features.temporal_windows_general import (
    SUPPORTED_WINDOW_HOURS,
    validate_window_hours,
)

TEMPORAL_BASELINE_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
    "failed_action_count",
)


def _parse_window_start(window: dict) -> datetime:
    return datetime.fromisoformat(window["window_start"])


def _zero_window(
    user_id: str,
    window_start: datetime,
    window_hours: int,
) -> dict:
    window_end = window_start + timedelta(hours=window_hours)

    return {
        "user_id": user_id,
        "window_hours": window_hours,
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "date": window_start.date().isoformat(),
        "window_start_hour": window_start.hour,
        "event_count": 0,
        "sensitive_access_count": 0,
        "unique_devices": 0,
        "unique_ips": 0,
        "bytes_transferred": 0,
        "failed_action_count": 0,
        "first_event_timestamp": None,
        "last_event_timestamp": None,
    }


def build_dense_temporal_windows(
    active_windows: Iterable[dict],
    users: Iterable[str],
    start_date: date,
    end_date: date,
    window_hours: int,
) -> list[dict]:
    """
    Build a dense user/date/window-position grid.

    Every user receives every anchored window slot for every date.
    Missing activity is represented by zero-valued features.
    """
    validate_window_hours(window_hours)

    if end_date < start_date:
        raise ValueError("end_date must be on or after start_date")

    users = sorted(set(users))
    active_lookup = {}

    for window in active_windows:
        if window["window_hours"] != window_hours:
            continue

        key = (
            window["user_id"],
            _parse_window_start(window),
        )
        active_lookup[key] = window

    windows_per_day = 24 // window_hours
    dense_windows = []

    current_date = start_date

    while current_date <= end_date:
        for user_id in users:
            for slot in range(windows_per_day):
                window_start = datetime(
                    current_date.year,
                    current_date.month,
                    current_date.day,
                    slot * window_hours,
                    tzinfo=timezone.utc,
                )

                key = (user_id, window_start)

                if key in active_lookup:
                    dense_windows.append(active_lookup[key])
                else:
                    dense_windows.append(
                        _zero_window(
                            user_id=user_id,
                            window_start=window_start,
                            window_hours=window_hours,
                        )
                    )

        current_date += timedelta(days=1)

    return dense_windows


def get_same_window_history(
    windows: Iterable[dict],
    user_id: str,
    target_date: date,
    window_start_hour: int,
    window_hours: int,
) -> list[dict]:
    """
    Return same-user, same-window-position history from previous dates only.
    """
    validate_window_hours(window_hours)

    history = []

    for window in windows:
        if window["user_id"] != user_id:
            continue

        if window["window_hours"] != window_hours:
            continue

        window_date = date.fromisoformat(window["date"])

        if window_date >= target_date:
            continue

        if window["window_start_hour"] != window_start_hour:
            continue

        history.append(window)

    return sorted(
        history,
        key=lambda window: (
            window["date"],
            window["window_start_hour"],
        ),
    )
