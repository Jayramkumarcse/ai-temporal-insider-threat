from collections import Counter
from statistics import mean, median
from typing import Iterable

from insider_threat.preprocessing.processed_event import ProcessedEvent

from .temporal import (
    calculate_inter_event_seconds,
    ensure_utc,
)


def aggregate_behavioral_features(
    events: Iterable[ProcessedEvent],
) -> dict:
    """
    Aggregate a sequence of events into user-level behavioral features.

    The input events should belong to a single user and should be
    chronologically ordered.

    The function produces descriptive behavioral signals only.
    It does not classify a user as malicious.
    """
    events = list(events)

    if not events:
        return {
            "event_count": 0,
            "login_count": 0,
            "file_access_count": 0,
            "sensitive_access_count": 0,
            "unique_devices": 0,
            "unique_ips": 0,
            "bytes_transferred": 0,
            "night_activity_count": 0,
            "weekend_activity_count": 0,
            "failed_action_count": 0,
            "mean_inter_event_seconds": 0.0,
            "median_inter_event_seconds": 0.0,
            "min_inter_event_seconds": 0.0,
            "max_inter_event_seconds": 0.0,
            "event_rate": 0.0,
        }

    event_count = len(events)

    login_count = sum(
        1
        for event in events
        if event.event_type == "login"
    )

    file_access_count = sum(
        1
        for event in events
        if event.event_type == "file"
    )

    sensitive_access_count = sum(
        1
        for event in events
        if event.sensitive
    )

    unique_devices = len(
        {
            event.device_id
            for event in events
            if event.device_id is not None
        }
    )

    unique_ips = len(
        {
            event.source_ip
            for event in events
            if event.source_ip is not None
        }
    )

    bytes_transferred = sum(
        event.bytes_transferred
        for event in events
    )

    night_activity_count = sum(
        1
        for event in events
        if ensure_utc(event.timestamp).hour < 6
    )

    weekend_activity_count = sum(
        1
        for event in events
        if ensure_utc(event.timestamp).weekday() >= 5
    )

    failed_action_count = sum(
        1
        for event in events
        if event.status == "failure"
    )

    intervals = calculate_inter_event_seconds(events)

    valid_intervals = [
        interval
        for interval in intervals
        if interval is not None
    ]

    if valid_intervals:
        mean_inter_event_seconds = mean(valid_intervals)
        median_inter_event_seconds = median(valid_intervals)
        min_inter_event_seconds = min(valid_intervals)
        max_inter_event_seconds = max(valid_intervals)
    else:
        mean_inter_event_seconds = 0.0
        median_inter_event_seconds = 0.0
        min_inter_event_seconds = 0.0
        max_inter_event_seconds = 0.0

    if len(events) >= 2:
        duration_seconds = (
            ensure_utc(events[-1].timestamp)
            - ensure_utc(events[0].timestamp)
        ).total_seconds()

        event_rate = (
            (event_count - 1) / duration_seconds
            if duration_seconds > 0
            else 0.0
        )
    else:
        event_rate = 0.0

    return {
        "event_count": event_count,
        "login_count": login_count,
        "file_access_count": file_access_count,
        "sensitive_access_count": sensitive_access_count,
        "unique_devices": unique_devices,
        "unique_ips": unique_ips,
        "bytes_transferred": bytes_transferred,
        "night_activity_count": night_activity_count,
        "weekend_activity_count": weekend_activity_count,
        "failed_action_count": failed_action_count,
        "mean_inter_event_seconds": mean_inter_event_seconds,
        "median_inter_event_seconds": median_inter_event_seconds,
        "min_inter_event_seconds": min_inter_event_seconds,
        "max_inter_event_seconds": max_inter_event_seconds,
        "event_rate": event_rate,
    }
