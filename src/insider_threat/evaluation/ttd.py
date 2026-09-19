from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from insider_threat.baseline.hourly_scoring import (
    score_hourly_window,
)
from insider_threat.detection.composite import (
    build_composite_investigation_signal,
)
from insider_threat.detection.context import (
    calculate_security_context_signal,
)
from insider_threat.detection.temporal_score import (
    build_temporal_score,
)


def build_prefix_window(
    events: Iterable[Any],
) -> dict[str, Any]:
    """
    Build cumulative behavioral features for an event prefix.
    """

    events = list(events)

    if not events:
        raise ValueError("events cannot be empty")

    first = events[0]

    timestamps = [
        event.timestamp
        for event in events
    ]

    sensitive_count = sum(
        event.sensitive
        for event in events
    )

    bytes_transferred = sum(
        event.bytes_transferred
        for event in events
    )

    unique_devices = len(
        {
            event.device_id
            for event in events
            if event.device_id
        }
    )

    unique_ips = len(
        {
            event.source_ip
            for event in events
            if event.source_ip
        }
    )

    failed_action_count = sum(
        event.status != "success"
        for event in events
    )

    first_timestamp = timestamps[0]

    return {
        "user_id": first.user_id,
        "date": first_timestamp.date().isoformat(),
        "hour_of_day": first_timestamp.hour,
        "event_count": len(events),
        "sensitive_access_count": sensitive_count,
        "bytes_transferred": bytes_transferred,
        "unique_devices": unique_devices,
        "unique_ips": unique_ips,
        "failed_action_count": failed_action_count,
        "timestamp": timestamps[-1],
        "first_timestamp": first_timestamp,
        "events": events,
    }


def evaluate_prefix(
    prefix_window: dict[str, Any],
    historical_windows: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Score one cumulative event prefix against historical
    same-hour behavior.
    """

    scored = score_hourly_window(
        current_window=prefix_window,
        historical_windows=historical_windows,
    )

    temporal = build_temporal_score(
        scored
    )

    context = calculate_security_context_signal(
        prefix_window
    )

    composite = build_composite_investigation_signal(
        temporal_signal=temporal["temporal_score"],
        context=context,
    )

    timestamp = prefix_window["timestamp"]

    return {
        "timestamp": timestamp,
        "event_count": prefix_window["event_count"],
        "sensitive_access_count": (
            prefix_window["sensitive_access_count"]
        ),
        "bytes_transferred": (
            prefix_window["bytes_transferred"]
        ),
        "unique_devices": (
            prefix_window["unique_devices"]
        ),
        "unique_ips": (
            prefix_window["unique_ips"]
        ),
        "temporal_score": (
            temporal["temporal_score"]
        ),
        "context_signal": (
            composite["context_signal"]
        ),
        "composite_signal": (
            composite["composite_signal"]
        ),
    }


def evaluate_event_prefixes(
    events: Iterable[Any],
    historical_windows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Evaluate every cumulative event prefix.
    """

    events = sorted(
        list(events),
        key=lambda event: event.timestamp,
    )

    if not events:
        return []

    results = []

    for index in range(1, len(events) + 1):
        prefix = events[:index]

        window = build_prefix_window(
            prefix
        )

        result = evaluate_prefix(
            window,
            historical_windows,
        )

        result["event_index"] = index

        results.append(result)

    return results


def find_first_detection(
    results: Iterable[dict[str, Any]],
    threshold: float,
) -> dict[str, Any] | None:
    """
    Find the first prefix whose composite signal
    reaches the specified threshold.
    """

    if not 0.0 <= threshold <= 1.0:
        raise ValueError(
            "threshold must be between 0 and 1"
        )

    for result in results:
        if result["composite_signal"] >= threshold:
            return result

    return None


def calculate_time_to_detection(
    first_event_timestamp: datetime,
    detection_timestamp: datetime,
) -> float:
    """
    Return elapsed seconds from first observed event
    to first detection.
    """

    return (
        detection_timestamp
        - first_event_timestamp
    ).total_seconds()
