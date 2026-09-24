from __future__ import annotations

from datetime import date
from typing import Iterable


DEFAULT_SEQUENCE_LENGTH = 6

SEQUENCE_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "bytes_transferred",
    "unique_devices",
    "unique_ips",
)


def validate_sequence_length(sequence_length: int) -> None:
    if sequence_length <= 0:
        raise ValueError("sequence_length must be positive")


def build_user_sequences(
    windows: Iterable[dict],
    *,
    sequence_length: int = DEFAULT_SEQUENCE_LENGTH,
    target_date: date | None = None,
) -> list[dict]:
    """
    Build chronological fixed-length sequences from temporal windows.

    Windows are grouped by user and ordered chronologically.

    Each sequence contains only historical/current windows and does
    not cross user boundaries.

    If target_date is provided, only sequences whose target window
    belongs
    to that date are returned.
    """
    validate_sequence_length(sequence_length)

    grouped: dict[str, list[dict]] = {}

    for window in windows:
        user_id = window["user_id"]
        grouped.setdefault(user_id, []).append(window)

    sequences = []

    for user_id, user_windows in sorted(grouped.items()):
        ordered = sorted(
            user_windows,
            key=lambda window: window["window_start"],
        )

        for index in range(sequence_length - 1, len(ordered)):
            sequence_windows = ordered[
                index - sequence_length + 1 : index + 1
            ]

            target_window = sequence_windows[-1]

            if target_date is not None:
                window_date = date.fromisoformat(
                    target_window["date"]
                )
                if window_date != target_date:
                    continue

            features = [
                [
                    window[feature]
                    for feature in SEQUENCE_FEATURES
                ]
                for window in sequence_windows
            ]

            sequences.append(
                {
                    "user_id": user_id,
                    "target_date": target_window["date"],
                    "target_window_start": target_window[
                        "window_start"
                    ],
                    "window_hours": target_window["window_hours"],
                    "features": features,
                    "target_window": target_window,
                }
            )

    return sequences
