from __future__ import annotations

from datetime import datetime, timedelta


KNOWN_ANOMALY_WINDOW = "2026-09-16T02:00:00+00:00"


def locate_anomaly_in_sequence(
    *,
    target_window_start: str,
    sequence_length: int,
    anomaly_window: str = KNOWN_ANOMALY_WINDOW,
) -> int | None:
    """Return the zero-based timestep containing the known anomaly."""
    if sequence_length <= 0:
        raise ValueError("sequence_length must be positive")

    target = datetime.fromisoformat(target_window_start)
    anomaly = datetime.fromisoformat(anomaly_window)

    sequence_start = target - timedelta(hours=sequence_length - 1)

    if not sequence_start <= anomaly <= target:
        return None

    delta = anomaly - sequence_start

    return int(delta.total_seconds() // 3600)


def summarize_lstm_localization(
    target_window_starts: list[str],
    *,
    sequence_length: int = 6,
    anomaly_window: str = KNOWN_ANOMALY_WINDOW,
) -> list[dict[str, object]]:
    """Summarize where the known anomaly occurs in each overlapping sequence."""
    return [
        {
            "target_window_start": target_window_start,
            "anomaly_timestep": locate_anomaly_in_sequence(
                target_window_start=target_window_start,
                sequence_length=sequence_length,
                anomaly_window=anomaly_window,
            ),
        }
        for target_window_start in target_window_starts
    ]
