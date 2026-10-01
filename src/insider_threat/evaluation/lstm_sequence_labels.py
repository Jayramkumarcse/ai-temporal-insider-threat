from __future__ import annotations

from datetime import datetime, timedelta

from insider_threat.evaluation.labels import KNOWN_ANOMALIES


KNOWN_ANOMALY_WINDOW = "2026-09-16T02:00:00+00:00"
DEFAULT_SEQUENCE_LENGTH = 6


def label_lstm_test_sequences(
    sequences: list[dict],
    *,
    context: bool = False,
    sequence_length: int = DEFAULT_SEQUENCE_LENGTH,
) -> list[int]:
    """Return sequence-level ground-truth labels for LSTM evaluation.

    Default semantics:
        1 = exact known anomalous target window
        0 = otherwise

    Context semantics:
        1 = sequence contains the known anomalous timestep
        0 = otherwise
    """
    if sequence_length <= 0:
        raise ValueError("sequence_length must be positive")

    anomaly_window = datetime.fromisoformat(KNOWN_ANOMALY_WINDOW)
    labels = []

    for sequence in sequences:
        user_id = sequence["user_id"]
        target_window = datetime.fromisoformat(
            sequence["target_window_start"]
        )

        is_known_user_day = (
            user_id,
            target_window.date(),
        ) in KNOWN_ANOMALIES

        if context:
            context_start = target_window - timedelta(
                hours=sequence_length - 1
            )
            is_anomaly = (
                is_known_user_day
                and context_start <= anomaly_window <= target_window
            )
        else:
            is_anomaly = (
                is_known_user_day
                and target_window == anomaly_window
            )

        labels.append(int(is_anomaly))

    return labels
