from insider_threat.evaluation.lstm_sequence_labels import (
    label_lstm_test_sequences,
)


def test_only_exact_known_anomaly_window_is_positive() -> None:
    sequences = [
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T01:00:00+00:00",
        },
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T02:00:00+00:00",
        },
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T03:00:00+00:00",
        },
        {
            "user_id": "USR-001",
            "target_window_start": "2026-09-16T02:00:00+00:00",
        },
    ]

    labels = label_lstm_test_sequences(sequences)

    assert labels == [0, 1, 0, 0]


def test_sequence_context_label_marks_windows_containing_known_anomaly() -> None:
    sequences = [
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T02:00:00+00:00",
            "window_starts": [
                "2026-09-15T22:00:00+00:00",
                "2026-09-15T23:00:00+00:00",
                "2026-09-16T00:00:00+00:00",
                "2026-09-16T01:00:00+00:00",
                "2026-09-16T02:00:00+00:00",
                "2026-09-16T03:00:00+00:00",
            ],
        },
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T03:00:00+00:00",
            "window_starts": [
                "2026-09-15T23:00:00+00:00",
                "2026-09-16T00:00:00+00:00",
                "2026-09-16T01:00:00+00:00",
                "2026-09-16T02:00:00+00:00",
                "2026-09-16T03:00:00+00:00",
                "2026-09-16T04:00:00+00:00",
            ],
        },
        {
            "user_id": "USR-001",
            "target_window_start": "2026-09-16T02:00:00+00:00",
            "window_starts": [
                "2026-09-15T22:00:00+00:00",
                "2026-09-15T23:00:00+00:00",
                "2026-09-16T00:00:00+00:00",
                "2026-09-16T01:00:00+00:00",
                "2026-09-16T02:00:00+00:00",
                "2026-09-16T03:00:00+00:00",
            ],
        },
    ]

    labels = label_lstm_test_sequences(
        sequences,
        context=True,
    )

    assert labels == [1, 1, 0]


def test_sequence_context_labels_cover_sliding_windows() -> None:
    sequences = [
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T02:00:00+00:00",
            "sequence_length": 6,
        },
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T03:00:00+00:00",
            "sequence_length": 6,
        },
        {
            "user_id": "USR-003",
            "target_window_start": "2026-09-16T04:00:00+00:00",
            "sequence_length": 6,
        },
        {
            "user_id": "USR-001",
            "target_window_start": "2026-09-16T04:00:00+00:00",
            "sequence_length": 6,
        },
    ]

    labels = label_lstm_test_sequences(
        sequences,
        context=True,
    )

    assert labels == [1, 1, 1, 0]
