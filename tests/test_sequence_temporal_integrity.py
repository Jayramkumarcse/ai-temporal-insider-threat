from datetime import datetime, timezone

import pytest

from insider_threat.models.sequence_dataset import build_user_sequences


def make_window(
    user_id: str,
    window_start: str,
    event_count: int = 0,
) -> dict:
    return {
        "user_id": user_id,
        "date": window_start[:10],
        "window_hours": 1,
        "window_start_hour": int(window_start[11:13]),
        "window_start": window_start,
        "window_end": window_start,
        "event_count": event_count,
        "sensitive_access_count": 0,
        "bytes_transferred": 0,
        "unique_devices": 0,
        "unique_ips": 0,
    }


def test_sequences_do_not_cross_user_boundaries():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T{hour:02d}:00:00+00:00",
        )
        for hour in range(6)
    ]

    windows += [
        make_window(
            "USR-002",
            f"2026-09-01T{hour:02d}:00:00+00:00",
        )
        for hour in range(6)
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=6,
    )

    assert len(sequences) == 2
    assert {
        sequence["user_id"]
        for sequence in sequences
    } == {"USR-001", "USR-002"}


def test_sequence_windows_are_chronological():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T{hour:02d}:00:00+00:00",
            event_count=hour,
        )
        for hour in range(6)
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=6,
    )

    assert len(sequences) == 1

    features = sequences[0]["features"]

    assert [row[0] for row in features] == [0, 1, 2, 3, 4, 5]


def test_sequence_does_not_cross_missing_hour():
    windows = [
        make_window("USR-001", "2026-09-01T00:00:00+00:00"),
        make_window("USR-001", "2026-09-01T01:00:00+00:00"),
        make_window("USR-001", "2026-09-01T02:00:00+00:00"),
        make_window("USR-001", "2026-09-01T04:00:00+00:00"),
        make_window("USR-001", "2026-09-01T05:00:00+00:00"),
        make_window("USR-001", "2026-09-01T06:00:00+00:00"),
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=6,
    )

    assert sequences == []


def test_sequence_length_is_exact():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T{hour:02d}:00:00+00:00",
        )
        for hour in range(8)
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=6,
    )

    assert len(sequences) == 3

    for sequence in sequences:
        assert len(sequence["features"]) == 6
        assert all(
            len(row) == 5
            for row in sequence["features"]
        )
