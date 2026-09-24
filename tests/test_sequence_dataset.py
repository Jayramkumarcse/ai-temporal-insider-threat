from datetime import date


from insider_threat.models.sequence_dataset import (
    SEQUENCE_FEATURES,
    build_user_sequences,
    validate_sequence_length,
)


def make_window(
    user_id: str,
    window_start: str,
    value: int,
) -> dict:
    return {
        "user_id": user_id,
        "window_hours": 1,
        "window_start": window_start,
        "window_end": window_start,
        "date": window_start[:10],
        "window_start_hour": int(window_start[11:13]),
        "event_count": value,
        "sensitive_access_count": value + 1,
        "unique_devices": 1,
        "unique_ips": 1,
        "bytes_transferred": value * 10,
        "failed_action_count": 0,
    }


def test_validate_sequence_length_rejects_non_positive():
    try:
        validate_sequence_length(0)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError")


def test_builds_fixed_length_chronological_sequence():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T0{hour}:00:00+00:00",
            hour,
        )
        for hour in range(6)
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=3,
    )

    assert len(sequences) == 4

    sequence = sequences[0]

    assert sequence["user_id"] == "USR-001"
    assert len(sequence["features"]) == 3
    assert len(sequence["features"][0]) == len(
        SEQUENCE_FEATURES
    )

    assert sequence["target_window_start"] == (
        "2026-09-01T02:00:00+00:00"
    )


def test_does_not_mix_users():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T0{hour}:00:00+00:00",
            hour,
        )
        for hour in range(3)
    ]

    windows.extend(
        make_window(
            "USR-002",
            f"2026-09-01T0{hour}:00:00+00:00",
            hour,
        )
        for hour in range(3)
    )

    sequences = build_user_sequences(
        windows,
        sequence_length=3,
    )

    assert len(sequences) == 2
    assert {
        sequence["user_id"]
        for sequence in sequences
    } == {"USR-001", "USR-002"}


def test_target_date_filters_target_window():
    windows = []

    for day in range(1, 3):
        for hour in range(3):
            windows.append(
                make_window(
                    "USR-001",
                    f"2026-09-{day:02d}T{hour:02d}:00:00+00:00",
                    hour,
                )
            )

    sequences = build_user_sequences(
        windows,
        sequence_length=3,
        target_date=date(2026, 9, 2),
    )

    assert len(sequences) == 3

    assert all(
        sequence["target_date"] == "2026-09-02"
        for sequence in sequences
    )


def test_sequence_is_chronological():
    windows = [
        make_window(
            "USR-001",
            f"2026-09-01T0{hour}:00:00+00:00",
            hour,
        )
        for hour in reversed(range(4))
    ]

    sequences = build_user_sequences(
        windows,
        sequence_length=3,
    )

    assert sequences[0]["features"][0][0] == 0
    assert sequences[0]["features"][1][0] == 1
    assert sequences[0]["features"][2][0] == 2
