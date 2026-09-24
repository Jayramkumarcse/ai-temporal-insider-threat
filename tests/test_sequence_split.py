from datetime import date


from insider_threat.evaluation.sequence_split import (
    split_sequences_by_date,
)


def make_sequence(target_date: str, user_id: str = "USR-001"):
    return {
        "user_id": user_id,
        "target_date": target_date,
        "target_window_start": (
            f"{target_date}T02:00:00+00:00"
        ),
        "window_hours": 1,
        "features": [
            [0, 0, 0, 0, 0],
        ],
    }


def test_sequences_are_split_chronologically():
    sequences = [
        make_sequence("2026-09-06"),
        make_sequence("2026-09-12"),
        make_sequence("2026-09-13"),
        make_sequence("2026-09-14"),
        make_sequence("2026-09-15"),
        make_sequence("2026-09-16"),
    ]

    splits = split_sequences_by_date(sequences)

    assert len(splits["train"]) == 2
    assert len(splits["validation"]) == 2
    assert len(splits["test"]) == 2

    assert {
        sequence["target_date"]
        for sequence in splits["train"]
    } == {
        "2026-09-06",
        "2026-09-12",
    }

    assert {
        sequence["target_date"]
        for sequence in splits["validation"]
    } == {
        "2026-09-13",
        "2026-09-14",
    }

    assert {
        sequence["target_date"]
        for sequence in splits["test"]
    } == {
        "2026-09-15",
        "2026-09-16",
    }


def test_known_anomaly_date_is_in_test_split():
    sequences = [
        make_sequence("2026-09-12"),
        make_sequence(
            "2026-09-16",
            user_id="USR-003",
        ),
    ]

    splits = split_sequences_by_date(sequences)

    assert len(splits["train"]) == 1
    assert len(splits["validation"]) == 0
    assert len(splits["test"]) == 1

    target = splits["test"][0]

    assert target["user_id"] == "USR-003"
    assert target["target_date"] == "2026-09-16"


def test_split_does_not_mix_target_dates():
    sequences = [
        make_sequence("2026-09-10"),
        make_sequence("2026-09-13"),
        make_sequence("2026-09-16"),
    ]

    splits = split_sequences_by_date(sequences)

    train_dates = {
        sequence["target_date"]
        for sequence in splits["train"]
    }

    validation_dates = {
        sequence["target_date"]
        for sequence in splits["validation"]
    }

    test_dates = {
        sequence["target_date"]
        for sequence in splits["test"]
    }

    assert train_dates.isdisjoint(validation_dates)
    assert train_dates.isdisjoint(test_dates)
    assert validation_dates.isdisjoint(test_dates)


def test_invalid_date_boundaries_are_rejected():
    sequences = []

    try:
        split_sequences_by_date(
            sequences,
            train_end_date=date(2026, 9, 14),
            validation_end_date=date(2026, 9, 12),
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError"
        )
