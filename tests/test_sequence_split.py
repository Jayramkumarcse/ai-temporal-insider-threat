from __future__ import annotations

from datetime import date

import pytest

from insider_threat.models.sequence_split import (
    split_sequences_by_target_date,
)


def _sequence(target_date: str, user_id: str = "USR-001") -> dict:
    return {
        "user_id": user_id,
        "target_date": target_date,
        "target_window_start": f"{target_date}T02:00:00+00:00",
        "window_hours": 1,
        "features": [[0, 0, 0, 1, 1]] * 6,
    }


def test_split_sequences_by_target_date():
    sequences = [
        _sequence("2026-09-10"),
        _sequence("2026-09-13"),
        _sequence("2026-09-15"),
    ]

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    assert len(train) == 1
    assert len(validation) == 1
    assert len(test) == 1

    assert train[0]["target_date"] == "2026-09-10"
    assert validation[0]["target_date"] == "2026-09-13"
    assert test[0]["target_date"] == "2026-09-15"


def test_split_is_chronological_and_disjoint():
    sequences = [
        _sequence("2026-09-15"),
        _sequence("2026-09-06"),
        _sequence("2026-09-13"),
        _sequence("2026-09-12"),
    ]

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    assert [item["target_date"] for item in train] == [
        "2026-09-06",
        "2026-09-12",
    ]

    assert [item["target_date"] for item in validation] == [
        "2026-09-13",
    ]

    assert [item["target_date"] for item in test] == [
        "2026-09-15",
    ]


def test_split_rejects_overlapping_boundaries():
    sequences = [_sequence("2026-09-10")]

    with pytest.raises(ValueError):
        split_sequences_by_target_date(
            sequences,
            train_end=date(2026, 9, 14),
            validation_end=date(2026, 9, 12),
        )


def test_real_dataset_split_keeps_target_anomaly_in_test():
    from pathlib import Path

    from insider_threat.evaluation.temporal_window_experiments import (
        build_temporal_window_experiment_results,
    )
    from insider_threat.features.builder import load_processed_events
    from insider_threat.models.sequence_dataset import build_user_sequences

    events = load_processed_events(
        Path("data/interim/clean_events.json")
    )

    results = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    sequences = build_user_sequences(
        results,
        sequence_length=6,
    )

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    assert train
    assert validation
    assert test

    assert all(
        date.fromisoformat(sequence["target_date"])
        <= date(2026, 9, 12)
        for sequence in train
    )

    assert all(
        date(2026, 9, 12)
        < date.fromisoformat(sequence["target_date"])
        <= date(2026, 9, 14)
        for sequence in validation
    )

    assert all(
        date.fromisoformat(sequence["target_date"])
        > date(2026, 9, 14)
        for sequence in test
    )

    target = next(
        sequence
        for sequence in test
        if (
            sequence["user_id"] == "USR-003"
            and sequence["target_window_start"]
            == "2026-09-16T02:00:00+00:00"
        )
    )

    assert target["features"][-1] == [
        56,
        51,
        850000000,
        2,
        2,
    ]
