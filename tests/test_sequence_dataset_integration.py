from datetime import date
from pathlib import Path

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.sequence_dataset import (
    SEQUENCE_FEATURES,
    build_user_sequences,
)


def _build_target_date_sequences():
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

    return build_user_sequences(
        results,
        sequence_length=6,
        target_date=date(2026, 9, 16),
    )


def test_real_dataset_builds_expected_sequence_count():
    sequences = _build_target_date_sequences()

    assert len(sequences) == 120
    assert all(len(sequence["features"]) == 6 for sequence in sequences)
    assert all(
        len(row) == len(SEQUENCE_FEATURES)
        for sequence in sequences
        for row in sequence["features"]
    )


def test_usr003_target_window_contains_injected_anomaly():
    sequences = _build_target_date_sequences()

    target = next(
        sequence
        for sequence in sequences
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


def test_usr003_sequence_is_chronological():
    sequences = _build_target_date_sequences()

    target = next(
        sequence
        for sequence in sequences
        if (
            sequence["user_id"] == "USR-003"
            and sequence["target_window_start"]
            == "2026-09-16T02:00:00+00:00"
        )
    )

    timestamps = [
        sequence["target_window_start"]
        for sequence in [target]
    ]

    assert timestamps == [
        "2026-09-16T02:00:00+00:00"
    ]
