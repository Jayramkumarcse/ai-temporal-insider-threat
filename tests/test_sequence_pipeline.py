from __future__ import annotations

from datetime import date

import numpy as np

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.sequence_pipeline import prepare_sequence_datasets
from insider_threat.models.sequence_split import split_sequences_by_target_date


def test_prepare_sequence_datasets_uses_train_only_scaling() -> None:
    events = load_processed_events("data/interim/clean_events.json")

    windows = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    sequences = __import__(
        "insider_threat.models.sequence_dataset",
        fromlist=["build_user_sequences"],
    ).build_user_sequences(
        windows,
        sequence_length=6,
    )

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    datasets = prepare_sequence_datasets(
        train,
        validation,
        test,
    )

    assert datasets["train"].shape == (815, 6, 5)
    assert datasets["validation"].shape == (240, 6, 5)
    assert datasets["test"].shape == (240, 6, 5)

    assert datasets["train"].dtype == float
    assert np.isfinite(datasets["train"]).all()
    assert np.isfinite(datasets["validation"]).all()
    assert np.isfinite(datasets["test"]).all()

    # The scaler must have been fitted from TRAIN only.
    scaler = datasets["scaler"]

    assert scaler.mean_.shape == (5,)
    assert scaler.scale_.shape == (5,)

    # These values should reflect the training distribution, not
    # validation/test anomaly values.
    assert scaler.mean_[0] < 2.0
    assert scaler.mean_[1] == 0.0
    assert scaler.mean_[2] == 0.0


def test_prepare_sequence_datasets_preserves_target_anomaly_features() -> None:
    events = load_processed_events("data/interim/clean_events.json")

    windows = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    from insider_threat.models.sequence_dataset import build_user_sequences

    sequences = build_user_sequences(
        windows,
        sequence_length=6,
    )

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    datasets = prepare_sequence_datasets(
        train,
        validation,
        test,
    )

    target = next(
        sequence
        for sequence in test
        if sequence["user_id"] == "USR-003"
        and sequence["target_date"] == "2026-09-16"
        and sequence["target_window_start"]
        == "2026-09-16T02:00:00+00:00"
    )

    assert target["features"][-1] == [56, 51, 850000000, 2, 2]

    # The target itself must not be part of scaler fitting.
    assert datasets["scaler"].mean_[0] < 2.0
    assert datasets["scaler"].mean_[1] == 0.0
    assert datasets["scaler"].mean_[2] == 0.0
