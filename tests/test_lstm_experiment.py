from datetime import date

import numpy as np

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.lstm_evaluation import (
    select_reconstruction_threshold,
    sequence_reconstruction_errors,
)
from insider_threat.models.sequence_dataset import build_user_sequences
from insider_threat.models.sequence_pipeline import prepare_sequence_datasets
from insider_threat.models.sequence_split import split_sequences_by_target_date
from insider_threat.models.lstm_training import train_autoencoder


def test_lstm_experiment_pipeline_produces_test_scores() -> None:
    events = load_processed_events("data/interim/clean_events.json")

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

    datasets = prepare_sequence_datasets(
        train,
        validation,
        test,
    )

    model, history = train_autoencoder(
        datasets["train"],
        input_size=5,
        hidden_size=16,
    )

    validation_scores = sequence_reconstruction_errors(
        model,
        datasets["validation"],
    )

    threshold = select_reconstruction_threshold(validation_scores)

    test_scores = sequence_reconstruction_errors(
        model,
        datasets["test"],
    )

    test_flags = test_scores > threshold

    assert datasets["train"].shape == (815, 6, 5)
    assert datasets["validation"].shape == (240, 6, 5)
    assert datasets["test"].shape == (240, 6, 5)

    assert len(history["train_loss"]) == 20
    assert validation_scores.shape == (240,)
    assert test_scores.shape == (240,)
    assert test_flags.shape == (240,)

    assert np.isfinite(validation_scores).all()
    assert np.isfinite(test_scores).all()
    assert np.isfinite(threshold)

    assert threshold == validation_scores.max()

    # Locate the known injected anomaly in the held-out test set.
            # Locate the known injected anomaly in the held-out test set.
    target_index = next(
        index
        for index, sequence in enumerate(test)
        if (
            sequence["user_id"] == "USR-003"
            and sequence["target_window_start"]
            == "2026-09-16T02:00:00+00:00"
        )
    )

    target_score = float(test_scores[target_index])

    assert np.isfinite(target_score)
    assert target_score > threshold
    assert bool(test_flags[target_index])
