from __future__ import annotations

import numpy as np
import pytest
import torch

from insider_threat.models.lstm_autoencoder import (
    LSTMSequenceAutoencoder,
)
from insider_threat.models.lstm_evaluation import (
    select_reconstruction_threshold,
    sequence_reconstruction_errors,
)


def test_sequence_reconstruction_errors_returns_one_score_per_sequence() -> None:
    torch.manual_seed(42)

    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=16,
    )

    sequences = np.random.default_rng(42).normal(
        size=(8, 6, 5),
    ).astype(np.float32)

    scores = sequence_reconstruction_errors(
        model,
        sequences,
    )

    assert scores.shape == (8,)
    assert np.isfinite(scores).all()


def test_sequence_reconstruction_errors_does_not_change_model_training_state() -> None:
    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=16,
    )

    model.train()

    sequences = np.zeros(
        (4, 6, 5),
        dtype=np.float32,
    )

    sequence_reconstruction_errors(
        model,
        sequences,
    )

    assert model.training is True


def test_threshold_uses_validation_scores_only() -> None:
    validation_scores = np.array(
        [0.10, 0.20, 0.15, 0.30],
        dtype=float,
    )

    threshold = select_reconstruction_threshold(
        validation_scores,
    )

    assert threshold == pytest.approx(0.30)


def test_threshold_rejects_empty_validation_scores() -> None:
    with pytest.raises(ValueError, match="empty"):
        select_reconstruction_threshold(
            np.array([], dtype=float),
        )


def test_threshold_rejects_non_finite_scores() -> None:
    with pytest.raises(ValueError, match="finite"):
        select_reconstruction_threshold(
            np.array([0.1, np.inf]),
        )
