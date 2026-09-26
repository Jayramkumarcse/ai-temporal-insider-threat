from __future__ import annotations

import numpy as np
import pytest
import torch

from insider_threat.models.lstm_autoencoder import LSTMSequenceAutoencoder
from insider_threat.models.lstm_training import (
    LSTMTrainingConfig,
    train_autoencoder,
)


def test_training_config_has_expected_defaults():
    config = LSTMTrainingConfig()

    assert config.epochs == 20
    assert config.learning_rate == 1e-3
    assert config.batch_size == 32
    assert config.random_seed == 42


def test_training_returns_model_and_history():
    rng = np.random.default_rng(42)
    train_sequences = rng.normal(size=(16, 6, 5)).astype(np.float32)

    config = LSTMTrainingConfig(
        epochs=2,
        batch_size=8,
        random_seed=42,
    )

    model, history = train_autoencoder(
        train_sequences,
        input_size=5,
        hidden_size=16,
        config=config,
    )

    assert isinstance(model, LSTMSequenceAutoencoder)
    assert len(history["train_loss"]) == 2
    assert all(np.isfinite(history["train_loss"]))


def test_training_loss_is_recorded():
    rng = np.random.default_rng(42)
    train_sequences = rng.normal(size=(16, 6, 5)).astype(np.float32)

    config = LSTMTrainingConfig(
        epochs=3,
        batch_size=8,
        random_seed=42,
    )

    _, history = train_autoencoder(
        train_sequences,
        input_size=5,
        hidden_size=16,
        config=config,
    )

    assert history["train_loss"][0] >= 0
    assert history["train_loss"][-1] >= 0


def test_training_rejects_empty_dataset():
    config = LSTMTrainingConfig(epochs=2)

    with pytest.raises(ValueError):
        train_autoencoder(
            np.empty((0, 6, 5), dtype=np.float32),
            input_size=5,
            hidden_size=16,
            config=config,
        )


def test_training_rejects_wrong_feature_width():
    config = LSTMTrainingConfig(epochs=2)

    with pytest.raises(ValueError):
        train_autoencoder(
            np.zeros((8, 6, 4), dtype=np.float32),
            input_size=5,
            hidden_size=16,
            config=config,
        )


def test_training_loss_decreases_on_reconstructable_data():
    rng = np.random.default_rng(42)

    base = rng.normal(
        size=(8, 6, 5),
    ).astype(np.float32)

    train_sequences = np.repeat(
        base[:1],
        repeats=16,
        axis=0,
    )

    config = LSTMTrainingConfig(
        epochs=20,
        batch_size=8,
        learning_rate=1e-2,
        random_seed=42,
    )

    _, history = train_autoencoder(
        train_sequences,
        input_size=5,
        hidden_size=16,
        config=config,
    )

    assert history["train_loss"][-1] < history["train_loss"][0]
