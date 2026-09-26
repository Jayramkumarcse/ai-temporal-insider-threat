from __future__ import annotations

import numpy as np
import pytest
import torch

from insider_threat.models.lstm_autoencoder import (
    LSTMSequenceAutoencoder,
    reconstruction_error,
)


def test_model_reconstructs_sequence_shape():
    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=16,
    )

    inputs = torch.randn(4, 6, 5)

    outputs = model(inputs)

    assert outputs.shape == inputs.shape


def test_model_accepts_float32_tensor():
    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=16,
    )

    inputs = torch.randn(2, 6, 5, dtype=torch.float32)

    outputs = model(inputs)

    assert outputs.dtype == torch.float32


def test_model_rejects_wrong_feature_width():
    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=16,
    )

    inputs = torch.randn(2, 6, 4)

    with pytest.raises(RuntimeError):
        model(inputs)


def test_reconstruction_error_returns_per_sequence_scores():
    predictions = torch.zeros(3, 6, 5)
    targets = torch.ones(3, 6, 5)

    scores = reconstruction_error(
        predictions,
        targets,
    )

    assert scores.shape == (3,)
    assert np.allclose(
        scores.detach().numpy(),
        np.ones(3),
    )


def test_reconstruction_error_zero_for_identical_sequences():
    values = torch.randn(3, 6, 5)

    scores = reconstruction_error(
        values,
        values,
    )

    assert torch.allclose(
        scores,
        torch.zeros(3),
    )


def test_reconstruction_error_requires_matching_shapes():
    predictions = torch.zeros(3, 6, 5)
    targets = torch.zeros(3, 5, 5)

    with pytest.raises(ValueError):
        reconstruction_error(
            predictions,
            targets,
        )
def test_model_rejects_invalid_input_size():
    with pytest.raises(ValueError):
        LSTMSequenceAutoencoder(
            input_size=0,
            hidden_size=16,
        )


def test_model_rejects_invalid_hidden_size():
    with pytest.raises(ValueError):
        LSTMSequenceAutoencoder(
            input_size=5,
            hidden_size=0,
        )


def test_model_uses_configured_hidden_size():
    model = LSTMSequenceAutoencoder(
        input_size=5,
        hidden_size=32,
    )

    assert model.hidden_size == 32
    assert model.encoder.hidden_size == 32
    assert model.decoder.in_features == 32
    assert model.decoder.out_features == 5
