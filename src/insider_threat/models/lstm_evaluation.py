from __future__ import annotations

import numpy as np
import torch

from insider_threat.models.lstm_autoencoder import (
    LSTMSequenceAutoencoder,
    reconstruction_error,
)


def sequence_reconstruction_errors(
    model: LSTMSequenceAutoencoder,
    sequences: np.ndarray,
) -> np.ndarray:
    """Return one reconstruction-error score per input sequence."""
    if sequences.ndim != 3:
        raise ValueError(
            "sequences must have shape (batch, sequence_length, features)"
        )

    if sequences.shape[0] == 0:
        raise ValueError("sequences cannot be empty")

    if sequences.shape[2] != model.input_size:
        raise ValueError(
            "sequence feature width must match model input_size"
        )

    model_was_training = model.training

    model.eval()

    try:
        inputs = torch.as_tensor(
            sequences,
            dtype=torch.float32,
        )

        with torch.no_grad():
            predictions = model(inputs)
            scores = reconstruction_error(
                predictions,
                inputs,
            )

        return scores.cpu().numpy()
    finally:
        model.train(model_was_training)


def select_reconstruction_threshold(
    validation_scores: np.ndarray,
) -> float:
    """Select an anomaly threshold using validation scores only."""
    validation_scores = np.asarray(
        validation_scores,
        dtype=float,
    )

    if validation_scores.size == 0:
        raise ValueError("validation scores cannot be empty")

    if not np.isfinite(validation_scores).all():
        raise ValueError("validation scores must be finite")

    return float(validation_scores.max())
