from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
from torch import nn

from insider_threat.models.lstm_autoencoder import (
    LSTMSequenceAutoencoder,
)


@dataclass(frozen=True)
class LSTMTrainingConfig:
    epochs: int = 20
    learning_rate: float = 1e-3
    batch_size: int = 32
    random_seed: int = 42


def train_autoencoder(
    train_sequences: np.ndarray,
    *,
    input_size: int,
    hidden_size: int = 16,
    config: LSTMTrainingConfig | None = None,
) -> tuple[LSTMSequenceAutoencoder, dict[str, list[float]]]:
    """Train an LSTM sequence autoencoder using training sequences only."""

    if config is None:
        config = LSTMTrainingConfig()

    if train_sequences.ndim != 3:
        raise ValueError(
            "train_sequences must have shape (batch, sequence_length, features)"
        )

    if train_sequences.shape[0] == 0:
        raise ValueError("train_sequences cannot be empty")

    if train_sequences.shape[2] != input_size:
        raise ValueError("train_sequences feature width must match input_size")

    if config.epochs <= 0:
        raise ValueError("epochs must be positive")

    if config.learning_rate <= 0:
        raise ValueError("learning_rate must be positive")

    if config.batch_size <= 0:
        raise ValueError("batch_size must be positive")

    torch.manual_seed(config.random_seed)

    dataset = torch.as_tensor(
        train_sequences,
        dtype=torch.float32,
    )

    model = LSTMSequenceAutoencoder(
        input_size=input_size,
        hidden_size=hidden_size,
    )

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=config.learning_rate,
    )

    criterion = nn.MSELoss()

    history: dict[str, list[float]] = {
        "train_loss": [],
    }

    model.train()

    for _ in range(config.epochs):
        epoch_loss = 0.0
        sample_count = 0

        for start in range(0, len(dataset), config.batch_size):
            batch = dataset[start : start + config.batch_size]

            optimizer.zero_grad()

            predictions = model(batch)

            loss = criterion(predictions, batch)

            loss.backward()
            optimizer.step()

            batch_size = len(batch)
            epoch_loss += loss.item() * batch_size
            sample_count += batch_size

        history["train_loss"].append(
            epoch_loss / sample_count
        )

    return model, history
