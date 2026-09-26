from __future__ import annotations

import torch
from torch import nn


class LSTMSequenceAutoencoder(nn.Module):
    """LSTM-based sequence autoencoder for temporal anomaly detection."""

    def __init__(
        self,
        *,
        input_size: int,
        hidden_size: int = 16,
    ) -> None:
        super().__init__()

        if input_size <= 0:
            raise ValueError("input_size must be positive")

        if hidden_size <= 0:
            raise ValueError("hidden_size must be positive")

        self.input_size = input_size
        self.hidden_size = hidden_size

        self.encoder = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            batch_first=True,
        )

        self.decoder = nn.Linear(
            hidden_size,
            input_size,
        )

    def forward(self, inputs: torch.Tensor) -> torch.Tensor:
        """Reconstruct the input sequence."""

        encoded, _ = self.encoder(inputs)

        return self.decoder(encoded)


def reconstruction_error(
    predictions: torch.Tensor,
    targets: torch.Tensor,
) -> torch.Tensor:
    """
    Calculate mean squared reconstruction error per sequence.

    Returns one anomaly score for each sequence in the batch.
    """

    if predictions.shape != targets.shape:
        raise ValueError(
            "predictions and targets must have matching shapes"
        )

    squared_error = (predictions - targets) ** 2

    return squared_error.mean(dim=(1, 2))
