from __future__ import annotations

from typing import Iterable

import numpy as np
from sklearn.preprocessing import StandardScaler

from insider_threat.models.sequence_scaling import (
    fit_sequence_scaler,
    transform_sequences,
)
from insider_threat.models.sequence_tensor import sequence_features_to_array


def prepare_sequence_datasets(
    train_sequences: Iterable[dict],
    validation_sequences: Iterable[dict],
    test_sequences: Iterable[dict],
) -> dict[str, np.ndarray | StandardScaler]:
    """Scale and convert train/validation/test sequences.

    The scaler is fitted exclusively on training sequences and then reused
    unchanged for validation and test sequences.
    """
    train_sequences = list(train_sequences)
    validation_sequences = list(validation_sequences)
    test_sequences = list(test_sequences)

    scaler = fit_sequence_scaler(train_sequences)

    train_scaled = transform_sequences(
        train_sequences,
        scaler,
    )
    validation_scaled = transform_sequences(
        validation_sequences,
        scaler,
    )
    test_scaled = transform_sequences(
        test_sequences,
        scaler,
    )

    return {
        "train": sequence_features_to_array(train_scaled),
        "validation": sequence_features_to_array(validation_scaled),
        "test": sequence_features_to_array(test_scaled),
        "scaler": scaler,
    }
