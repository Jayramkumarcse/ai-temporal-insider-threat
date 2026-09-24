from __future__ import annotations

from typing import Iterable

import numpy as np
from sklearn.preprocessing import StandardScaler

from insider_threat.models.sequence_dataset import SEQUENCE_FEATURES


def fit_sequence_scaler(
    sequences: Iterable[dict],
) -> StandardScaler:
    """
    Fit a StandardScaler using only the supplied training sequences.

    Every timestep from every sequence contributes to the feature-wise
    training distribution.
    """
    sequences = list(sequences)

    if not sequences:
        raise ValueError("cannot fit scaler on empty sequences")

    values = []

    for sequence in sequences:
        features = sequence["features"]

        if len(features) == 0:
            raise ValueError("sequence must contain at least one timestep")

        values.extend(features)

    matrix = np.asarray(values, dtype=float)

    if matrix.ndim != 2:
        raise ValueError("sequence features must form a 2D matrix")

    if matrix.shape[1] != len(SEQUENCE_FEATURES):
        raise ValueError(
            "sequence feature width does not match SEQUENCE_FEATURES"
        )

    scaler = StandardScaler()
    scaler.fit(matrix)

    return scaler


def transform_sequences(
    sequences: Iterable[dict],
    scaler: StandardScaler,
) -> list[dict]:
    """
    Transform sequence features using an already-fitted scaler.

    The input sequences are not mutated.
    """
    transformed = []

    for sequence in sequences:
        features = sequence["features"]

        matrix = np.asarray(features, dtype=float)

        if matrix.ndim != 2:
            raise ValueError("sequence features must form a 2D matrix")

        if matrix.shape[1] != len(SEQUENCE_FEATURES):
            raise ValueError(
                "sequence feature width does not match SEQUENCE_FEATURES"
            )

        scaled = scaler.transform(matrix)

        transformed_sequence = dict(sequence)
        transformed_sequence["features"] = scaled.tolist()

        transformed.append(transformed_sequence)

    return transformed
