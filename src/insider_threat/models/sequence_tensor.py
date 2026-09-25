from __future__ import annotations

from typing import Iterable

import numpy as np

from insider_threat.models.sequence_dataset import SEQUENCE_FEATURES


def sequence_features_to_array(
    sequences: Iterable[dict],
) -> np.ndarray:
    """
    Convert sequence feature lists into a 3D NumPy array.

    The resulting shape is:

        (batch, sequence_length, feature_count)

    All sequences must have the same sequence length and
    feature width.
    """
    sequences = list(sequences)

    if not sequences:
        raise ValueError("cannot convert empty sequences")

    sequence_lengths = {
        len(sequence["features"])
        for sequence in sequences
    }

    if len(sequence_lengths) != 1:
        raise ValueError(
            "all sequences must have the same sequence length"
        )

    feature_widths = {
        len(timestep)
        for sequence in sequences
        for timestep in sequence["features"]
    }

    if feature_widths != {len(SEQUENCE_FEATURES)}:
        raise ValueError(
            "all sequences must have the same feature width"
        )

    return np.asarray(
        [
            sequence["features"]
            for sequence in sequences
        ],
        dtype=float,
    )
