from __future__ import annotations

import numpy as np
import pytest

from insider_threat.models.sequence_tensor import (
    sequence_features_to_array,
)


def make_sequence(
    values: list[list[float]],
    *,
    user_id: str = "USR-001",
) -> dict:
    return {
        "user_id": user_id,
        "target_date": "2026-09-01",
        "target_window_start": "2026-09-01T00:00:00+00:00",
        "window_hours": 1,
        "features": values,
    }


def test_sequence_features_to_array_shape() -> None:
    sequences = [
        make_sequence(
            [
                [1.0, 2.0, 3.0, 4.0, 5.0],
                [2.0, 3.0, 4.0, 5.0, 6.0],
            ]
        ),
        make_sequence(
            [
                [3.0, 4.0, 5.0, 6.0, 7.0],
                [4.0, 5.0, 6.0, 7.0, 8.0],
            ],
            user_id="USR-002",
        ),
    ]

    array = sequence_features_to_array(sequences)

    assert isinstance(array, np.ndarray)
    assert array.shape == (2, 2, 5)
    assert array.dtype == np.float64


def test_sequence_features_to_array_preserves_values() -> None:
    sequences = [
        make_sequence(
            [
                [1.5, 2.5, 3.5, 4.5, 5.5],
                [6.5, 7.5, 8.5, 9.5, 10.5],
            ]
        )
    ]

    array = sequence_features_to_array(sequences)

    expected = np.asarray(
        sequences[0]["features"],
        dtype=float,
    )

    np.testing.assert_array_equal(
        array[0],
        expected,
    )


def test_empty_sequences_raise() -> None:
    with pytest.raises(
        ValueError,
        match="cannot convert empty sequences",
    ):
        sequence_features_to_array([])


def test_inconsistent_sequence_lengths_raise() -> None:
    sequences = [
        make_sequence(
            [
                [1.0, 2.0, 3.0, 4.0, 5.0],
                [2.0, 3.0, 4.0, 5.0, 6.0],
            ]
        ),
        make_sequence(
            [
                [3.0, 4.0, 5.0, 6.0, 7.0],
            ],
            user_id="USR-002",
        ),
    ]

    with pytest.raises(
        ValueError,
        match="same sequence length",
    ):
        sequence_features_to_array(sequences)


def test_inconsistent_feature_width_raises() -> None:
    sequences = [
        make_sequence(
            [
                [1.0, 2.0, 3.0, 4.0, 5.0],
            ]
        ),
        make_sequence(
            [
                [1.0, 2.0, 3.0],
            ],
            user_id="USR-002",
        ),
    ]

    with pytest.raises(
        ValueError,
        match="same feature width",
    ):
        sequence_features_to_array(sequences)
