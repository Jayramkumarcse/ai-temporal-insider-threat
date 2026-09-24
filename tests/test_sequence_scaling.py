from __future__ import annotations

import pytest

from insider_threat.models.sequence_scaling import (
    fit_sequence_scaler,
    transform_sequences,
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


def test_scaler_is_fit_from_training_sequences_only() -> None:
    train = [
        make_sequence(
            [
                [1, 0, 0, 1, 1],
                [3, 0, 0, 1, 1],
            ]
        )
    ]

    validation = [
        make_sequence(
            [
                [100, 50, 1000, 2, 2],
                [200, 60, 2000, 3, 3],
            ]
        )
    ]

    scaler = fit_sequence_scaler(train)

    transformed = transform_sequences(validation, scaler)

    assert scaler.mean_[0] == 2.0
    assert transformed[0]["features"][0][0] == pytest.approx(98.0)


def test_transform_preserves_sequence_shape() -> None:
    sequences = [
        make_sequence(
            [
                [1, 0, 0, 1, 1],
                [2, 0, 0, 1, 1],
                [3, 0, 0, 1, 1],
            ]
        )
    ]

    scaler = fit_sequence_scaler(sequences)
    transformed = transform_sequences(sequences, scaler)

    assert len(transformed) == 1
    assert len(transformed[0]["features"]) == 3
    assert len(transformed[0]["features"][0]) == 5


def test_transform_does_not_mutate_input() -> None:
    sequences = [
        make_sequence(
            [
                [1, 0, 0, 1, 1],
                [2, 0, 0, 1, 1],
            ]
        )
    ]

    original = [
        row[:] for row in sequences[0]["features"]
    ]

    scaler = fit_sequence_scaler(sequences)
    transform_sequences(sequences, scaler)

    assert sequences[0]["features"] == original


def test_empty_training_sequences_raise() -> None:
    with pytest.raises(ValueError, match="empty sequences"):
        fit_sequence_scaler([])


def test_feature_width_must_match() -> None:
    invalid = [
        make_sequence(
            [
                [1, 2, 3],
            ]
        )
    ]

    with pytest.raises(
        ValueError,
        match="feature width does not match",
    ):
        fit_sequence_scaler(invalid)


def test_transformation_rejects_invalid_feature_width() -> None:
    valid = [
        make_sequence(
            [
                [1, 0, 0, 1, 1],
            ]
        )
    ]

    invalid = [
        make_sequence(
            [
                [1, 2, 3],
            ]
        )
    ]

    scaler = fit_sequence_scaler(valid)

    with pytest.raises(
        ValueError,
        match="feature width does not match",
    ):
        transform_sequences(invalid, scaler)


def test_train_scaler_is_reused_for_validation_and_test() -> None:
    train = [
        make_sequence(
            [
                [1, 0, 0, 1, 1],
                [3, 0, 0, 1, 1],
            ]
        )
    ]

    validation = [
        make_sequence(
            [
                [5, 0, 0, 1, 1],
            ]
        )
    ]

    test = [
        make_sequence(
            [
                [7, 0, 0, 1, 1],
            ]
        )
    ]

    scaler = fit_sequence_scaler(train)

    validation_scaled = transform_sequences(
        validation,
        scaler,
    )
    test_scaled = transform_sequences(
        test,
        scaler,
    )

    assert validation_scaled[0]["features"][0][0] == pytest.approx(3.0)
    assert test_scaled[0]["features"][0][0] == pytest.approx(5.0)
