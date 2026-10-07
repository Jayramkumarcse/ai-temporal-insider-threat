import pytest

from insider_threat.evaluation.thresholds import (
    select_max_validation_threshold,
)


def test_select_max_validation_threshold():
    assert (
        select_max_validation_threshold(
            [0.10, 0.25, 0.15]
        )
        == 0.25
    )


def test_empty_validation_scores_rejected():
    with pytest.raises(ValueError):
        select_max_validation_threshold([])


def test_non_finite_validation_scores_rejected():
    with pytest.raises(ValueError):
        select_max_validation_threshold(
            [0.10, float("inf")]
        )


def test_generator_input_supported():
    threshold = select_max_validation_threshold(
        score for score in [0.10, 0.30, 0.20]
    )

    assert threshold == 0.30
