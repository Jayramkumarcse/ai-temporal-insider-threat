import pytest

from insider_threat.evaluation.metrics import (
    calculate_classification_metrics,
)


def test_perfect_classification():
    result = calculate_classification_metrics(
        y_true=[0, 0, 1, 0, 1],
        y_pred=[0, 0, 1, 0, 1],
    )

    assert result["precision"] == pytest.approx(1.0)
    assert result["recall"] == pytest.approx(1.0)
    assert result["f1"] == pytest.approx(1.0)

    assert result["true_negative"] == 3
    assert result["false_positive"] == 0
    assert result["false_negative"] == 0
    assert result["true_positive"] == 2


def test_one_missed_anomaly():
    result = calculate_classification_metrics(
        y_true=[0, 0, 1, 0],
        y_pred=[0, 0, 0, 0],
    )

    assert result["precision"] == pytest.approx(0.0)
    assert result["recall"] == pytest.approx(0.0)
    assert result["f1"] == pytest.approx(0.0)

    assert result["true_negative"] == 3
    assert result["false_positive"] == 0
    assert result["false_negative"] == 1
    assert result["true_positive"] == 0


def test_false_positive():
    result = calculate_classification_metrics(
        y_true=[0, 0, 1],
        y_pred=[1, 0, 1],
    )

    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(1.0)
    assert result["f1"] == pytest.approx(2 / 3)

    assert result["true_negative"] == 1
    assert result["false_positive"] == 1
    assert result["false_negative"] == 0
    assert result["true_positive"] == 1


def test_mismatched_lengths_rejected():
    with pytest.raises(ValueError):
        calculate_classification_metrics(
            y_true=[0, 1],
            y_pred=[0],
        )


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        calculate_classification_metrics(
            y_true=[],
            y_pred=[],
        )
