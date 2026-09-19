import pytest

from insider_threat.evaluation.threshold_sensitivity import (
    evaluate_threshold,
    evaluate_thresholds,
)


def test_evaluate_threshold():
    scores = [
        0.10,
        0.20,
        0.75,
        0.15,
    ]

    result = evaluate_threshold(
        scores=scores,
        target_index=2,
        threshold=0.50,
    )

    assert result["threshold"] == 0.50
    assert result["total_windows"] == 4
    assert result["alerts"] == 1
    assert result["normal_alerts"] == 0
    assert result["target_detected"] is True
    assert result["alert_rate"] == 0.25


def test_threshold_with_false_positive():
    scores = [
        0.60,
        0.20,
        0.75,
        0.15,
    ]

    result = evaluate_threshold(
        scores=scores,
        target_index=2,
        threshold=0.50,
    )

    assert result["alerts"] == 2
    assert result["normal_alerts"] == 1
    assert result["target_detected"] is True


def test_target_not_detected():
    scores = [
        0.10,
        0.20,
        0.25,
        0.15,
    ]

    result = evaluate_threshold(
        scores=scores,
        target_index=2,
        threshold=0.50,
    )

    assert result["alerts"] == 0
    assert result["normal_alerts"] == 0
    assert result["target_detected"] is False


def test_evaluate_multiple_thresholds():
    scores = [
        0.10,
        0.40,
        0.75,
        0.20,
    ]

    results = evaluate_thresholds(
        scores=scores,
        target_index=2,
        thresholds=[0.20, 0.50, 0.80],
    )

    assert len(results) == 3

    assert results[0]["alerts"] == 3
    assert results[0]["target_detected"] is True

    assert results[1]["alerts"] == 1
    assert results[1]["target_detected"] is True

    assert results[2]["alerts"] == 0
    assert results[2]["target_detected"] is False


def test_empty_scores():
    with pytest.raises(ValueError):
        evaluate_threshold(
            scores=[],
            target_index=0,
            threshold=0.30,
        )


def test_invalid_target_index():
    with pytest.raises(IndexError):
        evaluate_threshold(
            scores=[0.1, 0.2],
            target_index=5,
            threshold=0.30,
        )


@pytest.mark.parametrize(
    "threshold",
    [-0.1, 1.1],
)
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError):
        evaluate_threshold(
            scores=[0.1, 0.2],
            target_index=0,
            threshold=threshold,
        )
