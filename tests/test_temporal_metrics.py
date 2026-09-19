import pytest

from insider_threat.evaluation.temporal_metrics import (
    rank_descending,
    target_separation,
    threshold_alert_rate,
    threshold_counts,
)


def test_rank_descending():
    scores = [0.2, 0.8, 0.5, 0.3]

    assert rank_descending(scores, 0.8) == 1
    assert rank_descending(scores, 0.5) == 2


def test_threshold_counts():
    scores = [0.1, 0.3, 0.5, 0.8]

    result = threshold_counts(
        scores,
        threshold=0.5,
    )

    assert result["total"] == 4
    assert result["alerts"] == 2
    assert result["normal_or_other"] == 2


def test_threshold_alert_rate():
    scores = [0.1, 0.3, 0.5, 0.8]

    assert threshold_alert_rate(
        scores,
        0.5,
    ) == pytest.approx(0.5)


def test_empty_alert_rate():
    assert threshold_alert_rate([], 0.5) == 0.0


def test_target_separation():
    result = target_separation(
        0.7,
        [0.1, 0.2, 0.25],
    )

    assert result["target_score"] == 0.7
    assert result["highest_normal_score"] == 0.25
    assert result["absolute_margin"] == pytest.approx(0.45)
    assert result["ratio_to_highest_normal"] == pytest.approx(2.8)


def test_empty_normal_scores_rejected():
    with pytest.raises(ValueError):
        target_separation(0.7, [])
