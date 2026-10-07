import pytest

from insider_threat.evaluation.round10_comparison import (
    build_round10_comparison,
)


def make_evaluation(name):
    return {
        "model_name": name,
        "total_samples": 240,
        "alert_count": 1,
        "target_index": 0,
        "target_score": 0.75,
        "target_rank": 1,
        "predictions": [1],
        "metrics": {
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "true_positive": 1,
            "false_positive": 0,
            "true_negative": 239,
            "false_negative": 0,
        },
    }


def test_build_round10_comparison():
    result = build_round10_comparison(
        [
            make_evaluation("LSTM Autoencoder"),
            make_evaluation("Hourly Isolation Forest"),
        ]
    )

    assert len(result) == 2
    assert result[0]["model_name"] == "Hourly Isolation Forest"
    assert result[0]["test_samples"] == 240
    assert result[0]["alerts"] == 1
    assert result[0]["precision"] == 1.0
    assert result[0]["recall"] == 1.0
    assert result[0]["f1"] == 1.0
    assert result[0]["target_rank"] == 1
    assert result[0]["target_detected"] is True


def test_empty_evaluations_rejected():
    with pytest.raises(ValueError):
        build_round10_comparison([])


def test_lstm_target_localization():
    from insider_threat.evaluation.temporal_localization import (
        locate_anomaly_in_sequence,
    )

    timestep = locate_anomaly_in_sequence(
        target_window_start="2026-09-16T02:00:00+00:00",
        sequence_length=6,
    )

    assert timestep == 5
