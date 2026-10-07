from insider_threat.evaluation.hourly_if_experiment import (
    run_hourly_isolation_forest_experiment,
)


def test_hourly_isolation_forest_experiment():
    result = run_hourly_isolation_forest_experiment(
        "data/interim/clean_events.json"
    )

    assert result["train_windows"] == 840
    assert result["validation_windows"] == 240
    assert result["test_windows"] == 240

    assert result["threshold"] > 0
    assert result["alert_count"] >= 1

    metrics = result["metrics"]

    assert metrics["true_positive"] >= 1
    assert metrics["recall"] == 1.0

    assert result["target_score"] >= result["threshold"]
    assert result["target_rank"] >= 1
