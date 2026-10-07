from datetime import date

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.hourly_isolation_forest import (
    fit_hourly_isolation_forest,
    score_hourly_isolation_forest,
)


def test_hourly_isolation_forest_uses_chronological_split():
    events = load_processed_events(
        "data/interim/clean_events.json"
    )

    results = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    train = [
        result
        for result in results
        if result["date"] <= "2026-09-12"
    ]

    validation = [
        result
        for result in results
        if "2026-09-13" <= result["date"] <= "2026-09-14"
    ]

    test = [
        result
        for result in results
        if result["date"] >= "2026-09-15"
    ]

    assert len(train) == 840
    assert len(validation) == 240
    assert len(test) == 240

    model = fit_hourly_isolation_forest(
        train,
        random_state=42,
        n_estimators=200,
    )

    validation_scores = score_hourly_isolation_forest(
        model,
        validation,
    )

    test_scores = score_hourly_isolation_forest(
        model,
        test,
    )

    assert len(validation_scores) == 240
    assert len(test_scores) == 240

    target = next(
        result
        for result in test_scores
        if (
            result["user_id"] == "USR-003"
            and result["date"] == "2026-09-16"
            and result["hour_of_day"] == 2
        )
    )

    assert target["anomaly_score"] > 0
