from __future__ import annotations

from datetime import date

from insider_threat.evaluation.lstm_sequence_labels import (
    KNOWN_ANOMALY_WINDOW,
)
from insider_threat.evaluation.metrics import (
    calculate_classification_metrics,
)
from insider_threat.evaluation.thresholds import (
    select_max_validation_threshold,
)
from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.hourly_isolation_forest import (
    fit_hourly_isolation_forest,
    score_hourly_isolation_forest,
)


def run_hourly_isolation_forest_experiment(
    events_path: str,
) -> dict[str, object]:
    """Run a chronological hourly Isolation Forest experiment."""

    events = load_processed_events(events_path)

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

    threshold = select_max_validation_threshold(
        result["anomaly_score"]
        for result in validation_scores
    )

    predictions = [
        int(result["anomaly_score"] >= threshold)
        for result in test_scores
    ]

    labels = [
        int(
            result["user_id"] == "USR-003"
            and result["date"] == "2026-09-16"
            and result["hour_of_day"] == 2
        )
        for result in test_scores
    ]

    metrics = calculate_classification_metrics(
        labels,
        predictions,
    )

    target_index = next(
        index
        for index, result in enumerate(test_scores)
        if (
            result["user_id"] == "USR-003"
            and result["date"] == "2026-09-16"
            and result["hour_of_day"] == 2
        )
    )

    target_score = test_scores[target_index]["anomaly_score"]

    target_rank = (
        1
        + sum(
            result["anomaly_score"] > target_score
            for result in test_scores
        )
    )

    return {
        "train_windows": len(train),
        "validation_windows": len(validation),
        "test_windows": len(test),
        "threshold": threshold,
        "alert_count": sum(predictions),
        "metrics": metrics,
        "target_window": KNOWN_ANOMALY_WINDOW,
        "target_score": target_score,
        "target_rank": target_rank,
    }
