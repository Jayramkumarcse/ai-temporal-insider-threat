from __future__ import annotations

from datetime import date

from insider_threat.evaluation.experiments import (
    build_hourly_experiment_results,
)
from insider_threat.evaluation.lstm_sequence_labels import (
    label_lstm_test_sequences,
)
from insider_threat.evaluation.temporal_localization import (
    locate_anomaly_in_sequence,
)
from insider_threat.evaluation.model_comparison import (
    add_target_rank,
    build_model_evaluation,
)
from insider_threat.evaluation.round10_comparison import (
    build_round10_comparison,
)
from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.hourly_isolation_forest import (
    fit_hourly_isolation_forest,
    score_hourly_isolation_forest,
)
from insider_threat.models.lstm_evaluation import (
    select_reconstruction_threshold,
    sequence_reconstruction_errors,
)
from insider_threat.models.lstm_training import (
    train_autoencoder,
)
from insider_threat.models.sequence_dataset import (
    build_user_sequences,
)
from insider_threat.models.sequence_pipeline import (
    prepare_sequence_datasets,
)
from insider_threat.models.sequence_split import (
    split_sequences_by_target_date,
)
from insider_threat.evaluation.thresholds import (
    select_max_validation_threshold,
)


EVENTS_PATH = "data/interim/clean_events.json"

TARGET_USER = "USR-003"
TARGET_DATE = "2026-09-16"
TARGET_HOUR = 2
TARGET_WINDOW = "2026-09-16T02:00:00+00:00"


def run() -> None:
    events = load_processed_events(EVENTS_PATH)

    # ---------------------------------------------------------
    # 1. Statistical / Hybrid baseline
    # ---------------------------------------------------------

    baseline_results = build_hourly_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        minimum_history=5,
    )

    baseline_train = [
        result
        for result in baseline_results
        if result["date"] <= "2026-09-12"
    ]

    baseline_validation = [
        result
        for result in baseline_results
        if "2026-09-13" <= result["date"] <= "2026-09-14"
    ]

    baseline_test = [
        result
        for result in baseline_results
        if result["date"] >= "2026-09-15"
    ]

    baseline_threshold = max(
        result["composite_signal"]
        for result in baseline_validation
    )

    baseline_scores = [
        result["composite_signal"]
        for result in baseline_test
    ]

    baseline_labels = [
        int(
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["hour_of_day"] == TARGET_HOUR
        )
        for result in baseline_test
    ]

    baseline_target_index = next(
        index
        for index, result in enumerate(baseline_test)
        if (
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["hour_of_day"] == TARGET_HOUR
        )
    )

    baseline_evaluation = build_model_evaluation(
        model_name="Statistical / Hybrid",
        scores=baseline_scores,
        threshold=baseline_threshold,
        labels=baseline_labels,
    )

    baseline_evaluation = add_target_rank(
        baseline_evaluation,
        target_index=baseline_target_index,
    )

    # ---------------------------------------------------------
    # 2. Hourly Isolation Forest
    # ---------------------------------------------------------

    hourly_results = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    hourly_train = [
        result
        for result in hourly_results
        if result["date"] <= "2026-09-12"
    ]

    hourly_validation = [
        result
        for result in hourly_results
        if "2026-09-13" <= result["date"] <= "2026-09-14"
    ]

    hourly_test = [
        result
        for result in hourly_results
        if result["date"] >= "2026-09-15"
    ]

    hourly_model = fit_hourly_isolation_forest(
        hourly_train,
        random_state=42,
        n_estimators=200,
    )

    hourly_validation_scores = score_hourly_isolation_forest(
        hourly_model,
        hourly_validation,
    )

    hourly_test_scores = score_hourly_isolation_forest(
        hourly_model,
        hourly_test,
    )

    hourly_threshold = select_max_validation_threshold(
        result["anomaly_score"]
        for result in hourly_validation_scores
    )

    hourly_scores = [
        result["anomaly_score"]
        for result in hourly_test_scores
    ]

    hourly_labels = [
        int(
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["hour_of_day"] == TARGET_HOUR
        )
        for result in hourly_test_scores
    ]

    hourly_target_index = next(
        index
        for index, result in enumerate(hourly_test_scores)
        if (
            result["user_id"] == TARGET_USER
            and result["date"] == TARGET_DATE
            and result["hour_of_day"] == TARGET_HOUR
        )
    )

    hourly_evaluation = build_model_evaluation(
        model_name="Hourly Isolation Forest",
        scores=hourly_scores,
        threshold=hourly_threshold,
        labels=hourly_labels,
    )

    hourly_evaluation = add_target_rank(
        hourly_evaluation,
        target_index=hourly_target_index,
    )

    # ---------------------------------------------------------
    # 3. LSTM sequence autoencoder
    # ---------------------------------------------------------

    sequence_results = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    sequences = build_user_sequences(
        sequence_results,
        sequence_length=6,
    )

    lstm_train, lstm_validation, lstm_test = (
        split_sequences_by_target_date(
            sequences,
            train_end=date(2026, 9, 12),
            validation_end=date(2026, 9, 14),
        )
    )

    datasets = prepare_sequence_datasets(
        lstm_train,
        lstm_validation,
        lstm_test,
    )

    lstm_model, _ = train_autoencoder(
        datasets["train"],
        input_size=5,
        hidden_size=16,
    )

    lstm_validation_scores = sequence_reconstruction_errors(
        lstm_model,
        datasets["validation"],
    )

    lstm_threshold = select_reconstruction_threshold(
        lstm_validation_scores
    )

    lstm_test_scores = sequence_reconstruction_errors(
        lstm_model,
        datasets["test"],
    )

    lstm_scores = lstm_test_scores.tolist()

    lstm_labels = label_lstm_test_sequences(
        lstm_test,
    )

    lstm_target_index = next(
        index
        for index, sequence in enumerate(lstm_test)
        if (
            sequence["user_id"] == TARGET_USER
            and sequence["target_window_start"] == TARGET_WINDOW
        )
    )
    lstm_anomaly_timestep = locate_anomaly_in_sequence(
        target_window_start=lstm_test[lstm_target_index][
            "target_window_start"
        ],
        sequence_length=6,
    )

    lstm_evaluation = build_model_evaluation(
        model_name="LSTM Autoencoder",
        scores=lstm_scores,
        threshold=lstm_threshold,
        labels=lstm_labels,
    )

    lstm_evaluation = add_target_rank(
        lstm_evaluation,
        target_index=lstm_target_index,
    )

    # ---------------------------------------------------------
    # Final comparison
    # ---------------------------------------------------------

    comparison = build_round10_comparison(
        [
            baseline_evaluation,
            hourly_evaluation,
            lstm_evaluation,
        ]
    )

    print()
    print("Round 10 — Model Comparison")
    print("=" * 72)
    print(
        f"{'Model':<28}"
        f"{'Alerts':>8}"
        f"{'Precision':>12}"
        f"{'Recall':>10}"
        f"{'F1':>10}"
        f"{'Rank':>8}"
    )
    print("-" * 72)

    for result in comparison:
        print(
            f"{result['model_name']:<28}"
            f"{result['alerts']:>8}"
            f"{result['precision']:>12.6f}"
            f"{result['recall']:>10.6f}"
            f"{result['f1']:>10.6f}"
            f"{result['target_rank']:>8}"
        )

    print("-" * 72)
    print("Held-out test observations: 240")
    print(f"Known target: {TARGET_WINDOW}")
    print(
        "LSTM localized anomaly timestep: "
        f"{lstm_anomaly_timestep}"
    )

    for result in comparison:
        print(
            f"{result['model_name']}: "
            f"detected={result['target_detected']}"
        )


if __name__ == "__main__":
    run()
