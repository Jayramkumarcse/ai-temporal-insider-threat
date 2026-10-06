from datetime import date

import numpy as np

from insider_threat.evaluation.lstm_sequence_labels import (
    label_lstm_test_sequences,
)
from insider_threat.evaluation.metrics import calculate_classification_metrics
from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.features.builder import load_processed_events
from insider_threat.models.lstm_evaluation import (
    select_reconstruction_threshold,
    sequence_reconstruction_errors,
)
from insider_threat.models.lstm_training import train_autoencoder
from insider_threat.models.sequence_dataset import build_user_sequences
from insider_threat.models.sequence_pipeline import prepare_sequence_datasets
from insider_threat.models.sequence_split import split_sequences_by_target_date


def main() -> None:
    events = load_processed_events("data/interim/clean_events.json")

    results = build_temporal_window_experiment_results(
        events,
        start_date=date(2026, 9, 1),
        end_date=date(2026, 9, 16),
        window_hours=1,
        minimum_history=5,
    )

    sequences = build_user_sequences(
        results,
        sequence_length=6,
    )

    train, validation, test = split_sequences_by_target_date(
        sequences,
        train_end=date(2026, 9, 12),
        validation_end=date(2026, 9, 14),
    )

    datasets = prepare_sequence_datasets(
        train,
        validation,
        test,
    )

    model, history = train_autoencoder(
        datasets["train"],
        input_size=5,
        hidden_size=16,
    )

    validation_scores = sequence_reconstruction_errors(
        model,
        datasets["validation"],
    )

    threshold = select_reconstruction_threshold(validation_scores)

    test_scores = sequence_reconstruction_errors(
        model,
        datasets["test"],
    )

    test_flags = test_scores > threshold

    test_labels = label_lstm_test_sequences(test)
    context_labels = label_lstm_test_sequences(
        test,
        context=True,
    )

    metrics = calculate_classification_metrics(
        test_labels,
        test_flags.astype(int).tolist(),
    )

    context_metrics = calculate_classification_metrics(
        context_labels,
        test_flags.astype(int).tolist(),
    )

    target_index = next(
        index
        for index, sequence in enumerate(test)
        if (
            sequence["user_id"] == "USR-003"
            and sequence["target_window_start"]
            == "2026-09-16T02:00:00+00:00"
        )
    )

    target_score = float(test_scores[target_index])

    print("Round 9 — LSTM Temporal Sequence Anomaly Detection")
    print("=" * 55)
    print(f"Events: {len(events)}")
    print(f"Sequences: {len(sequences)}")
    print(f"Train sequences: {len(train)}")
    print(f"Validation sequences: {len(validation)}")
    print(f"Test sequences: {len(test)}")
    print(f"Training epochs: {len(history['train_loss'])}")
    print(f"Validation threshold: {threshold:.10f}")
    print(f"Test alerts: {int(test_flags.sum())}")
    print()
    print("Exact-window evaluation")
    print(f"  TP: {metrics['true_positive']}")
    print(f"  FP: {metrics['false_positive']}")
    print(f"  TN: {metrics['true_negative']}")
    print(f"  FN: {metrics['false_negative']}")
    print(f"  Precision: {metrics['precision']:.6f}")
    print(f"  Recall: {metrics['recall']:.6f}")
    print(f"  F1: {metrics['f1']:.6f}")
    print()
    print("Context-window evaluation")
    print(f"  TP: {context_metrics['true_positive']}")
    print(f"  FP: {context_metrics['false_positive']}")
    print(f"  TN: {context_metrics['true_negative']}")
    print(f"  FN: {context_metrics['false_negative']}")
    print(f"  Precision: {context_metrics['precision']:.6f}")
    print(f"  Recall: {context_metrics['recall']:.6f}")
    print(f"  F1: {context_metrics['f1']:.6f}")
    print()
    print("Known held-out anomaly")
    print("  User: USR-003")
    print("  Window: 2026-09-16T02:00:00+00:00")
    print(f"  Score: {target_score:.10f}")
    print(f"  Above threshold: {target_score > threshold}")
    print(
        f"  Test rank: "
        f"{int(np.argsort(-test_scores).tolist().index(target_index)) + 1}"
    )


if __name__ == "__main__":
    main()
