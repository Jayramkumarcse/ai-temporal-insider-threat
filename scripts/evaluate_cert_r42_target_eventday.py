#!/usr/bin/env python3
"""Chronological, leakage-aware Isolation Forest baseline for CERT r4.2."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data/processed/cert_r42_5source_target_eventday_labelled.csv"
OUTPUT_PATH = ROOT / "reports/experiment_results/cert_r42_target_eventday_isolation_forest.csv"

FEATURES = (
    "event_count",
    "logon_event_count",
    "login_count",
    "logout_count",
    "device_event_count",
    "device_connect_count",
    "device_disconnect_count",
    "file_event_count",
    "email_count",
    "email_bytes",
    "email_attachment_count",
    "http_event_count",
    "night_activity_count",
    "off_hours_activity_count",
    "weekend_activity_count",
    "active_span_seconds",
    "events_per_hour",
)

SEED = 42
N_ESTIMATORS = 200


def classification_metrics(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float,
) -> dict[str, float | int]:
    predictions = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    return {
        "precision": float(
            precision_score(y_true, predictions, zero_division=0)
        ),
        "recall": float(
            recall_score(y_true, predictions, zero_division=0)
        ),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
        "alert_rate": float(predictions.mean()),
    }


def main() -> None:
    if not DATA_PATH.is_file():
        raise FileNotFoundError(f"Feature dataset missing: {DATA_PATH}")

    required_columns = ["date", "target_eventday_label", *FEATURES]
    frame = pd.read_csv(
        DATA_PATH,
        usecols=required_columns,
        dtype={"date": "string", "target_eventday_label": "int8"},
    )

    if frame.empty:
        raise ValueError("Feature dataset is empty.")

    if frame["target_eventday_label"].isna().any():
        raise ValueError("Missing ground-truth labels.")
    if not frame["target_eventday_label"].isin([0, 1]).all():
        raise ValueError("Ground-truth labels must be binary.")

    # Use sorted, whole calendar dates: no date is split across partitions.
    dates = sorted(frame["date"].dropna().unique().tolist())
    if len(dates) < 10:
        raise ValueError("Too few unique dates for chronological splitting.")

    train_end = dates[int(len(dates) * 0.70) - 1]
    validation_end = dates[int(len(dates) * 0.85) - 1]

    row_dates = frame["date"].to_numpy()
    train_mask = row_dates <= train_end
    validation_mask = (row_dates > train_end) & (row_dates <= validation_end)
    test_mask = row_dates > validation_end

    y = frame["target_eventday_label"].to_numpy(dtype=np.int8)

    # All chosen variables are non-negative counts or durations.
    # A fixed log1p transformation reduces skew without learning from
    # validation or test data.
    raw_features = frame[list(FEATURES)].to_numpy(dtype=np.float64)
    if not np.isfinite(raw_features).all():
        raise ValueError("Feature matrix contains NaN or infinite values.")
    if (raw_features < 0).any():
        raise ValueError("Log-transformed features must be non-negative.")

    X = np.log1p(raw_features)

    normal_train_mask = train_mask & (y == 0)
    if normal_train_mask.sum() == 0:
        raise ValueError("No normal user-days in the training period.")

    y_validation = y[validation_mask]
    y_test = y[test_mask]

    if len(y_validation) == 0 or len(y_test) == 0:
        raise ValueError("Validation or test partition is empty.")
    if len(np.unique(y_validation)) < 2:
        raise ValueError("Validation needs positive and negative labels.")
    if len(np.unique(y_test)) < 2:
        raise ValueError("Test needs positive and negative labels.")

    print("===== CHRONOLOGICAL SPLIT =====")
    print(f"Train:      {dates[0]} to {train_end}")
    print(f"Validation: {validation_end if False else dates[dates.index(train_end) + 1]} to {validation_end}")
    print(f"Test:       {dates[dates.index(validation_end) + 1]} to {dates[-1]}")
    print(f"Training rows: {int(train_mask.sum()):,}")
    print(f"Normal training rows used to fit: {int(normal_train_mask.sum()):,}")
    print(f"Validation rows: {int(validation_mask.sum()):,}")
    print(f"Validation positives: {int(y_validation.sum()):,}")
    print(f"Test rows: {int(test_mask.sum()):,}")
    print(f"Test positives: {int(y_test.sum()):,}")
    print(f"Numeric features: {len(FEATURES)}")

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination="auto",
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(X[normal_train_mask])

    # Higher values mean more anomalous.
    validation_scores = -model.score_samples(X[validation_mask])
    test_scores = -model.score_samples(X[test_mask])

    # Select threshold on validation labels only. In an F1 tie, choose
    # the highest threshold, preferring fewer alerts.
    precision, recall, thresholds = precision_recall_curve(
        y_validation, validation_scores
    )
    if len(thresholds) == 0:
        raise ValueError("Could not select a validation threshold.")

    denominator = precision[:-1] + recall[:-1]
    validation_f1 = np.divide(
        2 * precision[:-1] * recall[:-1],
        denominator,
        out=np.zeros_like(denominator),
        where=denominator > 0,
    )
    best_f1 = float(validation_f1.max())
    tied = np.flatnonzero(np.isclose(validation_f1, best_f1))
    best_index = int(tied[-1])
    threshold = float(thresholds[best_index])

    validation_metrics = classification_metrics(
        y_validation, validation_scores, threshold
    )
    test_metrics = classification_metrics(y_test, test_scores, threshold)

    results = {
        "experiment": "cert_r42_isolation_forest_chronological_v1",
        "dataset": "CERT r4.2",
        "seed": SEED,
        "n_estimators": N_ESTIMATORS,
        "feature_count": len(FEATURES),
        "features": ";".join(FEATURES),
        "transform": "log1p",
        "training_rule": "fit on normal training-period user-days only",
        "threshold_rule": "maximize validation F1; highest threshold on ties",
        "threshold": threshold,
        "unique_dates": len(dates),
        "train_start": dates[0],
        "train_end": train_end,
        "validation_start": dates[dates.index(train_end) + 1],
        "validation_end": validation_end,
        "test_start": dates[dates.index(validation_end) + 1],
        "test_end": dates[-1],
        "train_rows": int(train_mask.sum()),
        "train_normal_rows": int(normal_train_mask.sum()),
        "train_positive_rows": int((train_mask & (y == 1)).sum()),
        "validation_rows": int(validation_mask.sum()),
        "validation_positive_rows": int(y_validation.sum()),
        "validation_selected_f1": best_f1,
        "test_rows": int(test_mask.sum()),
        "test_positive_rows": int(y_test.sum()),
        "test_roc_auc": float(roc_auc_score(y_test, test_scores)),
        "test_average_precision": float(
            average_precision_score(y_test, test_scores)
        ),
        **{f"validation_{k}": v for k, v in validation_metrics.items()},
        **{f"test_{k}": v for k, v in test_metrics.items()},
        "label_definition": "target-insider answer-key event-day; listed events are not exhaustive",
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results))
        writer.writeheader()
        writer.writerow(results)

    print("\n===== VALIDATION METRICS (threshold selection set) =====")
    print(json.dumps(validation_metrics, indent=2))
    print("\n===== HELD-OUT TEST METRICS =====")
    print(json.dumps({
        "roc_auc": results["test_roc_auc"],
        "average_precision": results["test_average_precision"],
        **test_metrics,
    }, indent=2))
    print(f"\nSaved summary: {OUTPUT_PATH}")
    print(
        "Caution: labels represent answer-key-listed target-insider event-days; "
        "they are not exhaustive malicious-event ground truth."
    )


if __name__ == "__main__":
    main()
