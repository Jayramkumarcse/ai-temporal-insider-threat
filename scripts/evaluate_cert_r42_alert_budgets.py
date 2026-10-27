#!/usr/bin/env python3
"""Evaluate validation-derived alert-budget thresholds on CERT r4.2."""

from pathlib import Path
import csv
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    precision_recall_curve,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed/cert_r42_5source_user_day.csv"
OUTPUT = ROOT / "reports/experiment_results/cert_r42_alert_budget_sensitivity.csv"

FEATURES = [
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
]


def metrics(y, scores, threshold):
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "alerts": int(pred.sum()),
        "alert_rate": float(pred.mean()),
    }


def main():
    if not DATA.exists():
        raise FileNotFoundError(DATA)

    frame = pd.read_csv(DATA, usecols=["date", "ground_truth", *FEATURES])
    dates = sorted(frame["date"].dropna().unique())
    if len(dates) < 10:
        raise ValueError("Insufficient dates for temporal evaluation.")

    train_end = dates[int(len(dates) * 0.70) - 1]
    val_end = dates[int(len(dates) * 0.85) - 1]
    d = frame["date"].to_numpy()

    train = d <= train_end
    val = (d > train_end) & (d <= val_end)
    test = d > val_end

    y = frame["ground_truth"].to_numpy(dtype=int)
    raw = frame[FEATURES].to_numpy(dtype=float)

    if not np.isfinite(raw).all() or (raw < 0).any():
        raise ValueError("Features contain non-finite or negative values.")

    X = np.log1p(raw)
    fit_mask = train & (y == 0)
    if not fit_mask.any():
        raise ValueError("No normal training observations.")

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X[fit_mask])

    val_scores = -model.score_samples(X[val])
    test_scores = -model.score_samples(X[test])
    y_val = y[val]
    y_test = y[test]

    if len(np.unique(y_val)) < 2 or len(np.unique(y_test)) < 2:
        raise ValueError("Validation and test both require two classes.")

    rows = []

    # Reference operating point: threshold selected using validation labels.
    precision, recall, thresholds = precision_recall_curve(y_val, val_scores)
    denom = precision[:-1] + recall[:-1]
    f1 = np.divide(
        2 * precision[:-1] * recall[:-1],
        denom,
        out=np.zeros_like(denom),
        where=denom > 0,
    )
    max_f1 = f1.max()
    index = int(np.flatnonzero(np.isclose(f1, max_f1))[-1])
    candidates = [("validation_max_f1", float(thresholds[index]), None)]

    # Other thresholds use validation scores only—not labels.
    for budget in (0.01, 0.02, 0.05, 0.10):
        threshold = float(np.quantile(val_scores, 1 - budget, method="higher"))
        candidates.append((f"validation_top_{int(budget*100)}pct", threshold, budget))

    for name, threshold, target_budget in candidates:
        val_metrics = metrics(y_val, val_scores, threshold)
        test_metrics = metrics(y_test, test_scores, threshold)

        rows.append({
            "operating_point": name,
            "target_validation_alert_rate": target_budget,
            "threshold": threshold,
            "validation_precision": val_metrics["precision"],
            "validation_recall": val_metrics["recall"],
            "validation_f1": val_metrics["f1"],
            "validation_alert_rate": val_metrics["alert_rate"],
            "test_precision": test_metrics["precision"],
            "test_recall": test_metrics["recall"],
            "test_f1": test_metrics["f1"],
            "test_alert_rate": test_metrics["alert_rate"],
            "test_alerts": test_metrics["alerts"],
            "test_tp": test_metrics["tp"],
            "test_fp": test_metrics["fp"],
            "test_fn": test_metrics["fn"],
            "test_roc_auc": float(roc_auc_score(y_test, test_scores)),
            "test_average_precision": float(
                average_precision_score(y_test, test_scores)
            ),
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print("Train end:", train_end)
    print("Validation end:", val_end)
    print("Test period:", dates[dates.index(val_end) + 1], "to", dates[-1])
    print("Test prevalence:", f"{y_test.mean():.4%}")
    print("\n===== THRESHOLD SENSITIVITY =====")
    for row in rows:
        print(json.dumps(row, indent=2))
    print("\nSaved:", OUTPUT)


if __name__ == "__main__":
    main()
