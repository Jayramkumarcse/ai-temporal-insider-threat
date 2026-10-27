#!/usr/bin/env python3
"""Compare Isolation Forest with simple CERT activity-ranking baselines."""

from pathlib import Path
import csv

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/processed/cert_r42_5source_user_day.csv"
OUTPUT = ROOT / "reports/experiment_results/cert_r42_ranking_baselines.csv"

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


def main():
    frame = pd.read_csv(DATA, usecols=["date", "ground_truth", *FEATURES])
    dates = sorted(frame["date"].dropna().unique())

    train_end = dates[int(len(dates) * 0.70) - 1]
    val_end = dates[int(len(dates) * 0.85) - 1]

    d = frame["date"].to_numpy()
    y = frame["ground_truth"].to_numpy(dtype=int)
    train = d <= train_end
    test = d > val_end
    normal_train = train & (y == 0)

    raw = frame[FEATURES].to_numpy(dtype=float)
    if not np.isfinite(raw).all() or (raw < 0).any():
        raise ValueError("Features contain non-finite or negative values.")

    X = np.log1p(raw)
    y_test = y[test]

    if len(np.unique(y_test)) != 2:
        raise ValueError("Test partition must contain both label classes.")

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X[normal_train])

    score_sets = {
        "isolation_forest_17_features": -model.score_samples(X[test]),
        "event_count_only": frame.loc[test, "event_count"].to_numpy(),
        "http_count_only": frame.loc[test, "http_event_count"].to_numpy(),
        "email_count_only": frame.loc[test, "email_count"].to_numpy(),
        "off_hours_count_only": frame.loc[
            test, "off_hours_activity_count"
        ].to_numpy(),
    }

    rows = []
    for name, scores in score_sets.items():
        rows.append({
            "model": name,
            "test_rows": len(y_test),
            "test_positive_rows": int(y_test.sum()),
            "test_prevalence": float(y_test.mean()),
            "roc_auc": float(roc_auc_score(y_test, scores)),
            "average_precision": float(
                average_precision_score(y_test, scores)
            ),
            "ap_divided_by_prevalence": float(
                average_precision_score(y_test, scores) / y_test.mean()
            ),
            "threshold_selected": False,
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Train ends: {train_end}")
    print(f"Validation ends: {dates[dates.index(train_end) + 1]} to {val_end}")
    print(f"Test: {dates[dates.index(val_end) + 1]} to {dates[-1]}")
    print(f"Test positives: {int(y_test.sum())} / {len(y_test)}")
    print("\n===== RANKING BASELINES (HELD-OUT TEST) =====")
    for row in sorted(rows, key=lambda r: r["average_precision"], reverse=True):
        print(
            f"{row['model']:<32} "
            f"ROC-AUC={row['roc_auc']:.4f}  "
            f"AP={row['average_precision']:.5f}  "
            f"AP/prevalence={row['ap_divided_by_prevalence']:.2f}x"
        )

    print(f"\nSaved: {OUTPUT}")
    print("No test-derived threshold was selected.")


if __name__ == "__main__":
    main()
