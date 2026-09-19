from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

from insider_threat.evaluation.experiments import (
    build_hourly_experiment_results,
    find_target_result,
)
from insider_threat.evaluation.threshold_sensitivity import (
    evaluate_thresholds,
)
from insider_threat.preprocessing.processed_event import (
    ProcessedEvent,
)


DATA_PATH = Path("data/interim/clean_events.json")

OUTPUT_PATH = Path(
    "reports/experiment_results/"
    "threshold_sensitivity.csv"
)

START_DATE = date(2026, 9, 1)
END_DATE = date(2026, 9, 30)

THRESHOLDS = (
    0.20,
    0.25,
    0.30,
    0.35,
    0.40,
    0.45,
    0.50,
    0.60,
    0.70,
)


def load_processed_events(
    path: str | Path,
) -> list[ProcessedEvent]:
    """Load validated processed events from JSON."""

    path = Path(path)

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError(
            "Processed event JSON must contain a list"
        )

    return [
        ProcessedEvent.model_validate(record)
        for record in records
    ]


def save_results(
    results: list[dict],
    output_path: str | Path,
) -> None:
    """Save threshold sensitivity results as CSV."""

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "threshold",
        "total_windows",
        "alerts",
        "normal_alerts",
        "target_detected",
        "alert_rate",
    ]

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(results)


def main() -> None:
    events = load_processed_events(
        DATA_PATH
    )

    print(
        f"Loaded processed events: {len(events)}"
    )

    results = build_hourly_experiment_results(
        events,
        start_date=START_DATE,
        end_date=END_DATE,
        minimum_history=5,
    )

    if not results:
        raise RuntimeError(
            "No hourly experiment results were generated."
        )

    target = find_target_result(results)

    target_index = results.index(target)

    scores = [
        result["composite_signal"]
        for result in results
    ]

    threshold_results = evaluate_thresholds(
        scores=scores,
        target_index=target_index,
        thresholds=THRESHOLDS,
    )

    save_results(
        threshold_results,
        OUTPUT_PATH,
    )

    print()
    print("ROUND 8A — THRESHOLD SENSITIVITY")
    print("=" * 72)

    print(
        f"Evaluated windows: {len(results)}"
    )

    print()
    print("TARGET")
    print("-" * 72)

    print(
        f'{target["user_id"]} '
        f'{target["date"]} '
        f'{target["hour_of_day"]:02d}:00 UTC'
    )

    print(
        f'Composite signal: '
        f'{target["composite_signal"]:.6f}'
    )

    print()
    print("THRESHOLD RESULTS")
    print("-" * 72)

    print(
        f'{"Threshold":>10} '
        f'{"Alerts":>8} '
        f'{"Normal FP":>10} '
        f'{"Target":>10} '
        f'{"Alert Rate":>12}'
    )

    print("-" * 72)

    for row in threshold_results:
        target_status = (
            "YES"
            if row["target_detected"]
            else "NO"
        )

        print(
            f'{row["threshold"]:>10.2f} '
            f'{row["alerts"]:>8} '
            f'{row["normal_alerts"]:>10} '
            f'{target_status:>10} '
            f'{row["alert_rate"] * 100:>11.2f}%'
        )

    print()
    print(
        f"Saved CSV: {OUTPUT_PATH}"
    )

    print("=" * 72)


if __name__ == "__main__":
    main()
