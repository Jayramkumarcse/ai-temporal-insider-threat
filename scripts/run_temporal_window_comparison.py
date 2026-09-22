from __future__ import annotations

import csv
import json
from datetime import date
from pathlib import Path

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
    evaluate_temporal_window_experiment,
)
from insider_threat.preprocessing.processed_event import (
    ProcessedEvent,
)


DATA_PATH = Path("data/interim/clean_events.json")
OUTPUT_PATH = Path(
    "reports/experiment_results/"
    "temporal_window_comparison.csv"
)

START_DATE = date(2026, 9, 1)
END_DATE = date(2026, 9, 16)

WINDOW_SIZES = (1, 2, 4, 6, 8, 12, 24)

MINIMUM_HISTORY = 5
THRESHOLD = 0.30


def load_processed_events() -> list[ProcessedEvent]:
    with DATA_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        records = json.load(file)

    return [
        ProcessedEvent.model_validate(record)
        for record in records
    ]


def count_threshold_alerts(
    results: list[dict],
    threshold: float,
    *,
    target_window: dict,
) -> tuple[int, int, bool]:
    alerts = [
        result
        for result in results
        if result["composite_signal"] >= threshold
    ]

    target_key = (
        target_window["user_id"],
        target_window["date"],
        target_window["window_hours"],
        target_window["window_start_hour"],
    )

    def is_target_window(result: dict) -> bool:
        return (
            result["user_id"],
            result["date"],
            result["window_hours"],
            result["window_start_hour"],
        ) == target_key

    normal_alerts = [
        result
        for result in alerts
        if not is_target_window(result)
    ]

    target_detected = any(
        is_target_window(result)
        for result in alerts
    )

    return (
        len(alerts),
        len(normal_alerts),
        target_detected,
    )


def main() -> None:
    events = load_processed_events()

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = []

    for window_hours in WINDOW_SIZES:
        results = build_temporal_window_experiment_results(
            events,
            start_date=START_DATE,
            end_date=END_DATE,
            window_hours=window_hours,
            minimum_history=MINIMUM_HISTORY,
        )

        evaluation = evaluate_temporal_window_experiment(
            results,
            window_hours=window_hours,
        )

        target = evaluation["target"]

        (
            total_alerts,
            normal_alerts,
            target_detected,
        ) = count_threshold_alerts(
            results,
            threshold=THRESHOLD,
            target_window=target,
        )

        rows.append(
            {
                "window_hours": window_hours,
                "total_windows": evaluation[
                    "total_windows"
                ],
                "target_window_start": target[
                    "window_start"
                ],
                "target_window_end": target[
                    "window_end"
                ],
                "target_event_count": target[
                    "event_count"
                ],
                "target_sensitive_access_count": target[
                    "sensitive_access_count"
                ],
                "target_bytes_transferred": target[
                    "bytes_transferred"
                ],
                "target_temporal_score": target[
                    "temporal_score"
                ],
                "target_context_signal": target[
                    "context_signal"
                ],
                "target_composite_signal": target[
                    "composite_signal"
                ],
                "temporal_rank": evaluation[
                    "temporal_rank"
                ],
                "composite_rank": evaluation[
                    "composite_rank"
                ],
                "composite_separation": evaluation[
                    "composite_separation"
                ],
                "threshold": THRESHOLD,
                "total_alerts": total_alerts,
                "normal_alerts": normal_alerts,
                "target_detected": target_detected,
            }
        )

    fieldnames = list(rows[0].keys())

    with OUTPUT_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)

    print(
        "\nTemporal window comparison"
    )
    print(
        "=========================="
    )

    for row in rows:
        print(
            f"\n{row['window_hours']}H"
        )
        print(
            f"  windows:       "
            f"{row['total_windows']}"
        )
        print(
            f"  target score:  "
            f"{row['target_composite_signal']:.6f}"
        )
        print(
            f"  temporal rank: "
            f"{row['temporal_rank']}"
        )
        print(
            f"  composite rank:"
            f" {row['composite_rank']}"
        )
        print(
            f"  separation:    "
            f"{row['composite_separation']}"
        )
        print(
            f"  alerts @ "
            f"{THRESHOLD:.2f}: "
            f"{row['total_alerts']}"
        )
        print(
            f"  normal alerts: "
            f"{row['normal_alerts']}"
        )
        print(
            f"  target detected:"
            f" {row['target_detected']}"
        )

    print(
        f"\nSaved: {OUTPUT_PATH}"
    )


if __name__ == "__main__":
    main()
