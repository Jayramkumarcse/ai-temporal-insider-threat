from __future__ import annotations

import csv
from datetime import date, datetime, timezone
from pathlib import Path

from insider_threat.evaluation.scenario_window_experiments import (
    evaluate_scenario_window,
)
from insider_threat.preprocessing.normalization import (
    derive_temporal_fields,
    normalize_events,
)
from insider_threat.preprocessing.processed_event import (
    ProcessedEvent,
)
from insider_threat.synthetic.scenario_dataset import (
    build_scenario_dataset,
)


START_DATE = date(2026, 9, 1)
END_DATE = date(2026, 9, 16)

SCENARIO_DATE = date(2026, 9, 16)
SCENARIO_USER = "USR-003"

SCENARIOS = (
    "sensitive_access_burst",
    "large_transfer",
    "off_hours_new_device",
    "short_anomaly_burst",
)

WINDOW_SIZES = (
    1,
    2,
    4,
    6,
    8,
    12,
    24,
)

MINIMUM_HISTORY = 5
THRESHOLD = 0.30

OUTPUT_PATH = Path(
    "reports/experiment_results/"
    "scenario_window_comparison.csv"
)


def build_processed_events(
    scenario: str,
) -> list[ProcessedEvent]:
    """Build and preprocess one isolated scenario dataset."""

    events = build_scenario_dataset(
        scenario,
        start_date=datetime(
            2026,
            9,
            1,
            tzinfo=timezone.utc,
        ),
        days=30,
        user_id=SCENARIO_USER,
    )

    events = normalize_events(events)

    processed_events = []

    for event in events:
        temporal = derive_temporal_fields(event)

        processed_events.append(
            ProcessedEvent(
                **event.model_dump(),
                **temporal,
            )
        )

    return processed_events


def main() -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = []

    for scenario in SCENARIOS:
        print()
        print("=" * 60)
        print(f"Scenario: {scenario}")
        print("=" * 60)

        events = build_processed_events(scenario)

        print(f"Processed events: {len(events)}")

        for window_hours in WINDOW_SIZES:
            evaluation = evaluate_scenario_window(
                events,
                start_date=START_DATE,
                end_date=END_DATE,
                window_hours=window_hours,
                target_user=SCENARIO_USER,
                target_date=SCENARIO_DATE,
                minimum_history=MINIMUM_HISTORY,
                threshold=THRESHOLD,
            )

            target = evaluation["target"]
            separation = evaluation["separation"]

            row = {
                "scenario": scenario,
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
                "target_unique_devices": target[
                    "unique_devices"
                ],
                "target_unique_ips": target[
                    "unique_ips"
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
                "target_rank": evaluation[
                    "target_rank"
                ],
                "highest_normal_score": separation[
                    "highest_normal_score"
                ],
                "absolute_margin": separation[
                    "absolute_margin"
                ],
                "ratio_to_highest_normal": separation[
                    "ratio_to_highest_normal"
                ],
                "threshold": THRESHOLD,
                "total_alerts": evaluation[
                    "total_alerts"
                ],
                "normal_alerts": evaluation[
                    "normal_alerts"
                ],
                "target_detected": evaluation[
                    "target_detected"
                ],
            }

            rows.append(row)

            print(
                f"{window_hours:>2}H | "
                f"score={row['target_composite_signal']:.6f} | "
                f"rank={row['target_rank']:>3} | "
                f"normal_fp={row['normal_alerts']:>3} | "
                f"detected={row['target_detected']}"
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

    print()
    print("=" * 60)
    print(f"Saved: {OUTPUT_PATH}")
    print(f"Rows: {len(rows)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
