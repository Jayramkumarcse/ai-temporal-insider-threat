from __future__ import annotations

import csv
from datetime import date, datetime, timezone
from pathlib import Path

from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.evaluation.time_of_day_experiments import (
    ANOMALY_HOURS,
    evaluate_time_of_day_window,
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

SCENARIO = "short_anomaly_burst"

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
    "time_of_day_comparison.csv"
)


def build_processed_events(
    anomaly_hour: int,
) -> list[ProcessedEvent]:
    """Build and preprocess one timed anomaly dataset."""

    events = build_scenario_dataset(
        SCENARIO,
        start_date=datetime(
            2026,
            9,
            1,
            tzinfo=timezone.utc,
        ),
        days=30,
        user_id=SCENARIO_USER,
        hour=anomaly_hour,
        minute=0,
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

    for anomaly_hour in ANOMALY_HOURS:
        print()
        print("=" * 60)
        print(
            f"Anomaly time: "
            f"{anomaly_hour:02d}:00 UTC"
        )
        print("=" * 60)

        events = build_processed_events(
            anomaly_hour,
        )

        print(
            f"Processed events: {len(events)}"
        )

        for window_hours in WINDOW_SIZES:
            results = build_temporal_window_experiment_results(
                events,
                start_date=START_DATE,
                end_date=END_DATE,
                window_hours=window_hours,
                minimum_history=MINIMUM_HISTORY,
            )

            evaluation = evaluate_time_of_day_window(
                results,
                anomaly_hour=anomaly_hour,
                window_hours=window_hours,
                threshold=THRESHOLD,
                target_user=SCENARIO_USER,
                target_date=SCENARIO_DATE,
            )

            rows.append(
                {
                    "anomaly_hour": anomaly_hour,
                    "window_hours": window_hours,
                    "target_window_start": (
                        evaluation[
                            "target_window_start"
                        ]
                    ),
                    "target_window_end": (
                        evaluation[
                            "target_window_end"
                        ]
                    ),
                    "target_event_count": (
                        evaluation[
                            "target_event_count"
                        ]
                    ),
                    "target_sensitive_access_count": (
                        evaluation[
                            "target_sensitive_access_count"
                        ]
                    ),
                    "target_unique_devices": (
                        evaluation[
                            "target_unique_devices"
                        ]
                    ),
                    "target_unique_ips": (
                        evaluation[
                            "target_unique_ips"
                        ]
                    ),
                    "target_bytes_transferred": (
                        evaluation[
                            "target_bytes_transferred"
                        ]
                    ),
                    "target_temporal_score": (
                        evaluation[
                            "target_temporal_score"
                        ]
                    ),
                    "target_context_signal": (
                        evaluation[
                            "target_context_signal"
                        ]
                    ),
                    "target_composite_signal": (
                        evaluation[
                            "target_composite_signal"
                        ]
                    ),
                    "target_rank": (
                        evaluation["target_rank"]
                    ),
                    "highest_normal_score": (
                        evaluation[
                            "highest_normal_score"
                        ]
                    ),
                    "absolute_margin": (
                        evaluation[
                            "absolute_margin"
                        ]
                    ),
                    "ratio_to_highest_normal": (
                        evaluation[
                            "ratio_to_highest_normal"
                        ]
                    ),
                    "threshold": THRESHOLD,
                    "total_alerts": (
                        evaluation["total_alerts"]
                    ),
                    "normal_alerts": (
                        evaluation["normal_alerts"]
                    ),
                    "target_detected": (
                        evaluation["target_detected"]
                    ),
                }
            )

            print(
                f"{window_hours:>2}H | "
                f"score="
                f"{evaluation['target_composite_signal']:.6f} | "
                f"rank="
                f"{evaluation['target_rank']:>3} | "
                f"normal_fp="
                f"{evaluation['normal_alerts']:>3} | "
                f"detected="
                f"{evaluation['target_detected']}"
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
