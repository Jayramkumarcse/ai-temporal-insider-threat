"""Run scenario-window evaluations across multiple synthetic-data seeds."""

from __future__ import annotations

import argparse
import csv
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd

from insider_threat.evaluation.scenario_window_experiments import (
    evaluate_scenario_window,
)
from insider_threat.preprocessing.normalization import (
    derive_temporal_fields,
    normalize_events,
)
from insider_threat.preprocessing.processed_event import ProcessedEvent
from insider_threat.synthetic.scenario_dataset import build_scenario_dataset


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "reports" / "experiment_results"

RAW_OUTPUT = OUTPUT_DIR / "multi_seed_scenario_results.csv"
SUMMARY_OUTPUT = OUTPUT_DIR / "multi_seed_scenario_summary.csv"

SEEDS = (7, 21, 42, 84, 123)

SCENARIOS = (
    "sensitive_access_burst",
    "large_transfer",
    "off_hours_new_device",
    "short_anomaly_burst",
)

WINDOW_SIZES = (1, 2, 4, 6, 8, 12, 24)

START_DATE = date(2026, 9, 1)
END_DATE = date(2026, 9, 16)
SCENARIO_DATE = date(2026, 9, 16)
SCENARIO_USER = "USR-003"

MINIMUM_HISTORY = 5
THRESHOLD = 0.30


def build_processed_events(scenario: str, seed: int) -> list[ProcessedEvent]:
    """Build one scenario using the requested baseline-generation seed."""
    events = build_scenario_dataset(
        scenario,
        start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
        days=30,
        user_id=SCENARIO_USER,
        seed=seed,
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


def save_rows(rows: list[dict], path: Path) -> None:
    """Write experiment rows as a CSV file."""
    if not rows:
        raise ValueError(f"Refusing to write an empty result: {path}")

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate scenario detection across synthetic background seeds."
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=list(SEEDS),
        help="Random seeds to evaluate (default: original five seeds).",
    )
    parser.add_argument(
        "--output-prefix",
        default="multi_seed_scenario",
        help="Prefix for separate result and summary CSV files.",
    )
    args = parser.parse_args()

    if len(set(args.seeds)) != len(args.seeds):
        parser.error("Seed values must be unique.")

    raw_output = OUTPUT_DIR / f"{args.output_prefix}_results.csv"
    summary_output = OUTPUT_DIR / f"{args.output_prefix}_summary.csv"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []

    total_runs = len(args.seeds) * len(SCENARIOS) * len(WINDOW_SIZES)
    run_number = 0

    for seed in args.seeds:
        for scenario in SCENARIOS:
            print(f"\nSeed {seed} | Scenario: {scenario}", flush=True)
            events = build_processed_events(scenario, seed)
            print(f"Processed events: {len(events)}", flush=True)

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

                rows.append({
                    "seed": seed,
                    "scenario": scenario,
                    "window_hours": window_hours,
                    "target_detected": evaluation["target_detected"],
                    "target_rank": evaluation["target_rank"],
                    "target_temporal_score": target["temporal_score"],
                    "target_composite_score": target["composite_signal"],
                    "highest_normal_score": separation["highest_normal_score"],
                    "absolute_margin": separation["absolute_margin"],
                    "total_alerts": evaluation["total_alerts"],
                    "normal_alerts": evaluation["normal_alerts"],
                })

                run_number += 1
                print(
                    f"[{run_number}/{total_runs}] "
                    f"window={window_hours:>2}h | "
                    f"detected={evaluation['target_detected']} | "
                    f"rank={evaluation['target_rank']} | "
                    f"non_target_alerts={evaluation['normal_alerts']}",
                    flush=True,
                )

    save_rows(rows, raw_output)

    raw = pd.DataFrame(rows)
    summary = (
        raw.groupby(["scenario", "window_hours"], as_index=False)
        .agg(
            runs=("seed", "count"),
            detections=("target_detected", "sum"),
            detection_rate=("target_detected", "mean"),
            mean_composite_score=("target_composite_score", "mean"),
            score_std=("target_composite_score", "std"),
            mean_target_rank=("target_rank", "mean"),
            mean_total_alerts=("total_alerts", "mean"),
            mean_non_target_alerts=("normal_alerts", "mean"),
        )
    )
    summary.to_csv(summary_output, index=False)

    print("\n===== MULTI-SEED EXPERIMENT COMPLETE =====")
    print(f"Evaluations: {len(rows)}")
    print(f"Raw results: {raw_output.relative_to(ROOT)}")
    print(f"Summary:     {summary_output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
