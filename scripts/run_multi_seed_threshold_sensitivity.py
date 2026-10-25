"""Evaluate threshold sensitivity across synthetic seeds and scenarios."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
from pathlib import Path

import pandas as pd

from insider_threat.evaluation.scenario_window_experiments import (
    calculate_window_separation,
    count_threshold_alerts,
    find_target_window,
    rank_target,
)
from insider_threat.evaluation.temporal_window_experiments import (
    build_temporal_window_experiment_results,
)
from insider_threat.preprocessing.normalization import (
    derive_temporal_fields,
    normalize_events,
)
from insider_threat.preprocessing.processed_event import ProcessedEvent
from insider_threat.synthetic.scenario_dataset import build_scenario_dataset


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "reports" / "experiment_results"

SEEDS = tuple(range(1, 21))
SCENARIOS = (
    "sensitive_access_burst",
    "large_transfer",
    "off_hours_new_device",
    "short_anomaly_burst",
)
WINDOW_SIZES = (1, 2, 4, 6, 8, 12, 24)
THRESHOLDS = (0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.60, 0.70)

START_DATE = date(2026, 9, 1)
END_DATE = date(2026, 9, 16)
SCENARIO_DATE = date(2026, 9, 16)
SCENARIO_USER = "USR-003"
MINIMUM_HISTORY = 5


def build_processed_events(scenario: str, seed: int) -> list[ProcessedEvent]:
    """Build and normalize the same seeded synthetic data as the baseline."""
    events = build_scenario_dataset(
        scenario,
        start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
        days=30,
        user_id=SCENARIO_USER,
        seed=seed,
    )
    events = normalize_events(events)

    return [
        ProcessedEvent(
            **event.model_dump(),
            **derive_temporal_fields(event),
        )
        for event in events
    ]


def summarize(
    raw: pd.DataFrame,
    group_fields: list[str],
) -> pd.DataFrame:
    """Aggregate target detection and non-target alert metrics."""
    summary = (
        raw.groupby(group_fields, as_index=False)
        .agg(
            evaluations=("target_detected", "size"),
            target_detections=("target_detected", "sum"),
            detection_rate=("target_detected", "mean"),
            evaluations_with_non_target_alert=(
                "any_normal_alert", "sum"
            ),
            fraction_evaluations_with_non_target_alert=(
                "any_normal_alert", "mean"
            ),
            mean_non_target_alerts_per_evaluation=(
                "normal_alerts", "mean"
            ),
            non_target_alert_windows=("normal_alerts", "sum"),
            total_non_target_windows=("normal_windows", "sum"),
            mean_target_score=("target_composite_score", "mean"),
            mean_highest_normal_score=("highest_normal_score", "mean"),
            mean_absolute_margin=("absolute_margin", "mean"),
        )
    )

    summary["non_target_window_alert_rate"] = (
        summary["non_target_alert_windows"]
        / summary["total_non_target_windows"]
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run multi-seed threshold-sensitivity experiments."
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=list(SEEDS),
        help="Unique seeds to evaluate (default: 1 through 20).",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=list(THRESHOLDS),
        help="Unique thresholds between 0 and 1.",
    )
    parser.add_argument(
        "--output-prefix",
        default="extended_multi_seed_threshold_sensitivity",
        help="Prefix for the three output CSV files.",
    )
    args = parser.parse_args()

    if not args.seeds or len(set(args.seeds)) != len(args.seeds):
        parser.error("Seed values must be non-empty and unique.")
    if not args.thresholds or len(set(args.thresholds)) != len(args.thresholds):
        parser.error("Threshold values must be non-empty and unique.")
    if any(not 0.0 <= t <= 1.0 for t in args.thresholds):
        parser.error("Every threshold must be between 0 and 1.")
    if not args.output_prefix or Path(args.output_prefix).name != args.output_prefix:
        parser.error("Output prefix must be a non-empty filename prefix.")

    outputs = {
        "raw": OUTPUT_DIR / f"{args.output_prefix}_results.csv",
        "summary": OUTPUT_DIR / f"{args.output_prefix}_summary.csv",
        "by_window": OUTPUT_DIR / f"{args.output_prefix}_by_window.csv",
    }
    existing = [str(path) for path in outputs.values() if path.exists()]
    if existing:
        parser.error(
            "Refusing to overwrite existing outputs: "
            + ", ".join(existing)
            + ". Choose another --output-prefix."
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    base_runs = len(args.seeds) * len(SCENARIOS) * len(WINDOW_SIZES)
    run_number = 0

    for seed in args.seeds:
        for scenario in SCENARIOS:
            events = build_processed_events(scenario, seed)
            print(
                f"Seed {seed} | scenario={scenario} "
                f"| processed_events={len(events)}",
                flush=True,
            )

            for window_hours in WINDOW_SIZES:
                results = build_temporal_window_experiment_results(
                    events,
                    start_date=START_DATE,
                    end_date=END_DATE,
                    window_hours=window_hours,
                    minimum_history=MINIMUM_HISTORY,
                )
                target = find_target_window(
                    results,
                    user_id=SCENARIO_USER,
                    target_date=SCENARIO_DATE,
                    window_hours=window_hours,
                )
                separation = calculate_window_separation(results, target)
                normal_windows = len(results) - 1

                if normal_windows < 1:
                    raise RuntimeError(
                        "Expected non-target windows for "
                        f"seed={seed}, scenario={scenario}, "
                        f"window={window_hours}h."
                    )

                for threshold in args.thresholds:
                    total_alerts, normal_alerts, detected = (
                        count_threshold_alerts(
                            results,
                            threshold=threshold,
                            target=target,
                        )
                    )
                    rows.append({
                        "seed": seed,
                        "scenario": scenario,
                        "window_hours": window_hours,
                        "threshold": threshold,
                        "total_windows": len(results),
                        "normal_windows": normal_windows,
                        "target_detected": detected,
                        "target_rank": rank_target(results, target),
                        "target_composite_score": separation["target_score"],
                        "highest_normal_score": separation["highest_normal_score"],
                        "absolute_margin": separation["absolute_margin"],
                        "total_alerts": total_alerts,
                        "normal_alerts": normal_alerts,
                        "any_normal_alert": normal_alerts > 0,
                        "normal_alert_rate": normal_alerts / normal_windows,
                    })

                run_number += 1
                print(
                    f"[{run_number}/{base_runs}] "
                    f"window={window_hours:>2}h | "
                    f"target_score={separation['target_score']:.3f} "
                    f"| highest_normal={separation['highest_normal_score']:.3f}",
                    flush=True,
                )

    raw = pd.DataFrame(rows)
    overall = summarize(raw, ["threshold"]).sort_values("threshold")
    by_window = summarize(raw, ["threshold", "window_hours"]).sort_values(
        ["threshold", "window_hours"]
    )

    raw.to_csv(outputs["raw"], index=False)
    overall.to_csv(outputs["summary"], index=False)
    by_window.to_csv(outputs["by_window"], index=False)

    print("\n===== MULTI-SEED THRESHOLD SENSITIVITY COMPLETE =====")
    print(f"Base evaluations: {base_runs}")
    print(f"Threshold evaluations: {len(raw)}")
    print(f"Seeds: {len(args.seeds)}")
    print(f"Thresholds: {len(args.thresholds)}")
    print("\n===== OVERALL RESULTS =====")
    print(
        overall[
            [
                "threshold",
                "target_detections",
                "evaluations",
                "detection_rate",
                "mean_non_target_alerts_per_evaluation",
                "fraction_evaluations_with_non_target_alert",
                "non_target_window_alert_rate",
            ]
        ].to_string(index=False)
    )
    for key, path in outputs.items():
        print(f"{key}: {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
