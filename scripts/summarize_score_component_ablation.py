"""Select ablation thresholds on development seeds and evaluate unseen cohorts."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "reports" / "experiment_results"
DEFAULT_INPUT = RESULTS_DIR / "score_component_ablation_60_seed_results.csv"
DEFAULT_OUTPUT = RESULTS_DIR / "score_component_ablation_selected_thresholds.csv"

COHORT_SEEDS = {
    "development_1_20": set(range(1, 21)),
    "heldout_21_40": set(range(21, 41)),
    "replication_41_60": set(range(41, 61)),
}

EXPECTED_VARIANTS = {
    "full_composite",
    "temporal_only",
    "context_only",
    "no_temporal_deviation",
    "no_temporal_zero_variance",
    "no_temporal_magnitude",
    "no_context_sensitive",
    "no_context_transfer",
    "no_context_device",
    "no_context_ip",
}


def evaluate(data: pd.DataFrame) -> dict:
    evaluations = len(data)
    if evaluations == 0:
        raise ValueError("Cannot evaluate an empty cohort.")

    return {
        "evaluations": evaluations,
        "target_detections": int(data["target_detected"].sum()),
        "detection_rate": data["target_detected"].mean(),
        "non_target_alert_windows": int(data["normal_alerts"].sum()),
        "evaluations_with_non_target_alert": int(
            data["any_normal_alert"].sum()
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select ablation thresholds on development seeds only."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input file not found: {args.input}")

    raw = pd.read_csv(args.input)
    required = {
        "seed", "cohort", "variant", "threshold",
        "target_detected", "normal_alerts", "any_normal_alert",
    }
    missing = required - set(raw.columns)
    if missing:
        parser.error(f"Input is missing columns: {sorted(missing)}")

    if len(raw) != 151200:
        parser.error(f"Expected 151200 input rows, found {len(raw)}")
    if set(raw["variant"]) != EXPECTED_VARIANTS:
        parser.error("Input variants do not match the expected ten variants.")

    for cohort, expected_seeds in COHORT_SEEDS.items():
        observed = set(raw.loc[raw["cohort"] == cohort, "seed"])
        if observed != expected_seeds:
            parser.error(f"Unexpected seed membership for {cohort}.")

    rows = []

    for variant in sorted(EXPECTED_VARIANTS):
        development = raw[
            (raw["cohort"] == "development_1_20")
            & (raw["variant"] == variant)
        ]

        candidates = []
        for threshold in sorted(development["threshold"].unique()):
            at_threshold = development[
                development["threshold"] == threshold
            ]
            metrics = evaluate(at_threshold)

            if metrics["non_target_alert_windows"] == 0:
                candidates.append((threshold, metrics))

        if not candidates:
            rows.append({
                "variant": variant,
                "selected_threshold": None,
                "selection_status": "No zero-alert threshold in grid",
            })
            continue

        # Maximize detection on development seeds; choose the lowest
        # threshold if detection rates tie.
        threshold, dev_metrics = min(
            candidates,
            key=lambda item: (
                -item[1]["detection_rate"],
                item[0],
            ),
        )

        row = {
            "variant": variant,
            "selected_threshold": threshold,
            "selection_status": "Selected on development",
        }

        for cohort in (
            "development_1_20",
            "heldout_21_40",
            "replication_41_60",
        ):
            cohort_data = raw[
                (raw["cohort"] == cohort)
                & (raw["variant"] == variant)
                & (raw["threshold"] == threshold)
            ]
            metrics = evaluate(cohort_data)

            for metric, value in metrics.items():
                row[f"{cohort}_{metric}"] = value

        combined = raw[
            (raw["cohort"].isin(COHORT_SEEDS))
            & (raw["variant"] == variant)
            & (raw["threshold"] == threshold)
        ]
        row.update({
            f"combined_1_60_{metric}": value
            for metric, value in evaluate(combined).items()
        })

        # Keep explicit development-selection metrics for auditability.
        row["development_selection_detection_rate"] = dev_metrics[
            "detection_rate"
        ]
        row["development_selection_non_target_alerts"] = dev_metrics[
            "non_target_alert_windows"
        ]

        rows.append(row)

    summary = pd.DataFrame(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    summary.to_csv(args.output, index=False)

    print("===== SELECTED THRESHOLDS AND COHORT RESULTS =====")
    view_columns = [
        "variant",
        "selected_threshold",
        "development_1_20_target_detections",
        "development_1_20_detection_rate",
        "heldout_21_40_target_detections",
        "heldout_21_40_detection_rate",
        "heldout_21_40_non_target_alert_windows",
        "replication_41_60_target_detections",
        "replication_41_60_detection_rate",
        "replication_41_60_non_target_alert_windows",
    ]
    print(summary[view_columns].to_string(
        index=False,
        formatters={
            column: "{:.2%}".format
            for column in (
                "development_1_20_detection_rate",
                "heldout_21_40_detection_rate",
                "replication_41_60_detection_rate",
            )
        },
    ))
    print(f"\nSaved: {args.output.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
