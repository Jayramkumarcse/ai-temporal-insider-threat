"""Plot threshold sensitivity from multi-seed experiment summary CSVs."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import PercentFormatter


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUMMARY = (
    ROOT / "reports" / "experiment_results"
    / "extended_multi_seed_threshold_sensitivity_summary.csv"
)
DEFAULT_OUTPUT = (
    ROOT / "reports" / "figures"
    / "extended_multi_seed_threshold_sensitivity.png"
)

REQUIRED_COLUMNS = {
    "threshold",
    "detection_rate",
    "fraction_evaluations_with_non_target_alert",
    "non_target_window_alert_rate",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot detection and non-target alert rates by threshold."
    )
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.summary.is_file():
        parser.error(f"Summary CSV not found: {args.summary}")

    df = pd.read_csv(args.summary)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        parser.error(f"Summary CSV is missing columns: {sorted(missing)}")
    if df.empty or df["threshold"].duplicated().any():
        parser.error("Summary must contain one row per threshold.")

    df = df.sort_values("threshold")
    rate_columns = [
        "detection_rate",
        "fraction_evaluations_with_non_target_alert",
        "non_target_window_alert_rate",
    ]
    for column in rate_columns:
        if df[column].isna().any() or not df[column].between(0, 1).all():
            parser.error(f"Invalid rate values in column: {column}")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    thresholds = df["threshold"]
    detection = df["detection_rate"]
    evaluation_alerts = df["fraction_evaluations_with_non_target_alert"]
    window_alerts = df["non_target_window_alert_rate"]

    fig, axes = plt.subplots(3, 1, figsize=(10, 11), sharex=True)
    fig.suptitle(
        "Threshold Sensitivity Across Synthetic Seeds",
        fontsize=15,
        fontweight="bold",
    )

    panels = [
        (
            axes[0],
            detection,
            "Target detection rate",
            "Share of target cases detected",
        ),
        (
            axes[1],
            evaluation_alerts,
            "Evaluations with at least one non-target alert",
            "Share of evaluations",
        ),
        (
            axes[2],
            window_alerts,
            "Non-target window alert rate",
            "Share of evaluated non-target windows",
        ),
    ]

    for ax, values, title, ylabel in panels:
        ax.plot(thresholds, values, marker="o", linewidth=2)
        ax.axvline(0.30, linestyle="--", linewidth=1.2, label="Threshold 0.30")
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        ax.set_title(title, loc="left", fontsize=11)
        ax.set_ylabel(ylabel)
        ax.grid(True, alpha=0.3)
        ax.legend(loc="best")

    axes[-1].set_xlabel("Alert threshold")
    axes[-1].set_xticks(thresholds)
    axes[-1].set_xlim(
        float(thresholds.min()) - 0.025,
        float(thresholds.max()) + 0.025,
    )

    fig.text(
        0.5,
        0.015,
        "Synthetic evaluation only. Window populations overlap across runs; "
        "rates are not independent real-world false-positive estimates.",
        ha="center",
        fontsize=9,
    )
    fig.tight_layout(rect=(0, 0.04, 1, 0.96))
    fig.savefig(args.output, dpi=180, bbox_inches="tight")
    plt.close(fig)

    print(f"Summary CSV: {args.summary}")
    print(f"Figure saved: {args.output}")
    print(f"Thresholds plotted: {len(df)}")


if __name__ == "__main__":
    main()
