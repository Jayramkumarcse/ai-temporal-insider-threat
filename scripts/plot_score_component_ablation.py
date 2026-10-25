"""Visualize component-ablation detection on development and unseen cohorts."""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import PercentFormatter


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = (
    ROOT / "reports" / "experiment_results"
    / "score_component_ablation_selected_thresholds.csv"
)
DEFAULT_OUTPUT = (
    ROOT / "reports" / "figures"
    / "score_component_ablation_selected_thresholds.png"
)

COHORTS = [
    ("development_1_20", "Development\n(seeds 1–20)"),
    ("heldout_21_40", "Held-out\n(seeds 21–40)"),
    ("replication_41_60", "Replication\n(seeds 41–60)"),
]

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plot ablation detection rates across three seed cohorts."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input summary not found: {args.input}")

    df = pd.read_csv(args.input)
    required = {
        "variant",
        "selected_threshold",
        "selection_status",
        "development_1_20_detection_rate",
        "heldout_21_40_detection_rate",
        "replication_41_60_detection_rate",
    }
    missing = required - set(df.columns)
    if missing:
        parser.error(f"Missing input columns: {sorted(missing)}")

    df = df[df["selection_status"] == "Selected on development"].copy()
    if df.empty:
        parser.error("No variants have a selected development threshold.")

    for cohort, _ in COHORTS:
        column = f"{cohort}_detection_rate"
        if df[column].isna().any() or not df[column].between(0, 1).all():
            parser.error(f"Invalid detection rates in {column}")

    df = df.sort_values(
        "development_1_20_detection_rate",
        ascending=True,
    ).reset_index(drop=True)

    fig, axes = plt.subplots(1, 3, figsize=(18, 8), sharey=True)
    fig.suptitle(
        "Score Component Ablation at Development-Selected Thresholds",
        fontsize=14,
        fontweight="bold",
    )

    y_positions = list(range(len(df)))

    for ax, (cohort, title) in zip(axes, COHORTS):
        rate_column = f"{cohort}_detection_rate"
        rates = df[rate_column].astype(float)

        bars = ax.barh(y_positions, rates)
        ax.set_title(title)
        ax.set_xlim(0, 1.08)
        ax.xaxis.set_major_formatter(PercentFormatter(xmax=1.0))
        ax.set_xlabel("Target detection rate")
        ax.set_yticks(y_positions)
        ax.set_yticklabels(df["variant"] if ax is axes[0] else [])
        ax.grid(axis="x", alpha=0.25)
        ax.set_axisbelow(True)

        for bar, rate in zip(bars, rates):
            ax.text(
                min(rate + 0.015, 1.005),
                bar.get_y() + bar.get_height() / 2,
                f"{rate:.1%}",
                va="center",
                fontsize=8,
            )

    # Show the selected threshold alongside each ablation label.
    label_axis = axes[0]
    labels = [
        f"{row.variant} (t={row.selected_threshold:.2f})"
        for row in df.itertuples()
    ]
    label_axis.set_yticklabels(labels, fontsize=8)

    fig.text(
        0.5,
        0.015,
        "Thresholds selected on development seeds only. "
        "Synthetic evaluation; results do not establish real-world false-positive rates.",
        ha="center",
        fontsize=9,
    )
    fig.tight_layout(rect=(0, 0.05, 1, 0.94))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.output, dpi=180, bbox_inches="tight")
    plt.close(fig)

    print(f"Input summary: {args.input}")
    print(f"Figure saved: {args.output}")
    print(f"Variants plotted: {len(df)}")


if __name__ == "__main__":
    main()
