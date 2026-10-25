"""Plot scenario robustness results from a multi-seed summary CSV."""

import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "reports" / "experiment_results"
OUT = ROOT / "reports" / "figures"
OUT.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(
        description="Plot detection rates and score variability across seeds."
    )
    parser.add_argument(
        "--summary",
        default="multi_seed_scenario_summary.csv",
        help="Summary CSV filename inside reports/experiment_results.",
    )
    parser.add_argument(
        "--output-prefix",
        default="multi_seed",
        help="Prefix for generated figure filenames.",
    )
    args = parser.parse_args()

    summary_path = DATA / args.summary
    if not summary_path.is_file():
        raise FileNotFoundError(f"Summary CSV not found: {summary_path}")

    df = pd.read_csv(summary_path)
    required = {
        "scenario",
        "window_hours",
        "runs",
        "detection_rate",
        "mean_composite_score",
        "score_std",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing CSV columns: {sorted(missing)}")

    if df.empty:
        raise ValueError(f"Summary CSV is empty: {summary_path}")

    seed_count = int(df["runs"].max())

    # Figure 1: detection rate across background-generation seeds.
    fig, ax = plt.subplots(figsize=(9, 5))
    for scenario, group in df.groupby("scenario"):
        group = group.sort_values("window_hours")
        ax.plot(
            group["window_hours"],
            group["detection_rate"],
            marker="o",
            label=scenario.replace("_", " "),
        )

    ax.set(
        title=f"Target Detection Rate Across {seed_count} Seeds",
        xlabel="Temporal window (hours)",
        ylabel="Detection rate",
        ylim=(-0.05, 1.05),
    )
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()

    detection_path = OUT / f"{args.output_prefix}_detection_rate.png"
    fig.savefig(detection_path, dpi=180, bbox_inches="tight")
    plt.close(fig)

    # Figure 2: mean target score and between-seed standard deviation.
    fig, ax = plt.subplots(figsize=(9, 5))
    for scenario, group in df.groupby("scenario"):
        group = group.sort_values("window_hours")
        ax.errorbar(
            group["window_hours"],
            group["mean_composite_score"],
            yerr=group["score_std"].fillna(0),
            marker="o",
            capsize=3,
            label=scenario.replace("_", " "),
        )

    ax.set(
        title=f"Target Score Variability Across {seed_count} Seeds",
        xlabel="Temporal window (hours)",
        ylabel="Mean composite score ± standard deviation",
    )
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()

    variability_path = OUT / f"{args.output_prefix}_score_variability.png"
    fig.savefig(variability_path, dpi=180, bbox_inches="tight")
    plt.close(fig)

    print(f"Input summary: {summary_path.relative_to(ROOT)}")
    print(f"Saved: {detection_path.relative_to(ROOT)}")
    print(f"Saved: {variability_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
