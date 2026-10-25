"""Plot multi-seed scenario robustness results."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "reports" / "experiment_results"
OUT = ROOT / "reports" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

SUMMARY = DATA / "multi_seed_scenario_summary.csv"


def main():
    df = pd.read_csv(SUMMARY)
    required = {
        "scenario", "window_hours", "detection_rate",
        "mean_composite_score", "score_std",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing CSV columns: {sorted(missing)}")

    # Figure 1: detection rate across background seeds.
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
        title="Multi-Seed Target Detection Rate",
        xlabel="Temporal window (hours)",
        ylabel="Detection rate across five seeds",
        ylim=(-0.05, 1.05),
    )
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "multi_seed_detection_rate.png",
                dpi=180, bbox_inches="tight")
    plt.close(fig)

    # Figure 2: mean target score, with between-seed standard deviation.
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
        title="Multi-Seed Target Score and Variability",
        xlabel="Temporal window (hours)",
        ylabel="Mean target composite score ± standard deviation",
    )
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "multi_seed_score_variability.png",
                dpi=180, bbox_inches="tight")
    plt.close(fig)

    print("Saved: reports/figures/multi_seed_detection_rate.png")
    print("Saved: reports/figures/multi_seed_score_variability.png")


if __name__ == "__main__":
    main()
