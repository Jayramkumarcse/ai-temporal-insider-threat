"""Generate research figures from committed experiment CSV files."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "reports" / "experiment_results"
OUT = ROOT / "reports" / "figures"
OUT.mkdir(parents=True, exist_ok=True)


def save_figure(fig, filename):
    fig.tight_layout()
    path = OUT / filename
    fig.savefig(path, dpi=180, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {path.relative_to(ROOT)}")


def load_results(filename):
    path = DATA / filename
    if not path.is_file():
        raise FileNotFoundError(f"Experiment CSV not found: {path}")
    return pd.read_csv(path)


def plot_temporal_windows():
    df = load_results("temporal_window_comparison.csv").sort_values(
        "window_hours"
    )
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(df["window_hours"], df["target_temporal_score"],
            marker="o", label="Temporal score")
    ax.plot(df["window_hours"], df["target_composite_signal"],
            marker="s", label="Composite score")
    ax.set(title="Anomaly Score by Temporal Window",
           xlabel="Window size (hours)", ylabel="Target anomaly score")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_figure(fig, "temporal_window_comparison.png")


def plot_thresholds():
    df = load_results("threshold_sensitivity.csv").sort_values("threshold")
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(df["threshold"], df["alerts"], marker="o",
            label="Total alerts")
    ax.plot(df["threshold"], df["normal_alerts"], marker="s",
            label="Non-target alerts")
    ax.set(title="Alert Counts by Threshold",
           xlabel="Alert threshold", ylabel="Number of alerts")
    ax.legend()
    ax.grid(True, alpha=0.3)
    save_figure(fig, "threshold_sensitivity.png")


def plot_scenarios():
    df = load_results("scenario_window_comparison.csv")
    fig, ax = plt.subplots(figsize=(9, 5))

    for scenario, group in df.groupby("scenario"):
        group = group.sort_values("window_hours")
        ax.plot(
            group["window_hours"],
            group["target_composite_signal"],
            marker="o",
            label=scenario.replace("_", " "),
        )

    ax.set(
        title="Anomaly Score Across Synthetic Scenarios",
        xlabel="Window size (hours)",
        ylabel="Target composite score",
    )
    ax.legend(fontsize=8)
    ax.grid(True, alpha=0.3)
    save_figure(fig, "scenario_window_comparison.png")


def plot_time_of_day():
    df = load_results("time_of_day_comparison.csv")
    scores = df.pivot(
        index="anomaly_hour",
        columns="window_hours",
        values="target_composite_signal",
    ).sort_index()

    scores = scores.reindex(sorted(scores.columns), axis=1)

    fig, ax = plt.subplots(figsize=(9, 5))
    image = ax.imshow(scores.values, aspect="auto", origin="lower")
    ax.set_xticks(range(len(scores.columns)))
    ax.set_xticklabels(scores.columns)
    ax.set_yticks(range(len(scores.index)))
    ax.set_yticklabels(scores.index)
    ax.set(
        title="Target Composite Score by Anomaly Time and Window",
        xlabel="Window size (hours)",
        ylabel="Anomaly hour (UTC)",
    )
    fig.colorbar(image, ax=ax, label="Target composite score")
    save_figure(fig, "time_of_day_comparison.png")


def main():
    plot_temporal_windows()
    plot_thresholds()
    plot_scenarios()
    plot_time_of_day()


if __name__ == "__main__":
    main()
