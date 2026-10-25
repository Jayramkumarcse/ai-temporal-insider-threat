#!/usr/bin/env python3
"""Seed-cluster bootstrap analysis for score-component ablation results.

Bootstrap units are random seeds, not individual overlapping windows.
Confidence intervals describe variation across synthetic seeds and do not
establish real-world false-positive rates.
"""

from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "reports" / "experiment_results"

INPUT_RESULTS = RESULTS_DIR / "score_component_ablation_60_seed_results.csv"
INPUT_THRESHOLDS = (
    RESULTS_DIR / "score_component_ablation_selected_thresholds.csv"
)

OUTPUT_SEEDS = (
    RESULTS_DIR / "score_component_ablation_seed_level_performance.csv"
)
OUTPUT_INTERVALS = (
    RESULTS_DIR / "score_component_ablation_bootstrap_confidence_intervals.csv"
)
OUTPUT_PAIRED = (
    RESULTS_DIR / "score_component_ablation_paired_differences.csv"
)

BOOTSTRAP_REPLICATES = 10_000
BOOTSTRAP_SEED = 20261025
REFERENCE_VARIANT = "full_composite"


def parse_boolean_column(series: pd.Series, name: str) -> pd.Series:
    """Parse CSV boolean values without interpreting 'False' as True."""
    if pd.api.types.is_bool_dtype(series):
        return series.astype(bool)

    mapping = {
        "true": True,
        "false": False,
        "1": True,
        "0": False,
    }
    parsed = series.astype(str).str.strip().str.lower().map(mapping)

    if parsed.isna().any():
        invalid = series[parsed.isna()].unique().tolist()
        raise ValueError(f"Unrecognized values in {name}: {invalid}")

    return parsed.astype(bool)


def bootstrap_mean_ci(
    values: np.ndarray,
    *,
    replicates: int = BOOTSTRAP_REPLICATES,
    random_seed: int = BOOTSTRAP_SEED,
) -> tuple[float, float]:
    """Return a percentile 95% CI by resampling independent seed-level units."""
    values = np.asarray(values, dtype=float)

    if values.ndim != 1 or values.size == 0:
        raise ValueError("Bootstrap values must be a non-empty 1-D array.")
    if not np.isfinite(values).all():
        raise ValueError("Bootstrap values must all be finite.")
    if replicates < 1:
        raise ValueError("replicates must be at least 1.")

    rng = np.random.default_rng(random_seed)
    indexes = rng.integers(
        low=0,
        high=len(values),
        size=(replicates, len(values)),
    )
    bootstrap_means = values[indexes].mean(axis=1)
    lower, upper = np.quantile(bootstrap_means, [0.025, 0.975])

    return float(lower), float(upper)


def load_selected_threshold_results() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load the experiment data and retain each variant's chosen threshold."""
    if not INPUT_RESULTS.exists():
        raise FileNotFoundError(f"Missing results file: {INPUT_RESULTS}")
    if not INPUT_THRESHOLDS.exists():
        raise FileNotFoundError(f"Missing threshold file: {INPUT_THRESHOLDS}")

    results = pd.read_csv(INPUT_RESULTS)
    thresholds = pd.read_csv(INPUT_THRESHOLDS)

    required_results = {
        "seed",
        "cohort",
        "scenario",
        "window_hours",
        "variant",
        "threshold",
        "target_detected",
        "normal_alerts",
        "any_normal_alert",
    }
    missing = required_results - set(results.columns)
    if missing:
        raise ValueError(f"Results file is missing columns: {sorted(missing)}")

    required_thresholds = {"variant", "selected_threshold"}
    missing = required_thresholds - set(thresholds.columns)
    if missing:
        raise ValueError(
            f"Threshold file is missing columns: {sorted(missing)}"
        )

    if thresholds["variant"].duplicated().any():
        raise ValueError("Threshold file has duplicate variant entries.")

    threshold_map = thresholds.set_index("variant")["selected_threshold"]
    results["selected_threshold"] = results["variant"].map(threshold_map)

    if results["selected_threshold"].isna().any():
        unknown = results.loc[
            results["selected_threshold"].isna(), "variant"
        ].unique().tolist()
        raise ValueError(f"No selected threshold for variants: {unknown}")

    selected_mask = np.isclose(
        results["threshold"].to_numpy(dtype=float),
        results["selected_threshold"].to_numpy(dtype=float),
        rtol=0.0,
        atol=1e-9,
    )
    selected = results.loc[selected_mask].copy()

    selected["target_detected"] = parse_boolean_column(
        selected["target_detected"], "target_detected"
    )
    selected["any_normal_alert"] = parse_boolean_column(
        selected["any_normal_alert"], "any_normal_alert"
    )
    selected["normal_alerts"] = pd.to_numeric(
        selected["normal_alerts"], errors="raise"
    )

    if selected.empty:
        raise ValueError("No rows match the selected thresholds.")

    duplicate_keys = [
        "seed",
        "scenario",
        "window_hours",
        "variant",
    ]
    if selected.duplicated(duplicate_keys).any():
        raise ValueError("Duplicate seed/scenario/window/variant records found.")

    expected_configs = selected[
        ["scenario", "window_hours"]
    ].drop_duplicates().shape[0]

    counts = selected.groupby(
        ["seed", "cohort", "variant"], observed=True
    ).size()

    if not (counts == expected_configs).all():
        bad = counts[counts != expected_configs].head(10)
        raise ValueError(
            "Incomplete seed-level scenario/window coverage. "
            f"Examples:\n{bad}"
        )

    if REFERENCE_VARIANT not in set(selected["variant"]):
        raise ValueError(f"Missing reference variant: {REFERENCE_VARIANT}")

    return selected, thresholds


def build_seed_level_metrics(
    selected: pd.DataFrame,
) -> pd.DataFrame:
    """Aggregate the 28 scenario/window configurations into seed-level units."""
    seed_metrics = (
        selected.groupby(
            ["seed", "cohort", "variant", "selected_threshold"],
            as_index=False,
            observed=True,
        )
        .agg(
            configurations=("target_detected", "size"),
            target_detections=("target_detected", "sum"),
            seed_detection_rate=("target_detected", "mean"),
            non_target_alert_windows=("normal_alerts", "sum"),
            evaluations_with_any_non_target_alert=(
                "any_normal_alert",
                "sum",
            ),
            any_non_target_alert=("any_normal_alert", "max"),
        )
        .rename(columns={"cohort": "source_cohort"})
    )

    return seed_metrics


def build_analysis_cohorts(seed_metrics: pd.DataFrame) -> pd.DataFrame:
    """Create source-cohort summaries plus the combined seeds 21–60 cohort."""
    frames = []

    for cohort in sorted(seed_metrics["source_cohort"].unique()):
        frame = seed_metrics.loc[
            seed_metrics["source_cohort"] == cohort
        ].copy()
        frame["analysis_cohort"] = cohort
        frame["cohort_role"] = (
            "threshold_selection"
            if "development" in cohort.lower()
            else "external_evaluation"
        )
        frames.append(frame)

    external_names = {"heldout_21_40", "replication_41_60"}
    available_external = set(seed_metrics["source_cohort"].unique())
    missing_external = external_names - available_external

    if missing_external:
        raise ValueError(
            "Expected held-out and replication cohorts; missing: "
            f"{sorted(missing_external)}"
        )

    combined = seed_metrics.loc[
        seed_metrics["source_cohort"].isin(external_names)
    ].copy()
    combined["analysis_cohort"] = "combined_heldout_replication_21_60"
    combined["cohort_role"] = "external_evaluation"
    frames.append(combined)

    return pd.concat(frames, ignore_index=True)


def summarize_confidence_intervals(
    analysis_data: pd.DataFrame,
    thresholds: pd.DataFrame,
) -> pd.DataFrame:
    """Estimate detection-rate intervals by resampling seed-level rates."""
    chosen = thresholds.set_index("variant")["selected_threshold"].to_dict()
    rows = []

    for (cohort, variant), group in analysis_data.groupby(
        ["analysis_cohort", "variant"], sort=True, observed=True
    ):
        group = group.sort_values("seed")
        seed_rates = group["seed_detection_rate"].to_numpy(dtype=float)
        ci_lower, ci_upper = bootstrap_mean_ci(seed_rates)

        configurations = int(group["configurations"].sum())
        detections = int(group["target_detections"].sum())

        rows.append(
            {
                "cohort": cohort,
                "cohort_role": group["cohort_role"].iloc[0],
                "variant": variant,
                "selected_threshold": float(chosen[variant]),
                "seed_count": int(group["seed"].nunique()),
                "configurations_per_seed": int(
                    group["configurations"].iloc[0]
                ),
                "total_evaluations": configurations,
                "target_detections": detections,
                "detection_rate": detections / configurations,
                "mean_seed_detection_rate": float(seed_rates.mean()),
                "seed_level_detection_rate_sd": float(
                    seed_rates.std(ddof=1)
                )
                if len(seed_rates) > 1
                else 0.0,
                "ci95_lower": ci_lower,
                "ci95_upper": ci_upper,
                "non_target_alert_windows": int(
                    group["non_target_alert_windows"].sum()
                ),
                "evaluations_with_any_non_target_alert": int(
                    group["evaluations_with_any_non_target_alert"].sum()
                ),
                "seeds_with_any_non_target_alert": int(
                    group["any_non_target_alert"].sum()
                ),
            }
        )

    return pd.DataFrame(rows)


def summarize_paired_differences(
    analysis_data: pd.DataFrame,
) -> pd.DataFrame:
    """Bootstrap per-seed paired detection-rate differences vs full composite."""
    rows = []

    for cohort, group in analysis_data.groupby(
        "analysis_cohort", sort=True, observed=True
    ):
        wide = group.pivot(
            index="seed",
            columns="variant",
            values="seed_detection_rate",
        ).sort_index()

        if wide[REFERENCE_VARIANT].isna().any():
            raise ValueError(
                f"Missing reference scores in analysis cohort {cohort}"
            )

        reference = wide[REFERENCE_VARIANT].to_numpy(dtype=float)

        for variant in sorted(wide.columns):
            if variant == REFERENCE_VARIANT:
                continue

            comparison = wide[variant].to_numpy(dtype=float)
            differences = reference - comparison
            ci_lower, ci_upper = bootstrap_mean_ci(differences)

            rows.append(
                {
                    "cohort": cohort,
                    "reference_variant": REFERENCE_VARIANT,
                    "comparison_variant": variant,
                    "paired_seed_count": int(len(differences)),
                    "full_composite_detection_rate": float(reference.mean()),
                    "comparison_detection_rate": float(comparison.mean()),
                    "difference_full_minus_variant": float(
                        differences.mean()
                    ),
                    "ci95_lower": ci_lower,
                    "ci95_upper": ci_upper,
                }
            )

    return pd.DataFrame(rows)


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    selected, thresholds = load_selected_threshold_results()
    seed_metrics = build_seed_level_metrics(selected)
    analysis_data = build_analysis_cohorts(seed_metrics)

    intervals = summarize_confidence_intervals(analysis_data, thresholds)
    paired = summarize_paired_differences(analysis_data)

    seed_metrics_path_data = analysis_data.sort_values(
        ["analysis_cohort", "variant", "seed"]
    )

    seed_metrics_path_data.to_csv(OUTPUT_SEEDS, index=False)
    intervals.to_csv(OUTPUT_INTERVALS, index=False)
    paired.to_csv(OUTPUT_PAIRED, index=False)

    print("Seed-cluster bootstrap analysis completed.")
    print(f"Input rows: {len(pd.read_csv(INPUT_RESULTS)):,}")
    print(f"Selected-threshold rows: {len(selected):,}")
    print(
        "Independent seed units per source cohort:",
        seed_metrics.groupby("source_cohort")["seed"].nunique().to_dict(),
    )
    print(f"Bootstrap replicates per interval: {BOOTSTRAP_REPLICATES:,}")
    print(f"Random seed: {BOOTSTRAP_SEED}")

    print("\n===== EXTERNAL-EVALUATION DETECTION-RATE INTERVALS =====")
    external = intervals.loc[
        intervals["cohort"].isin(
            [
                "heldout_21_40",
                "replication_41_60",
                "combined_heldout_replication_21_60",
            ]
        ),
        [
            "cohort",
            "variant",
            "selected_threshold",
            "seed_count",
            "target_detections",
            "total_evaluations",
            "detection_rate",
            "ci95_lower",
            "ci95_upper",
            "seeds_with_any_non_target_alert",
        ],
    ].copy()

    for column in ["detection_rate", "ci95_lower", "ci95_upper"]:
        external[column] = (100 * external[column]).round(2)

    print(
        external.sort_values(["cohort", "variant"]).to_string(index=False)
    )

    print("\n===== PAIRED DIFFERENCES: FULL COMPOSITE MINUS ABLATION =====")
    paired_external = paired.loc[
        paired["cohort"].isin(
            [
                "heldout_21_40",
                "replication_41_60",
                "combined_heldout_replication_21_60",
            ]
        ),
        [
            "cohort",
            "comparison_variant",
            "paired_seed_count",
            "difference_full_minus_variant",
            "ci95_lower",
            "ci95_upper",
        ],
    ].copy()

    for column in [
        "difference_full_minus_variant",
        "ci95_lower",
        "ci95_upper",
    ]:
        paired_external[column] = (
            100 * paired_external[column]
        ).round(2)

    print(
        paired_external.sort_values(
            ["cohort", "comparison_variant"]
        ).to_string(index=False)
    )

    print("\n===== OUTPUT FILES =====")
    for path in [OUTPUT_SEEDS, OUTPUT_INTERVALS, OUTPUT_PAIRED]:
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
