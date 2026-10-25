"""Compare fixed and window-aware thresholds across three seed cohorts."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "reports" / "experiment_results"

COHORTS = {
    "development_1_20": (
        "extended_multi_seed_threshold_sensitivity_results.csv",
        set(range(1, 21)),
    ),
    "heldout_21_40": (
        "holdout_seed21_40_threshold_sensitivity_results.csv",
        set(range(21, 41)),
    ),
    "replication_41_60": (
        "replication_seed41_60_threshold_sensitivity_results.csv",
        set(range(41, 61)),
    ),
}

POLICIES = ("fixed_025", "fixed_030", "window_aware")
KEYS = ["seed", "scenario", "window_hours"]
REQUIRED_COLUMNS = {
    *KEYS,
    "threshold",
    "target_detected",
    "normal_alerts",
    "normal_windows",
    "any_normal_alert",
}

def select_policy(df: pd.DataFrame, policy: str) -> pd.DataFrame:
    """Apply a fixed threshold or the previously selected window-aware rule."""
    if policy == "fixed_025":
        result = df[df["threshold"] == 0.25].copy()
    elif policy == "fixed_030":
        result = df[df["threshold"] == 0.30].copy()
    elif policy == "window_aware":
        result = df[
            (
                (df["window_hours"] <= 8)
                & (df["threshold"] == 0.30)
            )
            | (
                (df["window_hours"] >= 12)
                & (df["threshold"] == 0.25)
            )
        ].copy()
    else:
        raise ValueError(f"Unknown policy: {policy}")

    if len(result) != 560:
        raise ValueError(
            f"{policy}: expected 560 cases, found {len(result)}"
        )
    if result.duplicated(KEYS).any():
        raise ValueError(f"{policy}: duplicate seed/scenario/window cases")

    return result


def calculate_metrics(df: pd.DataFrame) -> dict:
    evaluations = len(df)
    normal_windows = int(df["normal_windows"].sum())
    detections = int(df["target_detected"].sum())
    normal_alerts = int(df["normal_alerts"].sum())
    cases_with_alerts = int(df["any_normal_alert"].sum())

    return {
        "evaluations": evaluations,
        "target_detections": detections,
        "detection_rate": detections / evaluations,
        "non_target_alert_windows": normal_alerts,
        "evaluations_with_non_target_alert": cases_with_alerts,
        "total_non_target_windows": normal_windows,
        "non_target_window_alert_rate": normal_alerts / normal_windows,
    }


def main() -> None:
    cohort_frames = {}

    print("===== INPUT VALIDATION =====")
    for cohort, (filename, expected_seeds) in COHORTS.items():
        path = RESULTS_DIR / filename
        if not path.is_file():
            raise FileNotFoundError(path)

        df = pd.read_csv(path)
        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            raise ValueError(f"{path.name}: missing columns {sorted(missing)}")

        if len(df) != 5040:
            raise ValueError(f"{path.name}: expected 5040 rows, found {len(df)}")
        if set(df["seed"]) != expected_seeds:
            raise ValueError(f"{path.name}: seed range does not match cohort")
        if df.duplicated(KEYS + ["threshold"]).any():
            raise ValueError(f"{path.name}: duplicate evaluation rows")
        if not df.groupby(KEYS).size().eq(9).all():
            raise ValueError(f"{path.name}: each case must have nine thresholds")

        detected_from_score = (
            df["target_composite_score"] >= df["threshold"]
        )
        if not detected_from_score.equals(df["target_detected"].astype(bool)):
            raise ValueError(f"{path.name}: target detection flags mismatch")

        ordered = df.sort_values(KEYS + ["threshold"])
        groups = ordered.groupby(KEYS, sort=False)
        if not groups["target_detected"].diff().fillna(0).le(0).all():
            raise ValueError(f"{path.name}: detection is not threshold-monotonic")
        if not groups["normal_alerts"].diff().fillna(0).le(0).all():
            raise ValueError(f"{path.name}: alerts are not threshold-monotonic")

        cohort_frames[cohort] = df
        print(f"{cohort}: {len(df)} rows, {df['seed'].nunique()} seeds validated")

    summary_rows = []
    window_rows = []
    scenario_rows = []

    for cohort, df in cohort_frames.items():
        for policy in POLICIES:
            selected = select_policy(df, policy)
            metrics = calculate_metrics(selected)
            summary_rows.append({
                "cohort": cohort,
                "policy": policy,
                **metrics,
            })

            if policy != "window_aware":
                continue

            for field, group_fields, target_rows in (
                ("window", ["window_hours"], window_rows),
                ("scenario", ["scenario"], scenario_rows),
            ):
                grouped = (
                    selected.groupby(group_fields, as_index=False)
                    .agg(
                        evaluations=("target_detected", "size"),
                        target_detections=("target_detected", "sum"),
                        detection_rate=("target_detected", "mean"),
                        non_target_alert_windows=("normal_alerts", "sum"),
                    )
                )
                grouped.insert(0, "cohort", cohort)
                target_rows.extend(grouped.to_dict("records"))

    summary = pd.DataFrame(summary_rows)
    by_window = pd.DataFrame(window_rows)
    by_scenario = pd.DataFrame(scenario_rows)

    # Combined results across all 60 seeds.
    combined_rows = []
    for policy in POLICIES:
        selected_parts = [
            select_policy(df, policy)
            for df in cohort_frames.values()
        ]
        combined = pd.concat(selected_parts, ignore_index=True)
        if len(combined) != 1680:
            raise ValueError(f"{policy}: expected 1680 combined cases")
        combined_rows.append({
            "cohort": "combined_1_60",
            "policy": policy,
            **calculate_metrics(combined),
        })

    summary = pd.concat(
        [summary, pd.DataFrame(combined_rows)],
        ignore_index=True,
    )

    candidate_summary = summary[
        (summary["policy"] == "window_aware")
    ]
    if not candidate_summary["non_target_alert_windows"].eq(0).all():
        raise ValueError("Candidate policy produced non-target alerts")

    if not summary[
        summary["cohort"] == "combined_1_60"
    ]["evaluations"].eq(1680).all():
        raise ValueError("Unexpected combined evaluation count")

    outputs = {
        "summary": RESULTS_DIR / "window_aware_policy_cohort_comparison.csv",
        "by_window": RESULTS_DIR / "window_aware_policy_by_window.csv",
        "by_scenario": RESULTS_DIR / "window_aware_policy_by_scenario.csv",
    }
    summary.to_csv(outputs["summary"], index=False)
    by_window.to_csv(outputs["by_window"], index=False)
    by_scenario.to_csv(outputs["by_scenario"], index=False)

    print("\n===== POLICY COMPARISON =====")
    print(
        summary[
            [
                "cohort",
                "policy",
                "target_detections",
                "evaluations",
                "detection_rate",
                "non_target_alert_windows",
                "evaluations_with_non_target_alert",
            ]
        ].to_string(
            index=False,
            formatters={"detection_rate": "{:.2%}".format},
        )
    )

    print("\n===== WINDOW-AWARE POLICY BY WINDOW =====")
    print(
        by_window[
            [
                "cohort",
                "window_hours",
                "evaluations",
                "target_detections",
                "detection_rate",
                "non_target_alert_windows",
            ]
        ].to_string(
            index=False,
            formatters={"detection_rate": "{:.2%}".format},
        )
    )

    for name, path in outputs.items():
        print(f"{name}: {path.relative_to(ROOT)}")

    print("\nAll cohort-comparison validations passed.")


if __name__ == "__main__":
    main()
