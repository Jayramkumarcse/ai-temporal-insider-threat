import numpy as np
import pandas as pd
import pytest

import scripts.analyze_score_component_ablation_uncertainty as analysis


def make_seed_metrics():
    rates = {
        21: ("heldout_21_40", 0.9, 0.7),
        22: ("heldout_21_40", 0.8, 0.7),
        41: ("replication_41_60", 0.8, 0.6),
        42: ("replication_41_60", 0.9, 0.8),
    }

    rows = []
    for seed, (cohort, full_rate, ablated_rate) in rates.items():
        for variant, rate, threshold in (
            ("full_composite", full_rate, 0.30),
            ("temporal_only", ablated_rate, 0.60),
        ):
            rows.append(
                {
                    "seed": seed,
                    "source_cohort": cohort,
                    "variant": variant,
                    "selected_threshold": threshold,
                    "configurations": 10,
                    "target_detections": int(rate * 10),
                    "seed_detection_rate": rate,
                    "non_target_alert_windows": 0,
                    "evaluations_with_any_non_target_alert": 0,
                    "any_non_target_alert": False,
                }
            )

    return pd.DataFrame(rows)


def test_parse_boolean_column_handles_boolean_strings():
    actual = analysis.parse_boolean_column(
        pd.Series(["True", "False", "1", "0", True, False]),
        "test_flag",
    )

    assert actual.tolist() == [True, False, True, False, True, False]


def test_parse_boolean_column_rejects_unknown_values():
    with pytest.raises(ValueError, match="Unrecognized values"):
        analysis.parse_boolean_column(
            pd.Series(["yes", "no"]),
            "test_flag",
        )


def test_bootstrap_mean_ci_is_reproducible_and_bounded():
    values = np.array([0.0, 0.5, 1.0])

    first = analysis.bootstrap_mean_ci(
        values, replicates=2000, random_seed=123
    )
    second = analysis.bootstrap_mean_ci(
        values, replicates=2000, random_seed=123
    )

    assert first == second
    assert first[0] <= values.mean() <= first[1]
    assert 0.0 <= first[0] <= first[1] <= 1.0


@pytest.mark.parametrize(
    ("values", "replicates", "message"),
    [
        ([], 100, "non-empty"),
        ([0.2, np.nan], 100, "finite"),
        ([0.2, np.inf], 100, "finite"),
        ([0.2, 0.8], 0, "at least 1"),
    ],
)
def test_bootstrap_mean_ci_rejects_invalid_inputs(
    values, replicates, message
):
    with pytest.raises(ValueError, match=message):
        analysis.bootstrap_mean_ci(
            np.asarray(values, dtype=float),
            replicates=replicates,
        )


def test_seed_level_metrics_aggregate_configurations_correctly():
    rows = []
    for variant, threshold, detected, alerts in (
        ("full_composite", 0.30, True, 0),
        ("full_composite", 0.30, False, 2),
        ("temporal_only", 0.60, False, 1),
        ("temporal_only", 0.60, True, 0),
    ):
        rows.append(
            {
                "seed": 21,
                "cohort": "heldout_21_40",
                "variant": variant,
                "selected_threshold": threshold,
                "scenario": f"scenario_{len(rows)}",
                "window_hours": 1,
                "target_detected": detected,
                "normal_alerts": alerts,
                "any_normal_alert": alerts > 0,
            }
        )

    result = analysis.build_seed_level_metrics(pd.DataFrame(rows))
    full = result.loc[result["variant"] == "full_composite"].iloc[0]

    assert len(result) == 2
    assert full["configurations"] == 2
    assert full["target_detections"] == 1
    assert full["seed_detection_rate"] == pytest.approx(0.5)
    assert full["non_target_alert_windows"] == 2
    assert full["evaluations_with_any_non_target_alert"] == 1
    assert bool(full["any_non_target_alert"])


def test_analysis_cohorts_include_combined_external_seeds():
    seed_metrics = make_seed_metrics()
    result = analysis.build_analysis_cohorts(seed_metrics)

    combined = result.loc[
        result["analysis_cohort"]
        == "combined_heldout_replication_21_60"
    ]

    assert combined["seed"].nunique() == 4
    assert len(combined) == 8
    assert set(combined["cohort_role"]) == {"external_evaluation"}

    development = result.loc[
        result["analysis_cohort"] == "development_1_20"
    ]
    assert development.empty


def test_confidence_intervals_summarize_seed_level_rates():
    seed_metrics = make_seed_metrics()
    analysis_data = analysis.build_analysis_cohorts(seed_metrics)
    thresholds = pd.DataFrame(
        {
            "variant": ["full_composite", "temporal_only"],
            "selected_threshold": [0.30, 0.60],
        }
    )

    intervals = analysis.summarize_confidence_intervals(
        analysis_data, thresholds
    )
    row = intervals.loc[
        (intervals["cohort"] == "combined_heldout_replication_21_60")
        & (intervals["variant"] == "full_composite")
    ].iloc[0]

    assert row["seed_count"] == 4
    assert row["total_evaluations"] == 40
    assert row["target_detections"] == 34
    assert row["detection_rate"] == pytest.approx(0.85)
    assert row["mean_seed_detection_rate"] == pytest.approx(0.85)
    assert 0.0 <= row["ci95_lower"] <= row["ci95_upper"] <= 1.0


def test_paired_difference_uses_matched_seeds():
    seed_metrics = make_seed_metrics()
    analysis_data = analysis.build_analysis_cohorts(seed_metrics)

    paired = analysis.summarize_paired_differences(analysis_data)
    row = paired.loc[
        (paired["cohort"] == "combined_heldout_replication_21_60")
        & (paired["comparison_variant"] == "temporal_only")
    ].iloc[0]

    assert row["paired_seed_count"] == 4
    assert row["difference_full_minus_variant"] == pytest.approx(0.15)
    assert row["ci95_lower"] <= row["difference_full_minus_variant"]
    assert row["ci95_upper"] >= row["difference_full_minus_variant"]


def test_loader_retains_only_each_variants_selected_threshold(
    tmp_path, monkeypatch
):
    results_path = tmp_path / "results.csv"
    thresholds_path = tmp_path / "thresholds.csv"

    pd.DataFrame(
        [
            {
                "seed": 21,
                "cohort": "heldout_21_40",
                "scenario": "synthetic",
                "window_hours": 1,
                "variant": "full_composite",
                "threshold": 0.20,
                "target_detected": "False",
                "normal_alerts": 3,
                "any_normal_alert": "True",
            },
            {
                "seed": 21,
                "cohort": "heldout_21_40",
                "scenario": "synthetic",
                "window_hours": 1,
                "variant": "full_composite",
                "threshold": 0.30,
                "target_detected": "True",
                "normal_alerts": 0,
                "any_normal_alert": "False",
            },
        ]
    ).to_csv(results_path, index=False)

    pd.DataFrame(
        {
            "variant": ["full_composite"],
            "selected_threshold": [0.30],
        }
    ).to_csv(thresholds_path, index=False)

    monkeypatch.setattr(analysis, "INPUT_RESULTS", results_path)
    monkeypatch.setattr(analysis, "INPUT_THRESHOLDS", thresholds_path)

    selected, _ = analysis.load_selected_threshold_results()

    assert len(selected) == 1
    assert selected.iloc[0]["threshold"] == pytest.approx(0.30)
    assert bool(selected.iloc[0]["target_detected"])
    assert not bool(selected.iloc[0]["any_normal_alert"])
