"""Run controlled ablations of temporal and security-context score components."""

from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from datetime import date, datetime, timezone
from math import isclose
from pathlib import Path

import pandas as pd

from insider_threat.evaluation.scenario_window_experiments import (
    find_target_window,
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
TARGET_DATE = date(2026, 9, 16)
TARGET_USER = "USR-003"
MINIMUM_HISTORY = 5

CONTEXT_KEYS = (
    "sensitive",
    "transfer",
    "device",
    "ip",
)

CONTEXT_COLUMNS = {
    "sensitive": "context_sensitive_signal",
    "transfer": "context_transfer_signal",
    "device": "context_device_signal",
    "ip": "context_ip_signal",
}

VARIANTS = (
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
)


def cohort_for_seed(seed: int) -> str:
    if 1 <= seed <= 20:
        return "development_1_20"
    if 21 <= seed <= 40:
        return "heldout_21_40"
    if 41 <= seed <= 60:
        return "replication_41_60"
    return "custom_seeds"


def build_processed_events(scenario: str, seed: int) -> list[ProcessedEvent]:
    """Reproduce the event preparation used by the existing seed experiments."""
    events = build_scenario_dataset(
        scenario,
        start_date=datetime(2026, 9, 1, tzinfo=timezone.utc),
        days=30,
        user_id=TARGET_USER,
        seed=seed,
    )
    normalized = normalize_events(events)

    return [
        ProcessedEvent(
            **event.model_dump(),
            **derive_temporal_fields(event),
        )
        for event in normalized
    ]


def weighted_mean(values: tuple[float, ...], weights: tuple[float, ...]) -> float:
    """Normalize weights across the components retained in an ablation."""
    if len(values) != len(weights) or not values:
        raise ValueError("Values and weights must be non-empty and equally sized.")
    total = sum(weights)
    if total <= 0:
        raise ValueError("At least one weight must be positive.")
    return sum(value * weight for value, weight in zip(values, weights)) / total


def score_variants(result: dict) -> dict[str, float]:
    """Calculate all ablation scores from one set of unchanged component values."""
    temporal = float(result["temporal_score"])
    context = float(result["context_signal"])

    deviation = float(result["temporal_deviation_coverage"])
    zero_variance = float(result["temporal_zero_variance_coverage"])
    magnitude = float(result["temporal_magnitude_signal"])

    temporal_parts = {
        "deviation": deviation,
        "zero_variance": zero_variance,
        "magnitude": magnitude,
    }

    # Reconstruct the standard temporal score and verify the observed baseline.
    reconstructed_temporal = weighted_mean(
        (deviation, zero_variance, magnitude),
        (0.5, 0.3, 0.2),
    )
    if not isclose(temporal, reconstructed_temporal, abs_tol=1e-12):
        raise ValueError("Diagnostic temporal components do not reproduce the baseline.")

    reconstructed_composite = (temporal + context) / 2.0
    if not isclose(
        float(result["composite_signal"]),
        reconstructed_composite,
        abs_tol=1e-12,
    ):
        raise ValueError("Temporal and context signals do not reproduce the baseline composite.")

    scores = {
        # Direct baseline plus signal-level comparisons.
        "full_composite": float(result["composite_signal"]),
        "temporal_only": temporal,
        "context_only": context,

        # Remove one temporal component; renormalize remaining original weights.
        "no_temporal_deviation": (
            weighted_mean((zero_variance, magnitude), (0.3, 0.2)) + context
        ) / 2.0,
        "no_temporal_zero_variance": (
            weighted_mean((deviation, magnitude), (0.5, 0.2)) + context
        ) / 2.0,
        "no_temporal_magnitude": (
            weighted_mean((deviation, zero_variance), (0.5, 0.3)) + context
        ) / 2.0,
    }

    context_values = {
        key: float(result[column])
        for key, column in CONTEXT_COLUMNS.items()
    }

    # Remove one context component; average the remaining three.
    for removed in CONTEXT_KEYS:
        remaining = [
            value for key, value in context_values.items()
            if key != removed
        ]
        ablated_context = sum(remaining) / len(remaining)
        scores[f"no_context_{removed}"] = (
            temporal + ablated_context
        ) / 2.0

    if set(scores) != set(VARIANTS):
        raise ValueError("Not all ablation variants were computed.")
    if any(not 0.0 <= score <= 1.0 for score in scores.values()):
        raise ValueError("Ablation scores must remain in [0, 1].")

    return scores


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
            non_target_alert_windows=("normal_alerts", "sum"),
            evaluations_with_non_target_alert=("any_normal_alert", "sum"),
            total_non_target_windows=("normal_windows", "sum"),
            mean_target_score=("target_score", "mean"),
            mean_highest_normal_score=("highest_normal_score", "mean"),
        )
    )
    summary["non_target_window_alert_rate"] = (
        summary["non_target_alert_windows"]
        / summary["total_non_target_windows"]
    )
    return summary


def add_combined_summary(
    raw: pd.DataFrame,
    group_fields: list[str],
    grouped: pd.DataFrame,
    combined_label: str,
) -> pd.DataFrame:
    """Add a pooled summary across all seeds provided to this run."""
    pooled_fields = [field for field in group_fields if field != "cohort"]
    combined = summarize(raw, pooled_fields)
    combined.insert(0, "cohort", combined_label)
    return pd.concat([grouped, combined], ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare temporal/context scoring ablations across synthetic seeds."
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=list(range(1, 61)),
        help="Unique synthetic-data seeds (default: 1 through 60).",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=list(THRESHOLDS),
        help="Unique alert thresholds between 0 and 1.",
    )
    parser.add_argument(
        "--output-prefix",
        default="score_component_ablation_60_seed",
        help="Prefix for four separate CSV files.",
    )
    args = parser.parse_args()

    if not args.seeds or len(set(args.seeds)) != len(args.seeds):
        parser.error("Seeds must be non-empty and unique.")
    if not args.thresholds or len(set(args.thresholds)) != len(args.thresholds):
        parser.error("Thresholds must be non-empty and unique.")
    if any(not 0.0 <= threshold <= 1.0 for threshold in args.thresholds):
        parser.error("Each threshold must be between 0 and 1.")
    if (
        not args.output_prefix
        or Path(args.output_prefix).name != args.output_prefix
    ):
        parser.error("Output prefix must be a non-empty filename prefix.")

    outputs = {
        "results": OUTPUT_DIR / f"{args.output_prefix}_results.csv",
        "summary": OUTPUT_DIR / f"{args.output_prefix}_summary.csv",
        "by_window": OUTPUT_DIR / f"{args.output_prefix}_by_window.csv",
        "by_scenario": OUTPUT_DIR / f"{args.output_prefix}_by_scenario.csv",
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

    base_cases = len(args.seeds) * len(SCENARIOS) * len(WINDOW_SIZES)
    case_number = 0

    for seed in args.seeds:
        for scenario in SCENARIOS:
            events = build_processed_events(scenario, seed)
            print(
                f"Seed {seed} | scenario={scenario} | events={len(events)}",
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
                    user_id=TARGET_USER,
                    target_date=TARGET_DATE,
                    window_hours=window_hours,
                )
                target_index = results.index(target)
                normal_count = len(results) - 1
                if normal_count < 1:
                    raise RuntimeError("Expected non-target scored windows.")

                scores_by_variant = {variant: [] for variant in VARIANTS}
                for result in results:
                    scores = score_variants(result)
                    for variant, score in scores.items():
                        scores_by_variant[variant].append(score)

                for variant, all_scores in scores_by_variant.items():
                    target_score = all_scores[target_index]
                    normal_scores = sorted(
                        score for i, score in enumerate(all_scores)
                        if i != target_index
                    )
                    highest_normal = normal_scores[-1] if normal_scores else 0.0
                    target_rank = (
                        1 + len(normal_scores)
                        - bisect_right(normal_scores, target_score)
                    )

                    for threshold in args.thresholds:
                        normal_alerts = len(normal_scores) - bisect_left(
                            normal_scores, threshold
                        )
                        target_detected = target_score >= threshold

                        rows.append({
                            "seed": seed,
                            "cohort": cohort_for_seed(seed),
                            "scenario": scenario,
                            "window_hours": window_hours,
                            "variant": variant,
                            "threshold": threshold,
                            "evaluated_windows": len(results),
                            "normal_windows": normal_count,
                            "target_score": target_score,
                            "highest_normal_score": highest_normal,
                            "target_margin": target_score - highest_normal,
                            "target_rank": target_rank,
                            "target_detected": target_detected,
                            "normal_alerts": normal_alerts,
                            "total_alerts": normal_alerts + int(target_detected),
                            "any_normal_alert": normal_alerts > 0,
                            "normal_alert_rate": normal_alerts / normal_count,
                        })

                case_number += 1
                print(
                    f"[{case_number}/{base_cases}] window={window_hours:>2}h | "
                    f"target baseline={float(target['composite_signal']):.3f}",
                    flush=True,
                )

    raw = pd.DataFrame(rows)

    summary = summarize(raw, ["cohort", "variant", "threshold"])
    window_summary = summarize(
        raw, ["cohort", "variant", "threshold", "window_hours"]
    )
    scenario_summary = summarize(
        raw, ["cohort", "variant", "threshold", "scenario"]
    )

    combined_label = "combined_selected_seeds"
    summary = add_combined_summary(
        raw, ["cohort", "variant", "threshold"], summary, combined_label
    )
    window_summary = add_combined_summary(
        raw,
        ["cohort", "variant", "threshold", "window_hours"],
        window_summary,
        combined_label,
    )
    scenario_summary = add_combined_summary(
        raw,
        ["cohort", "variant", "threshold", "scenario"],
        scenario_summary,
        combined_label,
    )

    # The full composite variant must exactly reproduce the established
    # baseline detection and alert counts at every threshold and case.
    full = raw[raw["variant"] == "full_composite"]
    expected_rows = len(args.seeds) * len(SCENARIOS) * len(WINDOW_SIZES) * len(args.thresholds)
    if len(full) != expected_rows:
        raise ValueError("Unexpected number of full-composite rows.")

    for key, path in outputs.items():
        frame = {
            "results": raw,
            "summary": summary,
            "by_window": window_summary,
            "by_scenario": scenario_summary,
        }[key]
        frame.to_csv(path, index=False)

    print("\n===== ABLATION EXPERIMENT COMPLETE =====")
    print(f"Seeds: {len(args.seeds)}")
    print(f"Base cases: {base_cases}")
    print(f"Variants: {len(VARIANTS)}")
    print(f"Thresholds: {len(args.thresholds)}")
    print(f"Raw ablation rows: {len(raw)}")

    print("\n===== FULL COMPOSITE AT THRESHOLD 0.30 =====")
    baseline_summary = summary[
        (summary["variant"] == "full_composite")
        & (summary["threshold"] == 0.30)
    ]
    cols = [
        "cohort", "evaluations", "target_detections",
        "detection_rate", "non_target_alert_windows",
    ]
    print(baseline_summary[cols].to_string(
        index=False,
        formatters={"detection_rate": "{:.2%}".format},
    ))

    for key, path in outputs.items():
        print(f"{key}: {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
