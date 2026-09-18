from collections import defaultdict
from datetime import date

from .statistical import build_baseline, score_against_baseline


def build_past_only_baselines(
    feature_records: list[dict],
    feature_name: str,
) -> list[dict]:
    """
    Build leakage-safe historical baselines for a single feature.

    For every user-day observation, the baseline is calculated
    exclusively from that user's previous observations.

    The current observation is never included in its own baseline.

    Feature records must contain:
        user_id
        date
        <feature_name>
    """
    grouped: dict[str, list[dict]] = defaultdict(list)

    for record in feature_records:
        grouped[record["user_id"]].append(record)

    results = []

    for user_id, records in grouped.items():
        records = sorted(
            records,
            key=lambda record: date.fromisoformat(
                record["date"]
            ),
        )

        history: list[float] = []

        for record in records:
            value = float(record[feature_name])

            if history:
                baseline = build_baseline(history)

                score = score_against_baseline(
                    value=value,
                    baseline=baseline,
                )

                results.append(
                    {
                        "user_id": user_id,
                        "date": record["date"],
                        "feature": feature_name,
                        "value": value,
                        "baseline_mean": baseline["mean"],
                        "baseline_std": baseline[
                            "standard_deviation"
                        ],
                        "history_count": int(
                            baseline["observation_count"]
                        ),
                        "z_score": score["z_score"],
                        "absolute_z_score": score[
                            "absolute_z_score"
                        ],
                        "zero_variance": score[
                            "zero_variance"
                        ],
                        "deviation_from_baseline": score[
                            "deviation_from_baseline"
                        ],
                    }
                )

            history.append(value)

    return sorted(
        results,
        key=lambda record: (
            record["user_id"],
            record["date"],
        ),
    )
