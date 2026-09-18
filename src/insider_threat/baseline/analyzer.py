from collections import defaultdict
from datetime import date

from .statistical import build_baseline, score_against_baseline


DEFAULT_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "night_activity_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
    "failed_action_count",
    "event_rate",
)


def build_multifeature_historical_baseline(
    feature_records: list[dict],
    feature_names: tuple[str, ...] = DEFAULT_FEATURES,
) -> list[dict]:
    """
    Build leakage-safe historical baseline results for multiple
    behavioral features.

    For each user-day, only observations from earlier days belonging
    to the same user are used to construct the baseline.

    The current observation is never included in its own baseline.

    A user-day is included when at least one requested feature has
    historical observations.
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

        histories = {
            feature_name: []
            for feature_name in feature_names
        }

        for record in records:
            has_history = any(
                histories[feature_name]
                for feature_name in feature_names
            )

            if has_history:
                result = {
                    "user_id": user_id,
                    "date": record["date"],
                }

                for feature_name in feature_names:
                    value = float(record[feature_name])
                    history = histories[feature_name]

                    if not history:
                        result[
                            f"{feature_name}_value"
                        ] = value
                        result[
                            f"{feature_name}_baseline_mean"
                        ] = None
                        result[
                            f"{feature_name}_baseline_std"
                        ] = None
                        result[
                            f"{feature_name}_history_count"
                        ] = 0
                        result[
                            f"{feature_name}_z_score"
                        ] = None
                        result[
                            f"{feature_name}_absolute_z_score"
                        ] = None
                        result[
                            f"{feature_name}_zero_variance"
                        ] = None
                        result[
                            f"{feature_name}_deviation"
                        ] = None

                        continue

                    baseline = build_baseline(history)

                    score = score_against_baseline(
                        value=value,
                        baseline=baseline,
                    )

                    result[
                        f"{feature_name}_value"
                    ] = value
                    result[
                        f"{feature_name}_baseline_mean"
                    ] = baseline["mean"]
                    result[
                        f"{feature_name}_baseline_std"
                    ] = baseline["standard_deviation"]
                    result[
                        f"{feature_name}_history_count"
                    ] = int(
                        baseline["observation_count"]
                    )
                    result[
                        f"{feature_name}_z_score"
                    ] = score["z_score"]
                    result[
                        f"{feature_name}_absolute_z_score"
                    ] = score["absolute_z_score"]
                    result[
                        f"{feature_name}_zero_variance"
                    ] = score["zero_variance"]
                    result[
                        f"{feature_name}_deviation"
                    ] = score[
                        "deviation_from_baseline"
                    ]

                results.append(result)

            for feature_name in feature_names:
                if feature_name in record:
                    histories[feature_name].append(
                        float(record[feature_name])
                    )

    return sorted(
        results,
        key=lambda record: (
            record["user_id"],
            record["date"],
        ),
    )
