from __future__ import annotations

from datetime import date


# Controlled anomaly injected by the synthetic dataset generator.
#
# This is an independently defined ground-truth reference used
# only for evaluation. It is not generated from model predictions.
KNOWN_ANOMALIES = {
    ("USR-003", date(2026, 9, 16)),
}


def is_known_anomaly(
    user_id: str,
    event_date: str,
) -> bool:
    """
    Return whether a user-day is part of the independently defined
    synthetic ground-truth anomaly set.
    """
    parsed_date = date.fromisoformat(event_date)

    return (
        user_id,
        parsed_date,
    ) in KNOWN_ANOMALIES


def add_ground_truth_labels(
    feature_records: list[dict],
) -> list[dict]:
    """
    Add an independently defined binary ground-truth label
    to each user-day feature record.

    Label semantics:

        0 = normal synthetic user-day
        1 = known injected anomalous user-day

    Existing records are not modified in place.
    """
    labeled_records = []

    for record in feature_records:
        labeled_record = {
            **record,
            "ground_truth": int(
                is_known_anomaly(
                    record["user_id"],
                    record["date"],
                )
            ),
        }

        labeled_records.append(labeled_record)

    return labeled_records
