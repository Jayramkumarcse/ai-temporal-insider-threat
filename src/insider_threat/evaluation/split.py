from datetime import date


def temporal_train_test_split(
    feature_records: list[dict],
    split_date: str,
) -> tuple[list[dict], list[dict]]:
    """
    Split user-day feature records chronologically.

    Records before split_date are assigned to the training set.
    Records on or after split_date are assigned to the evaluation set.

    The split is based on the UTC calendar date represented by each
    user-day feature record.

    Parameters:
        feature_records:
            User-day behavioral feature records.

        split_date:
            ISO date string, e.g. "2026-09-16".

    Returns:
        (train_records, test_records)
    """
    boundary = date.fromisoformat(split_date)

    train_records = []
    test_records = []

    for record in feature_records:
        record_date = date.fromisoformat(record["date"])

        if record_date < boundary:
            train_records.append(record)
        else:
            test_records.append(record)

    train_records.sort(
        key=lambda record: (
            record["date"],
            record["user_id"],
        )
    )

    test_records.sort(
        key=lambda record: (
            record["date"],
            record["user_id"],
        )
    )

    return train_records, test_records
