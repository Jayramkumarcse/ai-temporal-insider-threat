from __future__ import annotations

from datetime import date
from typing import Iterable


TRAIN_END_DATE = date(2026, 9, 12)
VALIDATION_END_DATE = date(2026, 9, 14)


def split_sequences_by_date(
    sequences: Iterable[dict],
    *,
    train_end_date: date = TRAIN_END_DATE,
    validation_end_date: date = VALIDATION_END_DATE,
) -> dict[str, list[dict]]:
    """
    Split temporal sequences chronologically by target date.

    Training sequences end on or before train_end_date.
    Validation sequences occur after train_end_date and
    on or before validation_end_date.
    Test sequences occur after validation_end_date.

    No random shuffling is performed.
    """

    if validation_end_date <= train_end_date:
        raise ValueError(
            "validation_end_date must be after train_end_date"
        )

    splits = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for sequence in sequences:
        target_date = date.fromisoformat(
            sequence["target_date"]
        )

        if target_date <= train_end_date:
            splits["train"].append(sequence)
        elif target_date <= validation_end_date:
            splits["validation"].append(sequence)
        else:
            splits["test"].append(sequence)

    return splits
