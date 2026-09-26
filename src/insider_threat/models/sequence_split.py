from __future__ import annotations

from datetime import date
from typing import Iterable


def split_sequences_by_target_date(
    sequences: Iterable[dict],
    *,
    train_end: date,
    validation_end: date,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split sequences chronologically by their target date.

    Dates <= train_end belong to training.
    Dates > train_end and <= validation_end belong to validation.
    Dates > validation_end belong to test.
    """

    if train_end >= validation_end:
        raise ValueError(
            "train_end must be earlier than validation_end"
        )

    train: list[dict] = []
    validation: list[dict] = []
    test: list[dict] = []

    for sequence in sequences:
        target_date = date.fromisoformat(
            sequence["target_date"]
        )

        if target_date <= train_end:
            train.append(sequence)
        elif target_date <= validation_end:
            validation.append(sequence)
        else:
            test.append(sequence)

    train.sort(key=lambda sequence: sequence["target_date"])
    validation.sort(key=lambda sequence: sequence["target_date"])
    test.sort(key=lambda sequence: sequence["target_date"])

    return train, validation, test
