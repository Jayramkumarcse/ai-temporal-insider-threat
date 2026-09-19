import pytest

from insider_threat.evaluation.split import (
    temporal_train_test_split,
)


def test_temporal_split():
    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-15",
            "event_count": 20,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
            "event_count": 30,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-20",
            "event_count": 40,
        },
    ]

    train, test = temporal_train_test_split(
        records,
        "2026-09-16",
    )

    assert len(train) == 2
    assert len(test) == 2

    assert train[-1]["date"] == "2026-09-15"
    assert test[0]["date"] == "2026-09-16"


def test_split_has_no_overlap():
    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-02",
            "event_count": 20,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-03",
            "event_count": 30,
        },
    ]

    train, test = temporal_train_test_split(
        records,
        "2026-09-03",
    )

    train_keys = {
        (record["user_id"], record["date"])
        for record in train
    }

    test_keys = {
        (record["user_id"], record["date"])
        for record in test
    }

    assert train_keys.isdisjoint(test_keys)


def test_split_preserves_all_records():
    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-02",
            "event_count": 20,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-03",
            "event_count": 30,
        },
    ]

    train, test = temporal_train_test_split(
        records,
        "2026-09-02",
    )

    assert len(train) + len(test) == len(records)


def test_split_invalid_date():
    with pytest.raises(ValueError):
        temporal_train_test_split(
            [],
            "not-a-date",
        )


def test_split_empty_dataset():
    train, test = temporal_train_test_split(
        [],
        "2026-09-16",
    )

    assert train == []
    assert test == []
