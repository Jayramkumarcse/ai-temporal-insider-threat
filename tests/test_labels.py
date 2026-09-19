from insider_threat.evaluation.labels import (
    add_ground_truth_labels,
    is_known_anomaly,
)


def test_known_anomaly_is_labeled():
    assert is_known_anomaly(
        "USR-003",
        "2026-09-16",
    ) is True


def test_normal_user_day_is_not_anomaly():
    assert is_known_anomaly(
        "USR-001",
        "2026-09-16",
    ) is False


def test_other_usr003_day_is_not_anomaly():
    assert is_known_anomaly(
        "USR-003",
        "2026-09-15",
    ) is False


def test_add_ground_truth_labels():
    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
        },
    ]

    labeled = add_ground_truth_labels(records)

    assert labeled[0]["ground_truth"] == 0
    assert labeled[1]["ground_truth"] == 1


def test_labels_do_not_modify_original_records():
    records = [
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
        }
    ]

    labeled = add_ground_truth_labels(records)

    assert "ground_truth" not in records[0]
    assert labeled[0]["ground_truth"] == 1
