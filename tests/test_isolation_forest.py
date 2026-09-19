import pytest

from insider_threat.models.isolation_forest import (
    create_isolation_forest,
    fit_isolation_forest,
    prepare_feature_matrix,
    score_isolation_forest,
)


def sample_records():
    return [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 20,
            "sensitive_access_count": 0,
            "night_activity_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
            "event_rate": 0.0005,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-01",
            "event_count": 22,
            "sensitive_access_count": 0,
            "night_activity_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
            "event_rate": 0.0006,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-01",
            "event_count": 21,
            "sensitive_access_count": 0,
            "night_activity_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
            "event_rate": 0.0005,
        },
    ]


def test_prepare_feature_matrix_shape():
    records = sample_records()

    matrix = prepare_feature_matrix(records)

    assert matrix.shape == (3, 8)


def test_prepare_feature_matrix_is_numeric():
    matrix = prepare_feature_matrix(sample_records())

    assert matrix.dtype.kind == "f"


def test_prepare_feature_matrix_empty():
    matrix = prepare_feature_matrix([])

    assert matrix.shape == (0, 8)


def test_prepare_feature_matrix_rejects_missing_value():
    records = sample_records()

    records[0]["event_count"] = None

    with pytest.raises(ValueError):
        prepare_feature_matrix(records)


def test_create_model_is_reproducible_configuration():
    model = create_isolation_forest(
        random_state=42,
        n_estimators=100,
    )

    assert model.n_estimators == 100
    assert model.random_state == 42


def test_fit_model():
    model = fit_isolation_forest(
        sample_records(),
        n_estimators=50,
    )

    assert model.estimators_
    assert len(model.estimators_) == 50


def test_score_model_returns_one_result_per_record():
    records = sample_records()

    model = fit_isolation_forest(
        records,
        n_estimators=50,
    )

    results = score_isolation_forest(
        model,
        records,
    )

    assert len(results) == len(records)


def test_score_model_contains_required_fields():
    records = sample_records()

    model = fit_isolation_forest(
        records,
        n_estimators=50,
    )

    results = score_isolation_forest(
        model,
        records,
    )

    result = results[0]

    assert result["user_id"] == "USR-001"
    assert result["date"] == "2026-09-01"
    assert isinstance(result["anomaly_score"], float)
    assert result["prediction"] in (-1, 1)


def test_empty_scoring_returns_empty_list():
    model = create_isolation_forest()

    results = score_isolation_forest(
        model,
        [],
    )

    assert results == []
