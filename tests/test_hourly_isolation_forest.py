import pytest

from insider_threat.models.hourly_isolation_forest import (
    HOURLY_MODEL_FEATURES,
    create_hourly_isolation_forest,
    fit_hourly_isolation_forest,
    prepare_hourly_feature_matrix,
    score_hourly_isolation_forest,
)


def sample_hourly_records():
    return [
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "event_count": 20,
            "sensitive_access_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "event_count": 22,
            "sensitive_access_count": 0,
            "unique_devices": 1,
            "unique_ips": 1,
            "bytes_transferred": 0,
            "failed_action_count": 0,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "event_count": 56,
            "sensitive_access_count": 51,
            "unique_devices": 2,
            "unique_ips": 2,
            "bytes_transferred": 850_000_000,
            "failed_action_count": 0,
        },
    ]


def test_hourly_model_features():
    assert HOURLY_MODEL_FEATURES == (
    "event_count",
    "sensitive_access_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
)


def test_prepare_hourly_feature_matrix_shape():
    matrix = prepare_hourly_feature_matrix(
        sample_hourly_records()
    )

    assert matrix.shape == (3, 5)


def test_prepare_hourly_feature_matrix_is_numeric():
    matrix = prepare_hourly_feature_matrix(
        sample_hourly_records()
    )

    assert matrix.dtype.kind == "f"


def test_prepare_hourly_feature_matrix_empty():
    matrix = prepare_hourly_feature_matrix([])

    assert matrix.shape == (0, 5)


def test_prepare_hourly_feature_matrix_rejects_missing_value():
    records = sample_hourly_records()
    records[0]["event_count"] = None

    with pytest.raises(ValueError):
        prepare_hourly_feature_matrix(records)


def test_create_hourly_model_is_reproducible():
    model = create_hourly_isolation_forest(
        random_state=42,
        n_estimators=100,
    )

    assert model.n_estimators == 100
    assert model.random_state == 42


def test_fit_hourly_model():
    model = fit_hourly_isolation_forest(
        sample_hourly_records(),
        n_estimators=50,
    )

    assert model.estimators_
    assert len(model.estimators_) == 50


def test_score_hourly_model_returns_one_result_per_record():
    records = sample_hourly_records()

    model = fit_hourly_isolation_forest(
        records,
        n_estimators=50,
    )

    results = score_hourly_isolation_forest(
        model,
        records,
    )

    assert len(results) == len(records)


def test_score_hourly_model_contains_required_fields():
    records = sample_hourly_records()

    model = fit_hourly_isolation_forest(
        records,
        n_estimators=50,
    )

    results = score_hourly_isolation_forest(
        model,
        records,
    )

    result = results[0]

    assert result["user_id"] == "USR-001"
    assert result["date"] == "2026-09-16"
    assert result["hour_of_day"] == 2
    assert isinstance(result["anomaly_score"], float)
    assert result["prediction"] in (-1, 1)


def test_empty_hourly_scoring_returns_empty_list():
    model = create_hourly_isolation_forest()

    results = score_hourly_isolation_forest(
        model,
        [],
    )

    assert results == []
