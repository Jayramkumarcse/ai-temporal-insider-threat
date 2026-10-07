from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest


HOURLY_MODEL_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
)


def prepare_hourly_feature_matrix(
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = HOURLY_MODEL_FEATURES,
) -> np.ndarray:
    """
    Convert hourly feature records into a numeric feature matrix.

    Records must contain every requested feature.
    """
    records = list(feature_records)

    if not records:
        return np.empty(
            (0, len(feature_names)),
            dtype=float,
        )

    matrix = []

    for record in records:
        row = []

        for feature_name in feature_names:
            value = record[feature_name]

            if value is None:
                raise ValueError(
                    f"Feature '{feature_name}' cannot be None"
                )

            row.append(float(value))

        matrix.append(row)

    return np.asarray(
        matrix,
        dtype=float,
    )


def create_hourly_isolation_forest(
    contamination: float = "auto",
    random_state: int = 42,
    n_estimators: int = 200,
) -> IsolationForest:
    """
    Create a reproducible Isolation Forest for hourly observations.
    """
    return IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )


def fit_hourly_isolation_forest(
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = HOURLY_MODEL_FEATURES,
    contamination: float = "auto",
    random_state: int = 42,
    n_estimators: int = 200,
) -> IsolationForest:
    """
    Fit an Isolation Forest on hourly behavioral features.
    """
    matrix = prepare_hourly_feature_matrix(
        feature_records,
        feature_names,
    )

    if len(matrix) == 0:
        raise ValueError(
            "Cannot fit hourly Isolation Forest on an empty dataset"
        )

    model = create_hourly_isolation_forest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
    )

    model.fit(matrix)

    return model


def score_hourly_isolation_forest(
    model: IsolationForest,
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = HOURLY_MODEL_FEATURES,
) -> list[dict]:
    """
    Generate anomaly scores for hourly observations.

    Higher anomaly_score values indicate more anomalous
    observations.

    prediction:
        1  = inlier
        -1 = anomaly according to the model threshold.
    """
    records = list(feature_records)

    matrix = prepare_hourly_feature_matrix(
        records,
        feature_names,
    )

    if len(matrix) == 0:
        return []

    predictions = model.predict(matrix)

    anomaly_scores = -model.score_samples(matrix)

    results = []

    for record, prediction, anomaly_score in zip(
        records,
        predictions,
        anomaly_scores,
    ):
        results.append(
            {
                "user_id": record["user_id"],
                "date": record["date"],
                "hour_of_day": record.get(
                    "hour_of_day",
                    record.get("window_start_hour"),
                ),
                "anomaly_score": float(anomaly_score),
                "prediction": int(prediction),
            }
        )

    return results
