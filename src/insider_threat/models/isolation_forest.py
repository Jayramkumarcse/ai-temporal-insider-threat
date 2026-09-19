from typing import Iterable

import numpy as np
from sklearn.ensemble import IsolationForest


DEFAULT_MODEL_FEATURES = (
    "event_count",
    "sensitive_access_count",
    "night_activity_count",
    "unique_devices",
    "unique_ips",
    "bytes_transferred",
    "failed_action_count",
    "event_rate",
)


def prepare_feature_matrix(
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = DEFAULT_MODEL_FEATURES,
) -> np.ndarray:
    """
    Convert user-day feature records into a numeric feature matrix.

    Records must contain every requested feature.

    The returned matrix has one row per user-day observation and
    one column per selected behavioral feature.
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


def create_isolation_forest(
    contamination: float = "auto",
    random_state: int = 42,
    n_estimators: int = 200,
) -> IsolationForest:
    """
    Create a reproducible Isolation Forest model.

    The model is configured without fitting it.

    Parameters:
        contamination:
            Expected proportion of anomalies. 'auto' lets
            scikit-learn determine the threshold.

        random_state:
            Fixed seed for reproducibility.

        n_estimators:
            Number of isolation trees.
    """
    return IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )


def fit_isolation_forest(
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = DEFAULT_MODEL_FEATURES,
    contamination: float = "auto",
    random_state: int = 42,
    n_estimators: int = 200,
) -> IsolationForest:
    """
    Fit an Isolation Forest model on user-day behavioral features.
    """
    matrix = prepare_feature_matrix(
        feature_records,
        feature_names,
    )

    if len(matrix) == 0:
        raise ValueError(
            "Cannot fit Isolation Forest on an empty dataset"
        )

    model = create_isolation_forest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=n_estimators,
    )

    model.fit(matrix)

    return model


def score_isolation_forest(
    model: IsolationForest,
    feature_records: Iterable[dict],
    feature_names: tuple[str, ...] = DEFAULT_MODEL_FEATURES,
) -> list[dict]:
    """
    Generate Isolation Forest anomaly scores.

    Returns one result per input user-day record.

    anomaly_score:
        Higher values indicate more anomalous observations.

    prediction:
        1  = inlier
        -1 = anomaly according to the model threshold.
    """
    records = list(feature_records)

    matrix = prepare_feature_matrix(
        records,
        feature_names,
    )

    if len(matrix) == 0:
        return []

    predictions = model.predict(matrix)

    # sklearn's score_samples gives lower values to more
    # abnormal observations. Negating it creates an intuitive
    # anomaly score where larger values mean more anomalous.
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
                "anomaly_score": float(anomaly_score),
                "prediction": int(prediction),
            }
        )

    return results
