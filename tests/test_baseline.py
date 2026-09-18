from math import isinf

from insider_threat.baseline.statistical import (
    build_baseline,
    calculate_absolute_z_score,
    calculate_mean,
    calculate_population_std,
    calculate_z_score,
    score_against_baseline,
)


def test_calculate_mean():
    assert calculate_mean([10, 20, 30]) == 20.0


def test_calculate_mean_empty():
    assert calculate_mean([]) == 0.0


def test_calculate_population_std():
    std = calculate_population_std(
        [10, 20, 30]
    )

    assert round(std, 6) == 8.164966


def test_calculate_population_std_empty():
    assert calculate_population_std([]) == 0.0


def test_calculate_z_score():
    z_score = calculate_z_score(
        value=30,
        baseline_mean=20,
        baseline_std=5,
    )

    assert z_score == 2.0


def test_zero_variance_equal_value():
    z_score = calculate_z_score(
        value=20,
        baseline_mean=20,
        baseline_std=0,
    )

    assert z_score == 0.0


def test_zero_variance_different_value():
    z_score = calculate_z_score(
        value=30,
        baseline_mean=20,
        baseline_std=0,
    )

    assert isinf(z_score)


def test_absolute_z_score():
    assert calculate_absolute_z_score(
        value=10,
        baseline_mean=20,
        baseline_std=5,
    ) == 2.0


def test_build_baseline():
    baseline = build_baseline(
        [10, 20, 30]
    )

    assert baseline["mean"] == 20.0
    assert round(
        baseline["standard_deviation"],
        6,
    ) == 8.164966
    assert baseline["observation_count"] == 3.0


def test_score_against_baseline():
    baseline = build_baseline(
        [10, 20, 30]
    )

    score = score_against_baseline(
        value=30,
        baseline=baseline,
    )

    assert round(score["z_score"], 6) == 1.224745
    assert round(
        score["absolute_z_score"],
        6,
    ) == 1.224745


def test_past_only_baseline_excludes_current_observation():
    from insider_threat.baseline.historical import (
        build_past_only_baselines,
    )

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

    results = build_past_only_baselines(
        records,
        "event_count",
    )

    assert len(results) == 2

    second_day = results[0]
    third_day = results[1]

    assert second_day["history_count"] == 1
    assert second_day["baseline_mean"] == 10.0

    assert third_day["history_count"] == 2
    assert third_day["baseline_mean"] == 15.0


def test_past_only_baseline_is_user_specific():
    from insider_threat.baseline.historical import (
        build_past_only_baselines,
    )

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
            "user_id": "USR-002",
            "date": "2026-09-01",
            "event_count": 100,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-02",
            "event_count": 120,
        },
    ]

    results = build_past_only_baselines(
        records,
        "event_count",
    )

    assert len(results) == 2

    user_001 = next(
        result
        for result in results
        if result["user_id"] == "USR-001"
    )

    user_002 = next(
        result
        for result in results
        if result["user_id"] == "USR-002"
    )

    assert user_001["baseline_mean"] == 10.0
    assert user_002["baseline_mean"] == 100.0


def test_first_observation_has_no_baseline():
    from insider_threat.baseline.historical import (
        build_past_only_baselines,
    )

    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
        },
    ]

    results = build_past_only_baselines(
        records,
        "event_count",
    )

    assert results == []


def test_multifeature_baseline_uses_past_only_data():
    from insider_threat.baseline.analyzer import (
        build_multifeature_historical_baseline,
    )

    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
            "sensitive_access_count": 0,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-02",
            "event_count": 20,
            "sensitive_access_count": 0,
        },
        {
            "user_id": "USR-001",
            "date": "2026-09-03",
            "event_count": 50,
            "sensitive_access_count": 10,
        },
    ]

    results = build_multifeature_historical_baseline(
        records,
        feature_names=(
            "event_count",
            "sensitive_access_count",
        ),
    )

    assert len(results) == 2

    third_day = results[1]

    assert third_day["event_count_baseline_mean"] == 15.0
    assert third_day["event_count_history_count"] == 2

    assert (
        third_day["sensitive_access_count_baseline_mean"]
        == 0.0
    )

    assert (
        third_day["sensitive_access_count_zero_variance"]
        is True
    )

    assert (
        third_day["sensitive_access_count_deviation"]
        is True
    )


def test_multifeature_baseline_first_day_is_excluded():
    from insider_threat.baseline.analyzer import (
        build_multifeature_historical_baseline,
    )

    records = [
        {
            "user_id": "USR-001",
            "date": "2026-09-01",
            "event_count": 10,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-01",
            "event_count": 100,
        },
    ]

    results = build_multifeature_historical_baseline(
        records,
        feature_names=("event_count",),
    )

    assert results == []
