import pytest

from insider_threat.evaluation.experiments import (
    evaluate_composite_experiment,
    find_target_result,
)


def make_results():
    return [
        {
            "user_id": "USR-001",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "temporal_score": 0.20,
            "composite_signal": 0.10,
        },
        {
            "user_id": "USR-003",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "temporal_score": 0.66,
            "composite_signal": 0.70,
        },
        {
            "user_id": "USR-002",
            "date": "2026-09-16",
            "hour_of_day": 2,
            "temporal_score": 0.40,
            "composite_signal": 0.30,
        },
    ]


def test_find_target_result():
    target = find_target_result(
        make_results()
    )

    assert target["user_id"] == "USR-003"
    assert target["composite_signal"] == 0.70


def test_find_target_result_missing():
    with pytest.raises(ValueError):
        find_target_result(
            [
                {
                    "user_id": "USR-001",
                    "date": "2026-09-16",
                    "hour_of_day": 2,
                }
            ]
        )


def test_evaluate_composite_experiment():
    result = evaluate_composite_experiment(
        make_results()
    )

    assert result["total_windows"] == 3
    assert result["temporal_rank"] == 1
    assert result["composite_rank"] == 1

    separation = result[
        "composite_separation"
    ]

    assert separation[
        "highest_normal_score"
    ] == pytest.approx(0.30)

    assert separation[
        "absolute_margin"
    ] == pytest.approx(0.40)


def test_empty_results_rejected():
    with pytest.raises(ValueError):
        evaluate_composite_experiment([])
