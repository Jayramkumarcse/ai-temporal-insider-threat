import pytest

from insider_threat.evaluation.model_comparison import (
    add_target_rank,
    build_model_evaluation,
    compare_model_evaluations,
)


def test_build_model_evaluation():
    evaluation = build_model_evaluation(
        model_name="test-model",
        scores=[0.1, 0.9, 0.2],
        threshold=0.5,
        labels=[0, 1, 0],
    )

    assert evaluation["model_name"] == "test-model"
    assert evaluation["predictions"] == [0, 1, 0]
    assert evaluation["alert_count"] == 1
    assert evaluation["total_samples"] == 3
    assert evaluation["metrics"]["true_positive"] == 1
    assert evaluation["metrics"]["false_positive"] == 0


def test_add_target_rank():
    evaluation = build_model_evaluation(
        model_name="test-model",
        scores=[0.1, 0.9, 0.2],
        threshold=0.5,
        labels=[0, 1, 0],
    )

    ranked = add_target_rank(
        evaluation,
        target_index=1,
    )

    assert ranked["target_index"] == 1
    assert ranked["target_score"] == 0.9
    assert ranked["target_rank"] == 1


def test_compare_model_evaluations_is_deterministic():
    evaluations = [
        {"model_name": "LSTM"},
        {"model_name": "Isolation Forest"},
        {"model_name": "Baseline"},
    ]

    compared = compare_model_evaluations(evaluations)

    assert [
        evaluation["model_name"]
        for evaluation in compared
    ] == [
        "Baseline",
        "Isolation Forest",
        "LSTM",
    ]


def test_empty_scores_rejected():
    with pytest.raises(ValueError):
        build_model_evaluation(
            model_name="test-model",
            scores=[],
            threshold=0.5,
            labels=[],
        )


def test_length_mismatch_rejected():
    with pytest.raises(ValueError):
        build_model_evaluation(
            model_name="test-model",
            scores=[0.1],
            threshold=0.5,
            labels=[0, 1],
        )
