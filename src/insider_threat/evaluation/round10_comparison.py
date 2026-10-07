from __future__ import annotations

from typing import Iterable

from insider_threat.evaluation.model_comparison import (
    compare_model_evaluations,
)


def build_round10_comparison(
    evaluations: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    """
    Build the final Round 10 model comparison table.

    Input evaluations must already be standardized by
    build_model_evaluation() and add_target_rank().
    """
    evaluations = list(evaluations)

    if not evaluations:
        raise ValueError("evaluations cannot be empty")

    standardized = compare_model_evaluations(evaluations)

    comparison = []

    for evaluation in standardized:
        metrics = evaluation["metrics"]

        comparison.append(
            {
                "model_name": evaluation["model_name"],
                "test_samples": evaluation["total_samples"],
                "alerts": evaluation["alert_count"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "true_positive": metrics["true_positive"],
                "false_positive": metrics["false_positive"],
                "true_negative": metrics["true_negative"],
                "false_negative": metrics["false_negative"],
                "target_score": evaluation["target_score"],
                "target_rank": evaluation["target_rank"],
                "target_detected": bool(
                    evaluation["predictions"][
                        evaluation["target_index"]
                    ]
                ),
            }
        )

    return comparison
