import pytest

from scripts.run_score_component_ablation import (
    score_variants,
    weighted_mean,
)


def sample_result():
    temporal_score = 0.5 * 0.50 + 0.25 * 0.30 + 0.75 * 0.20
    context_signal = (0.80 + 0.60 + 0.20 + 0.40) / 4

    return {
        "temporal_score": temporal_score,
        "context_signal": context_signal,
        "composite_signal": (temporal_score + context_signal) / 2,
        "temporal_deviation_coverage": 0.50,
        "temporal_zero_variance_coverage": 0.25,
        "temporal_magnitude_signal": 0.75,
        "context_sensitive_signal": 0.80,
        "context_transfer_signal": 0.60,
        "context_device_signal": 0.20,
        "context_ip_signal": 0.40,
    }


def test_weighted_mean_normalizes_retained_weights():
    assert weighted_mean((0.20, 0.80), (1.0, 3.0)) == pytest.approx(0.65)


def test_weighted_mean_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        weighted_mean((), ())

    with pytest.raises(ValueError):
        weighted_mean((0.2,), (0.5, 0.5))

    with pytest.raises(ValueError):
        weighted_mean((0.2, 0.8), (0.0, 0.0))


def test_score_variants_reproduce_full_composite():
    result = score_variants(sample_result())

    assert result["full_composite"] == pytest.approx(0.4875)
    assert result["temporal_only"] == pytest.approx(0.475)
    assert result["context_only"] == pytest.approx(0.50)
    assert len(result) == 10
    assert all(0.0 <= score <= 1.0 for score in result.values())


def test_temporal_component_removal_renormalizes_weights():
    result = score_variants(sample_result())

    assert result["no_temporal_deviation"] == pytest.approx(0.475)
    assert result["no_temporal_zero_variance"] == pytest.approx(
        (0.4 / 0.7 + 0.5) / 2
    )
    assert result["no_temporal_magnitude"] == pytest.approx(
        (0.325 / 0.8 + 0.5) / 2
    )


def test_context_component_removal_recomputes_context_average():
    result = score_variants(sample_result())

    assert result["no_context_sensitive"] == pytest.approx(0.4375)
    assert result["no_context_transfer"] == pytest.approx(
        (0.475 + (0.8 + 0.2 + 0.4) / 3) / 2
    )
    assert result["no_context_device"] == pytest.approx(0.5375)
    assert result["no_context_ip"] == pytest.approx(
        (0.475 + (0.8 + 0.6 + 0.2) / 3) / 2
    )


def test_inconsistent_temporal_components_are_rejected():
    result = sample_result()
    result["temporal_score"] = 0.99

    with pytest.raises(ValueError, match="temporal components"):
        score_variants(result)


def test_inconsistent_composite_score_is_rejected():
    result = sample_result()
    result["composite_signal"] = 0.99

    with pytest.raises(ValueError, match="baseline composite"):
        score_variants(result)
