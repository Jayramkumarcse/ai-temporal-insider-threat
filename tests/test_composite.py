import pytest

from insider_threat.detection.composite import (
    build_composite_investigation_signal,
    calculate_context_signal,
    combine_temporal_and_context,
)


def test_context_signal_is_average():
    context = {
        "sensitive_signal": 1.0,
        "transfer_signal": 1.0,
        "device_signal": 0.5,
        "ip_signal": 0.5,
    }

    assert calculate_context_signal(context) == pytest.approx(0.75)


def test_composite_equal_weights():
    result = combine_temporal_and_context(
        0.6,
        0.8,
    )

    assert result == pytest.approx(0.7)


def test_composite_is_bounded():
    result = combine_temporal_and_context(
        1.0,
        1.0,
    )

    assert 0.0 <= result <= 1.0
    assert result == pytest.approx(1.0)


def test_invalid_signal_rejected():
    with pytest.raises(ValueError):
        combine_temporal_and_context(
            1.1,
            0.5,
        )

    with pytest.raises(ValueError):
        combine_temporal_and_context(
            0.5,
            -0.1,
        )


def test_zero_weights_rejected():
    with pytest.raises(ValueError):
        combine_temporal_and_context(
            0.5,
            0.5,
            temporal_weight=0.0,
            context_weight=0.0,
        )


def test_build_composite_signal():
    context = {
        "sensitive_signal": 1.0,
        "transfer_signal": 1.0,
        "device_signal": 0.5,
        "ip_signal": 0.5,
    }

    result = build_composite_investigation_signal(
        temporal_signal=2 / 3,
        context=context,
    )

    assert result["context_signal"] == pytest.approx(0.75)

    assert result["composite_signal"] == pytest.approx(
        ((2 / 3) + 0.75) / 2
    )
