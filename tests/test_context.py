import pytest

from insider_threat.detection.context import (
    bounded_ratio,
    calculate_security_context_signal,
)


def test_bounded_ratio_zero_reference():
    assert bounded_ratio(0, 0) == 0.0
    assert bounded_ratio(1, 0) == 1.0


def test_bounded_ratio_is_bounded():
    result = bounded_ratio(10, 5)

    assert 0.0 <= result <= 1.0
    assert result == pytest.approx(10 / 15)


def test_bounded_ratio_rejects_negative_values():
    with pytest.raises(ValueError):
        bounded_ratio(-1, 5)

    with pytest.raises(ValueError):
        bounded_ratio(1, -5)


def test_security_context_signal():
    window = {
        "sensitive_access_count": 51,
        "bytes_transferred": 850_000_000,
        "unique_devices": 2,
        "unique_ips": 2,
    }

    result = calculate_security_context_signal(
        window
    )

    assert result["sensitive_access_count"] == 51
    assert result["bytes_transferred"] == 850_000_000
    assert result["unique_devices"] == 2
    assert result["unique_ips"] == 2

    assert result["sensitive_signal"] > 0
    assert result["transfer_signal"] > 0
    assert result["device_signal"] > 0
    assert result["ip_signal"] > 0


def test_normal_window_has_no_security_context_signal():
    window = {
        "sensitive_access_count": 0,
        "bytes_transferred": 0,
        "unique_devices": 1,
        "unique_ips": 1,
    }

    result = calculate_security_context_signal(
        window
    )

    assert result["sensitive_signal"] == 0.0
    assert result["transfer_signal"] == 0.0
    assert result["device_signal"] == 0.0
    assert result["ip_signal"] == 0.0
