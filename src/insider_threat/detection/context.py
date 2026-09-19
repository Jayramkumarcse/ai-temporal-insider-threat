from __future__ import annotations


def bounded_ratio(
    value: float,
    reference: float,
) -> float:
    """
    Convert a non-negative value into a bounded [0, 1] signal.

    A reference of zero means that any positive value represents
    a contextual deviation.
    """

    if value < 0:
        raise ValueError("value cannot be negative")

    if reference < 0:
        raise ValueError("reference cannot be negative")

    if reference == 0:
        return 1.0 if value > 0 else 0.0

    return value / (value + reference)


def calculate_security_context_signal(
    current_window: dict,
) -> dict:
    """
    Build security-relevant contextual signals for an hourly window.

    These signals describe observable security-relevant activity.
    They do not determine malicious intent.
    """

    sensitive_count = float(
        current_window["sensitive_access_count"]
    )

    bytes_transferred = float(
        current_window["bytes_transferred"]
    )

    device_count = float(
        current_window["unique_devices"]
    )

    ip_count = float(
        current_window["unique_ips"]
    )

    sensitive_signal = bounded_ratio(
        sensitive_count,
        1.0,
    )

    transfer_signal = bounded_ratio(
        bytes_transferred,
        1.0,
    )

    device_signal = bounded_ratio(
        max(device_count - 1.0, 0.0),
        1.0,
    )

    ip_signal = bounded_ratio(
        max(ip_count - 1.0, 0.0),
        1.0,
    )

    return {
        "sensitive_access_count": int(
            sensitive_count
        ),
        "bytes_transferred": int(
            bytes_transferred
        ),
        "unique_devices": int(
            device_count
        ),
        "unique_ips": int(
            ip_count
        ),
        "sensitive_signal": sensitive_signal,
        "transfer_signal": transfer_signal,
        "device_signal": device_signal,
        "ip_signal": ip_signal,
    }
