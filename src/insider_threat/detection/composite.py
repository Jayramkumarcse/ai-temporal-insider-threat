from __future__ import annotations


DEFAULT_WEIGHTS = {
    "temporal": 0.50,
    "context": 0.50,
}


def combine_temporal_and_context(
    temporal_signal: float,
    context_signal: float,
    *,
    temporal_weight: float = DEFAULT_WEIGHTS["temporal"],
    context_weight: float = DEFAULT_WEIGHTS["context"],
) -> float:
    """
    Combine temporal anomaly evidence with security-context evidence.

    The result is an investigation-prioritization signal, not a
    determination of malicious intent.
    """

    if not 0.0 <= temporal_signal <= 1.0:
        raise ValueError("temporal_signal must be between 0 and 1")

    if not 0.0 <= context_signal <= 1.0:
        raise ValueError("context_signal must be between 0 and 1")

    if temporal_weight < 0 or context_weight < 0:
        raise ValueError("weights cannot be negative")

    weight_sum = temporal_weight + context_weight

    if weight_sum <= 0:
        raise ValueError("at least one weight must be positive")

    return (
        temporal_weight * temporal_signal
        + context_weight * context_signal
    ) / weight_sum


def calculate_context_signal(context: dict) -> float:
    """
    Aggregate security-context components into one bounded signal.
    """

    components = (
        context["sensitive_signal"],
        context["transfer_signal"],
        context["device_signal"],
        context["ip_signal"],
    )

    return sum(components) / len(components)


def build_composite_investigation_signal(
    temporal_signal: float,
    context: dict,
    *,
    temporal_weight: float = DEFAULT_WEIGHTS["temporal"],
    context_weight: float = DEFAULT_WEIGHTS["context"],
) -> dict:
    """
    Build the hourly composite investigation signal.
    """

    context_signal = calculate_context_signal(context)

    composite = combine_temporal_and_context(
        temporal_signal,
        context_signal,
        temporal_weight=temporal_weight,
        context_weight=context_weight,
    )

    return {
        "temporal_signal": temporal_signal,
        "context_signal": context_signal,
        "composite_signal": composite,
    }
