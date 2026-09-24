from __future__ import annotations

from datetime import date


TARGET_USER = "USR-003"
TARGET_DATE = date(2026, 9, 16)

ANOMALY_HOURS = (0, 2, 6, 10, 14, 18, 22)

TARGET_WINDOW_START_HOURS = {
    1: {
        0: 0,
        2: 2,
        6: 6,
        10: 10,
        14: 14,
        18: 18,
        22: 22,
    },
    2: {
        0: 0,
        2: 2,
        6: 6,
        10: 10,
        14: 14,
        18: 18,
        22: 22,
    },
    4: {
        0: 0,
        2: 0,
        6: 4,
        10: 8,
        14: 12,
        18: 16,
        22: 20,
    },
    6: {
        0: 0,
        2: 0,
        6: 6,
        10: 6,
        14: 12,
        18: 18,
        22: 18,
    },
    8: {
        0: 0,
        2: 0,
        6: 0,
        10: 8,
        14: 8,
        18: 16,
        22: 16,
    },
    12: {
        0: 0,
        2: 0,
        6: 0,
        10: 0,
        14: 12,
        18: 12,
        22: 12,
    },
    24: {
        0: 0,
        2: 0,
        6: 0,
        10: 0,
        14: 0,
        18: 0,
        22: 0,
    },
}


def find_target_window(
    results: list[dict],
    *,
    user_id: str,
    target_date: date,
    window_hours: int,
    anomaly_hour: int,
) -> dict:
    """Find the exact target window for one anomaly time."""

    target_date_string = target_date.isoformat()
    target_start_hour = TARGET_WINDOW_START_HOURS[
        window_hours
    ][anomaly_hour]

    matches = [
        result
        for result in results
        if result["user_id"] == user_id
        and str(result["date"]) == target_date_string
        and result["window_hours"] == window_hours
        and result["window_start_hour"] == target_start_hour
    ]

    if len(matches) != 1:
        raise ValueError(
            "expected exactly one target window, "
            f"found {len(matches)}"
        )

    return matches[0]


def calculate_window_separation(
    target_score: float,
    highest_normal_score: float,
) -> dict[str, float]:
    """Calculate absolute and relative separation."""

    absolute_margin = target_score - highest_normal_score

    if highest_normal_score == 0:
        ratio = float("inf")
    else:
        ratio = target_score / highest_normal_score

    return {
        "absolute_margin": absolute_margin,
        "ratio_to_highest_normal": ratio,
    }


def count_threshold_alerts(
    results: list[dict],
    *,
    threshold: float,
    target_user: str,
    target_date: date,
    window_hours: int,
    anomaly_hour: int,
) -> dict[str, int]:
    """Count alerts while identifying the exact target window."""

    target_date_string = target_date.isoformat()
    target_start_hour = TARGET_WINDOW_START_HOURS[
        window_hours
    ][anomaly_hour]

    total_alerts = sum(
        result["composite_signal"] >= threshold
        for result in results
    )

    target_alerts = sum(
        result["user_id"] == target_user
        and str(result["date"]) == target_date_string
        and result["window_hours"] == window_hours
        and result["window_start_hour"] == target_start_hour
        and result["composite_signal"] >= threshold
        for result in results
    )

    normal_alerts = total_alerts - target_alerts

    return {
        "total_alerts": total_alerts,
        "normal_alerts": normal_alerts,
        "target_detected": int(target_alerts == 1),
    }


def rank_target(
    results: list[dict],
    *,
    target_user: str,
    target_date: date,
    window_hours: int,
    anomaly_hour: int,
) -> int:
    """Return the 1-based rank of the exact target window."""

    target = find_target_window(
        results,
        user_id=target_user,
        target_date=target_date,
        window_hours=window_hours,
        anomaly_hour=anomaly_hour,
    )

    ordered = sorted(
        results,
        key=lambda result: result["composite_signal"],
        reverse=True,
    )

    for rank, result in enumerate(ordered, start=1):
        if result is target:
            return rank

    raise RuntimeError("target window was not found in ranking")


def evaluate_time_of_day_window(
    results: list[dict],
    *,
    anomaly_hour: int,
    window_hours: int,
    threshold: float,
    target_user: str = TARGET_USER,
    target_date: date = TARGET_DATE,
) -> dict:
    """Evaluate one anomaly time against one observation window."""

    target = find_target_window(
        results,
        user_id=target_user,
        target_date=target_date,
        window_hours=window_hours,
        anomaly_hour=anomaly_hour,
    )

    normal_scores = [
        result["composite_signal"]
        for result in results
        if not (
            result["user_id"] == target_user
            and str(result["date"]) == target_date.isoformat()
            and result["window_hours"] == window_hours
            and result["window_start_hour"]
            == target["window_start_hour"]
        )
    ]

    highest_normal_score = max(normal_scores)

    separation = calculate_window_separation(
        target["composite_signal"],
        highest_normal_score,
    )

    alerts = count_threshold_alerts(
        results,
        threshold=threshold,
        target_user=target_user,
        target_date=target_date,
        window_hours=window_hours,
        anomaly_hour=anomaly_hour,
    )

    return {
        "anomaly_hour": anomaly_hour,
        "window_hours": window_hours,
        "target_window_start": target["window_start_hour"],
        "target_window_end": (
            target["window_start_hour"] + window_hours
        ),
        "target_event_count": target["event_count"],
        "target_sensitive_access_count": (
            target["sensitive_access_count"]
        ),
        "target_unique_devices": target["unique_devices"],
        "target_unique_ips": target["unique_ips"],
        "target_bytes_transferred": target["bytes_transferred"],
        "target_temporal_score": target["temporal_score"],
        "target_context_signal": target["context_signal"],
        "target_composite_signal": target["composite_signal"],
        "target_rank": rank_target(
            results,
            target_user=target_user,
            target_date=target_date,
            window_hours=window_hours,
            anomaly_hour=anomaly_hour,
        ),
        "highest_normal_score": highest_normal_score,
        "absolute_margin": separation["absolute_margin"],
        "ratio_to_highest_normal": separation[
            "ratio_to_highest_normal"
        ],
        "threshold": threshold,
        "total_alerts": alerts["total_alerts"],
        "normal_alerts": alerts["normal_alerts"],
        "target_detected": bool(alerts["target_detected"]),
    }
