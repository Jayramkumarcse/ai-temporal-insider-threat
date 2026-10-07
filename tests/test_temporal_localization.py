import pytest

from insider_threat.evaluation.temporal_localization import (
    locate_anomaly_in_sequence,
    summarize_lstm_localization,
)


def test_anomaly_is_last_timestep():
    assert locate_anomaly_in_sequence(
        target_window_start="2026-09-16T02:00:00+00:00",
        sequence_length=6,
    ) == 5


def test_anomaly_is_first_timestep():
    assert locate_anomaly_in_sequence(
        target_window_start="2026-09-16T07:00:00+00:00",
        sequence_length=6,
    ) == 0


def test_anomaly_is_middle_timestep():
    assert locate_anomaly_in_sequence(
        target_window_start="2026-09-16T05:00:00+00:00",
        sequence_length=6,
    ) == 2


def test_unrelated_sequence_returns_none():
    assert locate_anomaly_in_sequence(
        target_window_start="2026-09-15T12:00:00+00:00",
        sequence_length=6,
    ) is None


def test_invalid_sequence_length():
    with pytest.raises(ValueError):
        locate_anomaly_in_sequence(
            target_window_start="2026-09-16T02:00:00+00:00",
            sequence_length=0,
        )


def test_summarize_lstm_localization():
    starts = [
        "2026-09-16T02:00:00+00:00",
        "2026-09-16T03:00:00+00:00",
        "2026-09-16T04:00:00+00:00",
        "2026-09-16T05:00:00+00:00",
        "2026-09-16T06:00:00+00:00",
        "2026-09-16T07:00:00+00:00",
    ]

    result = summarize_lstm_localization(starts)

    assert [item["anomaly_timestep"] for item in result] == [
        5,
        4,
        3,
        2,
        1,
        0,
    ]
