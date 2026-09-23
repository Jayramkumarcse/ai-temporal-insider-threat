from datetime import datetime, timezone

import pytest

from insider_threat.synthetic.scenarios import build_scenario


START = datetime(
    2026,
    9,
    16,
    tzinfo=timezone.utc,
)


@pytest.mark.parametrize(
    "scenario,minimum_events",
    [
        ("sensitive_access_burst", 10),
        ("large_transfer", 1),
        ("off_hours_new_device", 3),
        ("short_anomaly_burst", 3),
    ],
)
def test_scenario_produces_events(
    scenario,
    minimum_events,
):
    events = build_scenario(
        scenario,
        START,
    )

    assert len(events) >= minimum_events
    assert all(
        event.user_id == "USR-003"
        for event in events
    )
    assert all(
        event.timestamp.tzinfo is not None
        for event in events
    )


def test_sensitive_access_burst_contains_only_sensitive_reads():
    events = build_scenario(
        "sensitive_access_burst",
        START,
    )

    assert len(events) == 12
    assert all(event.sensitive for event in events)
    assert all(event.action == "read" for event in events)
    assert all(
        event.bytes_transferred == 0
        for event in events
    )


def test_large_transfer_contains_no_sensitive_access():
    events = build_scenario(
        "large_transfer",
        START,
    )

    assert len(events) == 1
    assert events[0].action == "large_upload"
    assert events[0].bytes_transferred == 850_000_000
    assert not events[0].sensitive


def test_off_hours_new_device_sequence():
    events = build_scenario(
        "off_hours_new_device",
        START,
    )

    assert [
        event.action
        for event in events
    ] == [
        "login_success",
        "new_device",
        "read",
    ]

    assert events[-1].sensitive


def test_short_anomaly_burst_is_temporally_concentrated():
    events = build_scenario(
        "short_anomaly_burst",
        START,
    )

    timestamps = [
        event.timestamp
        for event in events
    ]

    assert timestamps == sorted(timestamps)

    duration = (
        timestamps[-1] - timestamps[0]
    ).total_seconds()

    assert duration == 120


def test_unknown_scenario_is_rejected():
    with pytest.raises(ValueError, match="unsupported scenario"):
        build_scenario(
            "does_not_exist",
            START,
        )
