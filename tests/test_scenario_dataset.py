from datetime import datetime, timezone

from insider_threat.synthetic.scenario_dataset import build_scenario_dataset


def test_scenario_dataset_supports_custom_anomaly_time():
    start_date = datetime(
        2026,
        9,
        1,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = build_scenario_dataset(
        "short_anomaly_burst",
        start_date=start_date,
        hour=14,
        minute=0,
    )

    scenario_events = [
        event
        for event in events
        if event.metadata.get("scenario") == "short_anomaly_burst"
    ]

    assert len(scenario_events) == 3

    timestamps = sorted(event.timestamp for event in scenario_events)

    assert timestamps[0].hour == 14
    assert timestamps[0].minute == 0

    assert timestamps[1].hour == 14
    assert timestamps[1].minute == 1

    assert timestamps[2].hour == 14
    assert timestamps[2].minute == 2


def test_scenario_dataset_seed_controls_baseline_reproducibly():
    start_date = datetime(
        2026, 9, 1, tzinfo=timezone.utc
    )

    def baseline_signature(seed):
        events = build_scenario_dataset(
            "short_anomaly_burst",
            start_date=start_date,
            days=3,
            seed=seed,
        )
        return [
            (
                event.timestamp,
                event.user_id,
                event.event_type,
                event.action,
                event.device_id,
                event.source_ip,
            )
            for event in events
            if event.metadata.get("scenario") != "short_anomaly_burst"
        ]

    baseline_a = baseline_signature(7)
    baseline_b = baseline_signature(7)
    baseline_c = baseline_signature(21)

    assert baseline_a == baseline_b
    assert baseline_a != baseline_c
