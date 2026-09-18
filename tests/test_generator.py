from datetime import datetime, timezone

from insider_threat.synthetic.generator import (
    SyntheticEventGenerator,
)


def test_generator_is_reproducible():
    start = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    generator_a = SyntheticEventGenerator(seed=42)
    generator_b = SyntheticEventGenerator(seed=42)

    events_a = generator_a.generate(start, days=3)
    events_b = generator_b.generate(start, days=3)

    assert len(events_a) == len(events_b)

    assert [
        event.model_dump()
        for event in events_a
    ] == [
        event.model_dump()
        for event in events_b
    ]


def test_generator_produces_multiple_users():
    start = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    generator = SyntheticEventGenerator(seed=42)

    events = generator.generate(
        start,
        days=3,
    )

    users = {
        event.user_id
        for event in events
    }

    assert len(users) == 5


def test_generator_contains_suspicious_sequence():
    start = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    generator = SyntheticEventGenerator(seed=42)

    events = generator.generate(
        start,
        days=10,
    )

    suspicious_events = [
        event
        for event in events
        if event.user_id == "USR-003"
        and (
            event.sensitive
            or event.action == "new_device"
            or event.action == "usb_connect"
            or event.action == "large_upload"
        )
    ]

    assert len(suspicious_events) > 0

    assert any(
        event.action == "new_device"
        for event in suspicious_events
    )

    assert any(
        event.action == "usb_connect"
        for event in suspicious_events
    )

    assert any(
        event.action == "large_upload"
        for event in suspicious_events
    )


def test_generated_events_are_temporally_sorted():
    start = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    generator = SyntheticEventGenerator(seed=42)

    events = generator.generate(
        start,
        days=3,
    )

    timestamps = [
        event.timestamp
        for event in events
    ]

    assert timestamps == sorted(timestamps)
