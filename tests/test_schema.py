from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from insider_threat.ingestion.schema import EventSchema


def test_valid_event():
    event = EventSchema(
        event_id="EVT-0001",
        timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
        user_id="USR-001",
        event_type="login",
        action="login_success",
        resource=None,
        device_id="DEV-001",
        source_ip="10.0.0.10",
        status="success",
        sensitive=False,
        bytes_transferred=0,
    )

    assert event.event_id == "EVT-0001"
    assert event.user_id == "USR-001"
    assert event.event_type == "login"


def test_negative_bytes_are_rejected():
    with pytest.raises(ValidationError):
        EventSchema(
            event_id="EVT-0002",
            timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
            user_id="USR-001",
            event_type="network",
            action="upload",
            bytes_transferred=-100,
        )


def test_empty_event_id_is_rejected():
    with pytest.raises(ValidationError):
        EventSchema(
            event_id="",
            timestamp=datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc),
            user_id="USR-001",
            event_type="login",
            action="login_success",
        )
