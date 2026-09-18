import json
from pathlib import Path

from insider_threat.ingestion.loader import load_events_from_json


def test_load_events_from_json(tmp_path: Path):
    dataset = [
        {
            "event_id": "EVT-0001",
            "timestamp": "2026-09-01T09:00:00+00:00",
            "user_id": "USR-001",
            "event_type": "login",
            "action": "login_success",
            "device_id": "DEV-001",
            "source_ip": "10.0.0.10",
            "status": "success",
            "sensitive": False,
            "bytes_transferred": 0,
        },
        {
            "event_id": "EVT-0002",
            "timestamp": "2026-09-01T09:15:00+00:00",
            "user_id": "USR-001",
            "event_type": "file",
            "action": "read",
            "resource": "/documents/report.pdf",
            "device_id": "DEV-001",
            "source_ip": "10.0.0.10",
            "status": "success",
            "sensitive": False,
            "bytes_transferred": 0,
        },
    ]

    path = tmp_path / "events.json"

    with path.open("w", encoding="utf-8") as file:
        json.dump(dataset, file)

    events = load_events_from_json(path)

    assert len(events) == 2
    assert events[0].event_type == "login"
    assert events[1].action == "read"
