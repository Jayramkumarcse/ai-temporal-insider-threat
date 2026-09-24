from __future__ import annotations

from datetime import datetime, timedelta

from insider_threat.ingestion.schema import EventSchema


SCENARIO_USERS = {
    "sensitive_access_burst": "USR-003",
    "large_transfer": "USR-003",
    "off_hours_new_device": "USR-003",
    "short_anomaly_burst": "USR-003",
}


def _event(
    *,
    event_id: str,
    timestamp: datetime,
    user_id: str,
    event_type: str,
    action: str,
    resource: str | None = None,
    device_id: str | None = None,
    source_ip: str | None = None,
    status: str = "success",
    sensitive: bool = False,
    bytes_transferred: int = 0,
    metadata: dict | None = None,
) -> EventSchema:
    return EventSchema(
        event_id=event_id,
        timestamp=timestamp,
        user_id=user_id,
        event_type=event_type,
        action=action,
        resource=resource,
        device_id=device_id,
        source_ip=source_ip,
        status=status,
        sensitive=sensitive,
        bytes_transferred=bytes_transferred,
        metadata=metadata or {},
    )


def build_sensitive_access_burst(
    start: datetime,
    *,
    user_id: str = "USR-003",
) -> list[EventSchema]:
    """Generate repeated sensitive file access without USB or upload."""

    events: list[EventSchema] = []

    timestamp = start.replace(
        hour=2,
        minute=10,
        second=0,
        microsecond=0,
    )

    for index in range(12):
        events.append(
            _event(
                event_id=f"SCN-SAB-{index + 1:03d}",
                timestamp=timestamp,
                user_id=user_id,
                event_type="file",
                action="read",
                resource="/sensitive/confidential_document.pdf",
                device_id="DEV-099",
                source_ip="10.0.99.99",
                sensitive=True,
                metadata={
                    "scenario": "sensitive_access_burst",
                },
            )
        )

        timestamp += timedelta(seconds=30)

    return events


def build_large_transfer(
    start: datetime,
    *,
    user_id: str = "USR-003",
) -> list[EventSchema]:
    """Generate a large outbound transfer without USB activity."""

    timestamp = start.replace(
        hour=2,
        minute=20,
        second=0,
        microsecond=0,
    )

    return [
        _event(
            event_id="SCN-LT-001",
            timestamp=timestamp,
            user_id=user_id,
            event_type="network",
            action="large_upload",
            resource="external_destination",
            device_id="DEV-003",
            source_ip="10.0.0.30",
            bytes_transferred=850_000_000,
            metadata={
                "scenario": "large_transfer",
                "destination_type": "external",
            },
        )
    ]


def build_off_hours_new_device(
    start: datetime,
    *,
    user_id: str = "USR-003",
) -> list[EventSchema]:
    """Generate off-hours login, new-device activity, and sensitive access."""

    timestamp = start.replace(
        hour=2,
        minute=30,
        second=0,
        microsecond=0,
    )

    return [
        _event(
            event_id="SCN-OHND-001",
            timestamp=timestamp,
            user_id=user_id,
            event_type="login",
            action="login_success",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            metadata={
                "scenario": "off_hours_new_device",
            },
        ),
        _event(
            event_id="SCN-OHND-002",
            timestamp=timestamp + timedelta(minutes=2),
            user_id=user_id,
            event_type="device",
            action="new_device",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            metadata={
                "scenario": "off_hours_new_device",
                "novelty": "new_device",
            },
        ),
        _event(
            event_id="SCN-OHND-003",
            timestamp=timestamp + timedelta(minutes=4),
            user_id=user_id,
            event_type="file",
            action="read",
            resource="/sensitive/financial_records.xlsx",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            sensitive=True,
            metadata={
                "scenario": "off_hours_new_device",
            },
        ),
    ]


def build_short_anomaly_burst(
    start: datetime,
    *,
    user_id: str = "USR-003",
    hour: int = 2,
    minute: int = 40,
) -> list[EventSchema]:
    """Generate a short, concentrated anomalous activity burst."""

    timestamp = start.replace(
    hour=hour,
    minute=minute,
    second=0,
    microsecond=0,
)

    return [
        _event(
            event_id="SCN-SB-001",
            timestamp=timestamp,
            user_id=user_id,
            event_type="login",
            action="login_success",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            metadata={
                "scenario": "short_anomaly_burst",
            },
        ),
        _event(
            event_id="SCN-SB-002",
            timestamp=timestamp + timedelta(minutes=1),
            user_id=user_id,
            event_type="file",
            action="read",
            resource="/sensitive/confidential_document.pdf",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            sensitive=True,
            metadata={
                "scenario": "short_anomaly_burst",
            },
        ),
        _event(
            event_id="SCN-SB-003",
            timestamp=timestamp + timedelta(minutes=2),
            user_id=user_id,
            event_type="network",
            action="large_upload",
            resource="external_destination",
            device_id="DEV-099",
            source_ip="10.0.99.99",
            bytes_transferred=250_000_000,
            metadata={
                "scenario": "short_anomaly_burst",
                "destination_type": "external",
            },
        ),
    ]


def build_scenario(
    scenario: str,
    start: datetime,
    *,
    user_id: str = "USR-003",
    hour: int | None = None,
    minute: int | None = None,
) -> list[EventSchema]:
    """Build one controlled anomaly scenario."""

    builders = {
        "sensitive_access_burst": build_sensitive_access_burst,
        "large_transfer": build_large_transfer,
        "off_hours_new_device": build_off_hours_new_device,
        "short_anomaly_burst": build_short_anomaly_burst,
    }

    try:
        builder = builders[scenario]
    except KeyError as exc:
        raise ValueError(
            f"unsupported scenario: {scenario}"
        ) from exc

    if scenario == "short_anomaly_burst":
        return builder(
            start,
            user_id=user_id,
            hour=2 if hour is None else hour,
            minute=40 if minute is None else minute,
        )

    return builder(
        start,
        user_id=user_id,
    )
