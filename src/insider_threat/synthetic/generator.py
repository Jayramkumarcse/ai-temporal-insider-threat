import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from insider_threat.ingestion.schema import EventSchema


USERS = [
    "USR-001",
    "USR-002",
    "USR-003",
    "USR-004",
    "USR-005",
]

DEVICES = {
    "USR-001": ["DEV-001"],
    "USR-002": ["DEV-002"],
    "USR-003": ["DEV-003", "DEV-099"],
    "USR-004": ["DEV-004"],
    "USR-005": ["DEV-005"],
}

IPS = {
    "USR-001": ["10.0.0.10"],
    "USR-002": ["10.0.0.20"],
    "USR-003": ["10.0.0.30", "10.0.99.99"],
    "USR-004": ["10.0.0.40"],
    "USR-005": ["10.0.0.50"],
}


class SyntheticEventGenerator:
    """Generate reproducible synthetic security telemetry."""

    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)
        self.event_counter = 0

    def _event(
        self,
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

        self.event_counter += 1

        return EventSchema(
            event_id=f"EVT-{self.event_counter:06d}",
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

    def _normal_day(
        self,
        user_id: str,
        day: datetime,
    ) -> list[EventSchema]:

        events = []

        device_id = self.random.choice(DEVICES[user_id])
        source_ip = self.random.choice(IPS[user_id])

        login_time = day.replace(
            hour=8 + self.random.randint(0, 1),
            minute=self.random.randint(0, 59),
            second=0,
            microsecond=0,
        )

        events.append(
            self._event(
                login_time,
                user_id,
                "login",
                "login_success",
                device_id=device_id,
                source_ip=source_ip,
            )
        )

        current = login_time + timedelta(minutes=5)

        activity_count = self.random.randint(15, 30)

        resources = [
            "/documents/report.pdf",
            "/documents/project.docx",
            "/documents/notes.txt",
            "/shared/team.xlsx",
            "/projects/source_code.zip",
        ]

        for _ in range(activity_count):
            current += timedelta(
                minutes=self.random.randint(5, 35)
            )

            event_type = self.random.choice(
                ["file", "database", "network"]
            )

            if event_type == "file":
                events.append(
                    self._event(
                        current,
                        user_id,
                        "file",
                        self.random.choice(
                            ["read", "write"]
                        ),
                        resource=self.random.choice(resources),
                        device_id=device_id,
                        source_ip=source_ip,
                    )
                )

            elif event_type == "database":
                events.append(
                    self._event(
                        current,
                        user_id,
                        "database",
                        "query",
                        resource="internal_database",
                        device_id=device_id,
                        source_ip=source_ip,
                    )
                )

            else:
                events.append(
                    self._event(
                        current,
                        user_id,
                        "network",
                        self.random.choice(
                            ["request", "response"]
                        ),
                        resource="internal_service",
                        device_id=device_id,
                        source_ip=source_ip,
                    )
                )

        logout_time = day.replace(
            hour=17,
            minute=self.random.randint(0, 45),
            second=0,
            microsecond=0,
        )

        events.append(
            self._event(
                logout_time,
                user_id,
                "logout",
                "logout",
                device_id=device_id,
                source_ip=source_ip,
            )
        )

        return events

    def _suspicious_sequence(
        self,
        user_id: str,
        day: datetime,
    ) -> list[EventSchema]:

        events = []

        timestamp = day.replace(
            hour=2,
            minute=13,
            second=0,
            microsecond=0,
        )

        normal_device = DEVICES[user_id][0]
        unusual_device = DEVICES[user_id][-1]

        normal_ip = IPS[user_id][0]
        unusual_ip = IPS[user_id][-1]

        events.append(
            self._event(
                timestamp,
                user_id,
                "login",
                "login_success",
                device_id=normal_device,
                source_ip=normal_ip,
            )
        )

        timestamp += timedelta(minutes=2)

        events.append(
            self._event(
                timestamp,
                user_id,
                "device",
                "new_device",
                device_id=unusual_device,
                source_ip=unusual_ip,
                metadata={"novelty": "new_device"},
            )
        )

        timestamp += timedelta(minutes=2)

        events.append(
            self._event(
                timestamp,
                user_id,
                "file",
                "read",
                resource="/sensitive/financial_records.xlsx",
                device_id=unusual_device,
                source_ip=unusual_ip,
                sensitive=True,
            )
        )

        timestamp += timedelta(minutes=1)

        for _ in range(50):
            timestamp += timedelta(seconds=self.random.randint(10, 30))

            events.append(
                self._event(
                    timestamp,
                    user_id,
                    "file",
                    "read",
                    resource="/sensitive/confidential_document.pdf",
                    device_id=unusual_device,
                    source_ip=unusual_ip,
                    sensitive=True,
                    metadata={
                        "sequence": "high_velocity_file_access"
                    },
                )
            )

        timestamp += timedelta(minutes=2)

        events.append(
            self._event(
                timestamp,
                user_id,
                "usb",
                "usb_connect",
                device_id=unusual_device,
                source_ip=unusual_ip,
                metadata={"removable_media": True},
            )
        )

        timestamp += timedelta(minutes=6)

        events.append(
            self._event(
                timestamp,
                user_id,
                "network",
                "large_upload",
                resource="external_destination",
                device_id=unusual_device,
                source_ip=unusual_ip,
                bytes_transferred=850_000_000,
                metadata={
                    "destination_type": "external"
                },
            )
        )

        timestamp += timedelta(minutes=4)

        events.append(
            self._event(
                timestamp,
                user_id,
                "logout",
                "logout",
                device_id=unusual_device,
                source_ip=unusual_ip,
            )
        )

        return events

    def generate(
        self,
        start_date: datetime,
        days: int = 30,
    ) -> list[EventSchema]:

        events = []

        for day_offset in range(days):
            day = start_date + timedelta(days=day_offset)

            for user_id in USERS:
                if user_id == "USR-003":
                    events.extend(
                        self._normal_day(user_id, day)
                    )

                else:
                    events.extend(
                        self._normal_day(user_id, day)
                    )

        anomaly_day = start_date + timedelta(days=days // 2)

        events.extend(
            self._suspicious_sequence(
                "USR-003",
                anomaly_day,
            )
        )

        events.sort(key=lambda event: event.timestamp)

        return events


def save_events(
    events: list[EventSchema],
    path: str | Path,
) -> None:
    """Save validated events to JSON."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    records = [
        event.model_dump(mode="json")
        for event in events
    ]

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            records,
            file,
            indent=2,
        )


if __name__ == "__main__":
    generator = SyntheticEventGenerator(seed=42)

    start = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    events = generator.generate(
        start_date=start,
        days=30,
    )

    output_path = Path("data/raw/events.json")

    save_events(events, output_path)

    print(f"Generated {len(events)} events")
    print(f"Saved to {output_path}")
