from __future__ import annotations

from datetime import datetime, timezone

from insider_threat.ingestion.schema import EventSchema
from insider_threat.preprocessing.cleaning import clean_events

from .generator import SyntheticEventGenerator
from .scenarios import build_scenario


SCENARIO_START = datetime(
    2026,
    9,
    16,
    2,
    0,
    tzinfo=timezone.utc,
)

SCENARIO_USER = "USR-003"


def build_scenario_dataset(
    scenario: str,
    *,
    start_date: datetime,
    days: int = 30,
    user_id: str = SCENARIO_USER,
    hour: int | None = None,
    minute: int | None = None,
) -> list[EventSchema]:
    """
    Build a clean synthetic dataset containing exactly one
    controlled anomalous scenario.

    The existing generator's built-in anomaly is disabled so
    scenarios remain isolated from one another.
    """

    generator = SyntheticEventGenerator(seed=42)

    baseline_events = generator.generate(
        start_date=start_date,
        days=days,
        include_anomaly=False,
    )

    scenario_events = build_scenario(
        scenario,
        SCENARIO_START,
        user_id=user_id,
        hour=hour,
        minute=minute,
    )

    events = [
        *baseline_events,
        *scenario_events,
    ]

    return clean_events(events)
