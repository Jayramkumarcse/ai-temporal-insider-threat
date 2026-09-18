import json
from collections import defaultdict
from datetime import date
from pathlib import Path

from insider_threat.preprocessing.processed_event import ProcessedEvent

from .behavioral import aggregate_behavioral_features
from .temporal import ensure_utc


def load_processed_events(
    path: str | Path,
) -> list[ProcessedEvent]:
    """
    Load processed events from a JSON file.
    """
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError(
            "Processed event dataset must contain a list"
        )

    return [
        ProcessedEvent.model_validate(record)
        for record in records
    ]


def group_events_by_user_and_day(
    events: list[ProcessedEvent],
) -> dict[tuple[str, date], list[ProcessedEvent]]:
    """
    Group events into user-day behavioral windows.

    The grouping key is:

        (user_id, UTC calendar date)
    """
    grouped: dict[
        tuple[str, date],
        list[ProcessedEvent],
    ] = defaultdict(list)

    for event in events:
        timestamp = ensure_utc(event.timestamp)

        key = (
            event.user_id,
            timestamp.date(),
        )

        grouped[key].append(event)

    for event_list in grouped.values():
        event_list.sort(
            key=lambda event: ensure_utc(event.timestamp)
        )

    return dict(grouped)


def build_user_day_features(
    events: list[ProcessedEvent],
) -> list[dict]:
    """
    Build one behavioral feature record per user per UTC day.

    Each output record contains:
        - user_id
        - date
        - behavioral and temporal features
    """
    grouped = group_events_by_user_and_day(events)

    feature_records = []

    for (user_id, event_date), event_list in sorted(
        grouped.items(),
        key=lambda item: item[0],
    ):
        features = aggregate_behavioral_features(
            event_list
        )

        record = {
            "user_id": user_id,
            "date": event_date.isoformat(),
            **features,
        }

        feature_records.append(record)

    return feature_records


def save_user_day_features(
    feature_records: list[dict],
    output_path: str | Path,
) -> None:
    """
    Save user-day behavioral features as JSON.
    """
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            feature_records,
            file,
            indent=2,
        )
