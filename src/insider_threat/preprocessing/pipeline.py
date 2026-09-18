import json
from pathlib import Path

from insider_threat.ingestion.loader import load_events_from_json

from .cleaning import clean_events
from .normalization import (
    derive_temporal_fields,
    normalize_events,
)
from .processed_event import ProcessedEvent


def build_processed_events(
    input_path: str | Path,
) -> list[ProcessedEvent]:
    """
    Load, clean, normalize, and enrich events.

    Pipeline:

        raw JSON
          ↓
        validation
          ↓
        duplicate removal
          ↓
        chronological sorting
          ↓
        normalization
          ↓
        temporal enrichment
    """
    events = load_events_from_json(input_path)

    events = clean_events(events)

    events = normalize_events(events)

    processed_events = []

    for event in events:
        temporal = derive_temporal_fields(event)

        processed_events.append(
            ProcessedEvent(
                **event.model_dump(),
                **temporal,
            )
        )

    return processed_events


def save_processed_events(
    events: list[ProcessedEvent],
    output_path: str | Path,
) -> None:
    """
    Save processed events as JSON.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    records = [
        event.model_dump(mode="json")
        for event in events
    ]

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            records,
            file,
            indent=2,
        )
