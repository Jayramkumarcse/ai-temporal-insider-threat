import json
from pathlib import Path

from .schema import EventSchema


def load_events_from_json(path: str | Path) -> list[EventSchema]:
    """
    Load and validate event records from a JSON file.
    """

    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("JSON dataset must contain a list of event records")

    return [EventSchema.model_validate(record) for record in records]
