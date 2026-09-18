from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProcessedEvent(BaseModel):
    """
    Preprocessed event representation containing the original
    event information plus derived temporal attributes.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime

    user_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    action: str = Field(min_length=1)

    resource: str | None = None
    device_id: str | None = None
    source_ip: str | None = None

    status: str = "success"
    sensitive: bool = False

    bytes_transferred: int = Field(default=0, ge=0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    hour_of_day: int = Field(ge=0, le=23)
    day_of_week: int = Field(ge=0, le=6)
    is_weekend: bool
    is_off_hours: bool
