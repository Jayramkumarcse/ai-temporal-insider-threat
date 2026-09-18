from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventSchema(BaseModel):
    """
    Canonical representation of a user activity event.

    This schema is used as the normalized input representation
    for temporal and behavioral insider-threat analysis.
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

    status: str = Field(default="success")
    sensitive: bool = False

    bytes_transferred: int = Field(default=0, ge=0)

    metadata: dict[str, Any] = Field(default_factory=dict)
