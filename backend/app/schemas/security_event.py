from enum import Enum
from typing import Any
from datetime import datetime

from pydantic import BaseModel, Field


class Severity(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"


class SecurityEvent(BaseModel):
    timestamp: datetime

    source_type: str = Field(min_length=1)

    source_ip: str | None = None
    destination_ip: str | None = None

    hostname: str | None = None

    service: str = Field(min_length=1)

    event_type: str = Field(min_length=1)

    severity: Severity = Severity.UNKNOWN

    user: str | None = None

    action: str | None = None

    outcome: EventOutcome = EventOutcome.UNKNOWN

    raw_event: dict[str, Any]