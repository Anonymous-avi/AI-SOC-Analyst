from typing import Any

from pydantic import BaseModel, Field

from app.schemas.security_alert import AlertSeverity
from app.schemas.security_event import SecurityEvent


class DetectionResult(BaseModel):
    attack_type: str = Field(min_length=1)

    severity: AlertSeverity

    attacker_ip: str | None = None

    confidence: float = Field(
        default=0.95,
        ge=0.0,
        le=1.0,
    )

    recommendation: str = Field(min_length=1)

    evidence_events: list[SecurityEvent] = Field(
        default_factory=list
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )