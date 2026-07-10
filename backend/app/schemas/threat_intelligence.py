from datetime import datetime

from pydantic import BaseModel, Field


class ThreatIntelligenceResult(BaseModel):
    indicator: str = Field(min_length=1)

    indicator_type: str = Field(min_length=1)

    provider: str = Field(min_length=1)

    reputation: str = "unknown"

    malicious: bool = False

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    tags: list[str] = Field(default_factory=list)

    description: str | None = None

    last_updated: datetime | None = None