from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitreTechnique(BaseModel):
    tactic: str
    technique: str
    technique_id: str


class SecurityAlert(BaseModel):

    alert_id: str

    title: str

    attack_type: str

    severity: AlertSeverity

    confidence: float

    attacker_ip: str | None = None

    recommendation: str

    mitre: MitreTechnique

    created_at: datetime

    threat_score: int

    risk_level: str