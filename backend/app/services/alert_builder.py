from datetime import datetime
from uuid import uuid4

from app.schemas.security_alert import (
    AlertSeverity,
    SecurityAlert,
)
from app.services.mitre_service import get_mitre_mapping


def build_security_alert(detector_output: dict) -> SecurityAlert:

    severity = AlertSeverity(
        detector_output["severity"].upper()
    )

    mitre = get_mitre_mapping(
        detector_output["attack_type"]
    )

    return SecurityAlert(

        alert_id=f"ALT-{uuid4().hex[:8].upper()}",

        title=f"{detector_output['attack_type']} Detected",

        attack_type=detector_output["attack_type"],

        severity=severity,

        confidence=0.95,

        attacker_ip=detector_output.get("attacker_ip"),

        recommendation=detector_output["recommendation"],

        mitre=mitre,

        created_at=datetime.utcnow()
    )