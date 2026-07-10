from app.schemas.ioc import IOC
from app.services.threat_score_service import calculate_threat_score
from datetime import datetime
from uuid import uuid4

from app.schemas.security_alert import (
    AlertSeverity,
    SecurityAlert,
)
from app.services.mitre_service import get_mitre_mapping


def build_security_alert(
    detector_output: dict,
    iocs: IOC,
) -> SecurityAlert:

    severity = AlertSeverity(
        detector_output["severity"].upper()
    )

    mitre = get_mitre_mapping(
        detector_output["attack_type"]
    )
    ioc_count = (
    len(iocs.ips)
    + len(iocs.domains)
    + len(iocs.urls)
    + len(iocs.cves)
    + len(iocs.hashes)
    + len(iocs.emails)
    + len(iocs.malware)
)

    score = calculate_threat_score(
    attack_type=detector_output["attack_type"],
    severity=severity,
    confidence=0.95,
    ioc_count=ioc_count,
)
    if score >= 90:
      risk_level = "Critical"
    elif score >= 70:
      risk_level = "High"
    elif score >= 40:
       risk_level = "Medium"
    else:
       risk_level = "Low"

    return SecurityAlert(

        alert_id=f"ALT-{uuid4().hex[:8].upper()}",

        title=f"{detector_output['attack_type']} Detected",

        attack_type=detector_output["attack_type"],

        severity=severity,

        confidence=0.95,

        attacker_ip=detector_output.get("attacker_ip"),

        recommendation=detector_output["recommendation"],

        mitre=mitre,

        iocs=iocs,

        threat_score=score,

        risk_level=risk_level,

        created_at=datetime.utcnow()
    )