from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.ioc import IOC
from app.schemas.security_alert import (
    AlertSeverity,
    SecurityAlert,
)
from app.schemas.security_event import SecurityEvent
from app.services.mitre_service import get_mitre_mapping
from app.services.threat_score_service import calculate_threat_score
from nlp.ioc_extractor import extract_iocs


def extract_iocs_from_evidence(
    evidence_events: list[SecurityEvent],
) -> IOC:

    combined_text_parts = []

    for event in evidence_events:

        # Include common normalized fields.
        if event.source_ip:
            combined_text_parts.append(event.source_ip)

        if event.destination_ip:
            combined_text_parts.append(event.destination_ip)

        if event.hostname:
            combined_text_parts.append(event.hostname)

        if event.user:
            combined_text_parts.append(event.user)

        # Include the original parsed event data.
        combined_text_parts.extend(
            str(value)
            for value in event.raw_event.values()
            if value is not None
        )

    combined_text = " ".join(combined_text_parts)

    return extract_iocs(combined_text)


def build_security_alert(
    detector_output: dict,
) -> SecurityAlert:

    severity = AlertSeverity(
        detector_output["severity"].upper()
    )

    mitre = get_mitre_mapping(
        detector_output["attack_type"]
    )

    evidence_events = detector_output.get(
        "evidence_events",
        [],
    )

    iocs = extract_iocs_from_evidence(
        evidence_events
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

    confidence = 0.95

    score = calculate_threat_score(
        attack_type=detector_output["attack_type"],
        severity=severity,
        confidence=confidence,
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
        confidence=confidence,
        attacker_ip=detector_output.get("attacker_ip"),
        recommendation=detector_output["recommendation"],
        mitre=mitre,
        iocs=iocs,
        threat_score=score,
        risk_level=risk_level,
        created_at=datetime.now(timezone.utc),
    )