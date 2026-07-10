from datetime import datetime, timezone

from app.schemas.security_alert import SecurityAlert
from app.schemas.security_event import SecurityEvent
from app.services.alert_builder import build_security_alert


def create_security_event(
    source_ip: str,
    event_type: str,
    service: str,
    raw_event: dict,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="test",
        source_ip=source_ip,
        destination_ip=None,
        hostname=None,
        service=service,
        event_type=event_type,
        user=None,
        action=None,
        raw_event=raw_event,
    )


def test_build_brute_force_security_alert():

    evidence_event = create_security_event(
        source_ip="192.168.1.10",
        event_type="authentication_failure",
        service="ssh",
        raw_event={
            "message": (
                "Failed password for admin "
                "from 192.168.1.10"
            )
        },
    )

    detector_output = {
        "attack_type": "Brute Force",
        "severity": "High",
        "attacker_ip": "192.168.1.10",
        "evidence_events": [evidence_event],
        "recommendation": "Investigate the source IP.",
    }

    alert = build_security_alert(
        detector_output=detector_output,
    )

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Brute Force"
    assert alert.severity.value == "HIGH"
    assert alert.attacker_ip == "192.168.1.10"

    assert alert.confidence == 0.95

    assert alert.mitre.tactic == "Credential Access"
    assert alert.mitre.technique == "Brute Force"
    assert alert.mitre.technique_id == "T1110"

    assert alert.iocs.ips == ["192.168.1.10"]

    assert alert.threat_score == 85
    assert alert.risk_level == "High"

    assert alert.alert_id.startswith("ALT-")
    assert len(alert.threat_intelligence) == 1

    intel = alert.threat_intelligence[0]

    assert intel.indicator == "192.168.1.10"
    assert intel.reputation == "private"
    assert intel.malicious is False
    assert intel.provider == "local"


def test_build_critical_alert_with_multiple_iocs():

    evidence_event = create_security_event(
        source_ip="203.45.12.8",
        event_type="http_request",
        service="apache",
        raw_event={
            "path": "/../../etc/passwd",
            "description": (
                "Request from 203.45.12.8 related "
                "to CVE-2024-12345"
            ),
        },
    )

    detector_output = {
        "attack_type": "Path Traversal",
        "severity": "High",
        "attacker_ip": "203.45.12.8",
        "evidence_events": [evidence_event],
        "recommendation": "Investigate the web request.",
    }

    alert = build_security_alert(
        detector_output=detector_output,
    )

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Path Traversal"

    assert alert.mitre.technique_id == "T1083"

    assert alert.iocs.ips == ["203.45.12.8"]
    assert alert.iocs.cves == ["CVE-2024-12345"]

    assert alert.threat_score == 95
    assert alert.risk_level == "Critical"
    assert len(alert.threat_intelligence) == 1

    intel = alert.threat_intelligence[0]

    assert intel.indicator == "203.45.12.8"
    assert intel.reputation == "malicious"
    assert intel.malicious is True
    assert intel.confidence == 0.95
    assert intel.provider == "local"


def test_generated_alert_ids_are_unique():

    evidence_event = create_security_event(
        source_ip="192.168.1.10",
        event_type="authentication_failure",
        service="ssh",
        raw_event={
            "message": (
                "Failed password for admin "
                "from 192.168.1.10"
            )
        },
    )

    detector_output = {
        "attack_type": "Brute Force",
        "severity": "High",
        "attacker_ip": "192.168.1.10",
        "evidence_events": [evidence_event],
        "recommendation": "Investigate the source IP.",
    }

    first_alert = build_security_alert(detector_output)
    second_alert = build_security_alert(detector_output)

    assert first_alert.alert_id != second_alert.alert_id