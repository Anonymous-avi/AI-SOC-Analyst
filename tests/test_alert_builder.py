from app.schemas.ioc import IOC
from app.schemas.security_alert import SecurityAlert
from app.services.alert_builder import build_security_alert


def test_build_brute_force_security_alert():

    detector_output = {
        "attack_type": "Brute Force",
        "severity": "High",
        "attacker_ip": "192.168.1.10",
        "recommendation": "Investigate the source IP.",
    }

    iocs = IOC(
        ips=["192.168.1.10"],
    )

    alert = build_security_alert(
        detector_output=detector_output,
        iocs=iocs,
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


def test_build_critical_alert_with_multiple_iocs():

    detector_output = {
        "attack_type": "Path Traversal",
        "severity": "High",
        "attacker_ip": "203.45.12.8",
        "recommendation": "Investigate the web request.",
    }

    iocs = IOC(
        ips=["203.45.12.8"],
        cves=["CVE-2024-12345"],
    )

    alert = build_security_alert(
        detector_output=detector_output,
        iocs=iocs,
    )

    assert isinstance(alert, SecurityAlert)

    assert alert.attack_type == "Path Traversal"

    assert alert.mitre.technique_id == "T1083"

    assert alert.iocs.ips == ["203.45.12.8"]
    assert alert.iocs.cves == ["CVE-2024-12345"]

    assert alert.threat_score == 95
    assert alert.risk_level == "Critical"


def test_generated_alert_ids_are_unique():

    detector_output = {
        "attack_type": "Brute Force",
        "severity": "High",
        "attacker_ip": "192.168.1.10",
        "recommendation": "Investigate the source IP.",
    }

    iocs = IOC(
        ips=["192.168.1.10"],
    )

    first_alert = build_security_alert(detector_output, iocs)
    second_alert = build_security_alert(detector_output, iocs)

    assert first_alert.alert_id != second_alert.alert_id