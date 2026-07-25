from datetime import datetime, timezone

from app.schemas.ioc import IOC
from app.schemas.security_alert import (
    AlertSeverity,
    MitreTechnique,
    SecurityAlert,
)
from app.schemas.threat_intelligence import ThreatIntelligenceResult
from app.services.ai_summary_service import generate_ai_summary


def build_alert(**overrides):
    alert = SecurityAlert(
        alert_id="ALT-TEST01",
        title="Brute Force Detected",
        attack_type="Brute Force",
        severity=AlertSeverity.HIGH,
        confidence=0.95,
        attacker_ip="192.168.1.10",
        recommendation="Investigate the source IP.",
        mitre=MitreTechnique(
            tactic="Credential Access",
            technique="Brute Force",
            technique_id="T1110",
        ),
        created_at=datetime.now(timezone.utc),
        threat_score=85,
        risk_level="High",
        iocs=IOC(
            ips=["192.168.1.10"],
            domains=[],
            urls=[],
            cves=[],
            hashes=[],
            emails=[],
            malware=[],
        ),
        threat_intelligence=[
            ThreatIntelligenceResult(
                indicator="192.168.1.10",
                indicator_type="ip",
                provider="local",
                reputation="private",
                malicious=False,
                confidence=0.95,
            )
        ],
    )

    for key, value in overrides.items():
        setattr(alert, key, value)

    return alert


def test_generate_ai_summary_returns_structured_report():
    summary = generate_ai_summary(build_alert())

    assert summary.startswith("🤖 AI SECURITY INVESTIGATION REPORT")
    assert "Attack Overview" in summary
    assert "Risk Assessment" in summary
    assert "MITRE ATT&CK Mapping" in summary
    assert "Indicators of Compromise" in summary
    assert "Business Impact" in summary
    assert "Recommended Actions" in summary
    assert "Conclusion" in summary
    assert "1. Block attacker IP 192.168.1.10." in summary
    assert "None" not in summary


def test_generate_ai_summary_omits_empty_ioc_values():
    summary = generate_ai_summary(
        build_alert(
            attacker_ip=None,
            iocs=IOC(),
        )
    )

    assert "Attacker IP:" not in summary
    assert "IPs:" not in summary
    assert "Hashes:" not in summary
    assert "Domains:" not in summary
    assert "URLs:" not in summary
    assert "Malware:" not in summary
    assert "CVEs:" not in summary
    assert "Emails:" not in summary
    assert "No indicators of compromise were identified." in summary
    assert "None" not in summary