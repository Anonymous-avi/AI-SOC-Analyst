from app.schemas.security_alert import AlertSeverity
from app.services.threat_score_service import calculate_threat_score
from datetime import datetime, timezone
from app.schemas.threat_intelligence import ThreatIntelligenceResult

def test_high_severity_brute_force_score():

    score = calculate_threat_score(
        attack_type="Brute Force",
        severity=AlertSeverity.HIGH,
        confidence=0.95,
        ioc_count=1,
    )

    assert score == 85


def test_path_traversal_score():

    score = calculate_threat_score(
        attack_type="Path Traversal",
        severity=AlertSeverity.HIGH,
        confidence=0.95,
        ioc_count=2,
    )

    assert score == 95


def test_ioc_score_is_capped():

    score = calculate_threat_score(
        attack_type="Brute Force",
        severity=AlertSeverity.LOW,
        confidence=0.50,
        ioc_count=100,
    )

    assert score == 70


def test_total_score_never_exceeds_100():

    score = calculate_threat_score(
        attack_type="Path Traversal",
        severity=AlertSeverity.CRITICAL,
        confidence=0.99,
        ioc_count=100,
    )

    assert score == 100

def test_malicious_threat_intelligence_increases_score():

    intel = ThreatIntelligenceResult(
        indicator="203.45.12.8",
        indicator_type="ip",
        provider="local",
        reputation="malicious",
        malicious=True,
        confidence=0.95,
        last_updated=datetime.now(timezone.utc),
    )

    score = calculate_threat_score(
        attack_type="Brute Force",
        severity=AlertSeverity.LOW,
        confidence=0.50,
        ioc_count=1,
        threat_intelligence=[intel],
    )

    assert score == 65


def test_private_ip_does_not_increase_score():

    intel = ThreatIntelligenceResult(
        indicator="192.168.1.10",
        indicator_type="ip",
        provider="local",
        reputation="private",
        malicious=False,
        confidence=1.0,
        last_updated=datetime.now(timezone.utc),
    )

    score = calculate_threat_score(
        attack_type="Brute Force",
        severity=AlertSeverity.LOW,
        confidence=0.50,
        ioc_count=1,
        threat_intelligence=[intel],
    )

    assert score == 55


def test_threat_intelligence_contribution_is_capped():

    malicious_results = [
        ThreatIntelligenceResult(
            indicator=f"203.0.113.{index}",
            indicator_type="ip",
            provider="local",
            reputation="malicious",
            malicious=True,
            confidence=0.95,
        )
        for index in range(1, 6)
    ]

    score = calculate_threat_score(
        attack_type="Unknown Attack",
        severity=AlertSeverity.LOW,
        confidence=0.50,
        ioc_count=0,
        threat_intelligence=malicious_results,
    )

    # 20 attack + 10 severity + 20 capped TI contribution
    assert score == 50


def test_score_with_threat_intelligence_never_exceeds_100():

    intel = ThreatIntelligenceResult(
        indicator="203.45.12.8",
        indicator_type="ip",
        provider="local",
        reputation="malicious",
        malicious=True,
        confidence=0.95,
    )

    score = calculate_threat_score(
        attack_type="Path Traversal",
        severity=AlertSeverity.CRITICAL,
        confidence=0.99,
        ioc_count=100,
        threat_intelligence=[intel],
    )

    assert score == 100