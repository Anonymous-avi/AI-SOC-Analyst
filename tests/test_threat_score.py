from app.schemas.security_alert import AlertSeverity
from app.services.threat_score_service import calculate_threat_score


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