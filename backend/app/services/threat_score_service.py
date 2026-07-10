from app.schemas.security_alert import AlertSeverity
from app.schemas.threat_intelligence import ThreatIntelligenceResult


def calculate_threat_score(
    attack_type: str,
    severity: AlertSeverity,
    confidence: float,
    ioc_count: int,
    threat_intelligence: list[ThreatIntelligenceResult] | None = None,
) -> int:

    score = 0

    attack_scores = {
        "Brute Force": 40,
        "Path Traversal": 45,
    }

    score += attack_scores.get(attack_type, 20)

    severity_scores = {
        AlertSeverity.LOW: 10,
        AlertSeverity.MEDIUM: 20,
        AlertSeverity.HIGH: 30,
        AlertSeverity.CRITICAL: 40,
    }

    score += severity_scores.get(severity, 0)

    # IOC contribution is capped at 20 points.
    score += min(ioc_count * 5, 20)

    # High-confidence detection contribution.
    if confidence >= 0.90:
        score += 10

    # Threat-intelligence contribution.
    threat_intelligence = threat_intelligence or []

    malicious_count = sum(
        1
        for result in threat_intelligence
        if result.malicious
    )

    threat_intelligence_score = min(
        malicious_count * 10,
        20,
    )

    score += threat_intelligence_score

    return min(score, 100)