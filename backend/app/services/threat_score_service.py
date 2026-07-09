from app.schemas.security_alert import AlertSeverity


def calculate_threat_score(
    attack_type: str,
    severity: AlertSeverity,
    confidence: float,
    ioc_count: int,
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

    score += min(ioc_count * 5, 20)

    if confidence >= 0.90:
        score += 10

    return min(score, 100)