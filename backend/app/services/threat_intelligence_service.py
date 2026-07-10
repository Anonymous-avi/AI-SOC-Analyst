from datetime import datetime, timezone
from ipaddress import ip_address

from app.schemas.threat_intelligence import ThreatIntelligenceResult


KNOWN_MALICIOUS_IPS = {
    "203.45.12.8",
    "203.45.12.7",
}


def is_private_ip(indicator: str) -> bool:
    try:
        return ip_address(indicator).is_private
    except ValueError:
        return False


def enrich_ip(indicator: str) -> ThreatIntelligenceResult:

    if is_private_ip(indicator):
        return ThreatIntelligenceResult(
            indicator=indicator,
            indicator_type="ip",
            provider="local",
            reputation="private",
            malicious=False,
            confidence=1.0,
            tags=["private-ip", "internal-network"],
            description=(
                "Private IP address. External reputation lookup skipped."
            ),
            last_updated=datetime.now(timezone.utc),
        )

    if indicator in KNOWN_MALICIOUS_IPS:
        return ThreatIntelligenceResult(
            indicator=indicator,
            indicator_type="ip",
            provider="local",
            reputation="malicious",
            malicious=True,
            confidence=0.95,
            tags=["known-malicious", "suspicious-source"],
            description=(
                "Indicator matched the local malicious IP intelligence dataset."
            ),
            last_updated=datetime.now(timezone.utc),
        )

    return ThreatIntelligenceResult(
        indicator=indicator,
        indicator_type="ip",
        provider="local",
        reputation="unknown",
        malicious=False,
        confidence=0.0,
        tags=[],
        description=(
            "No threat intelligence information is available "
            "for this IP address."
        ),
        last_updated=datetime.now(timezone.utc),
    )