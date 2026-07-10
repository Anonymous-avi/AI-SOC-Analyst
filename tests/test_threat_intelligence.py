from app.services.threat_intelligence_service import (
    enrich_ip,
)


def test_private_ip_enrichment():

    result = enrich_ip("192.168.1.10")

    assert result.indicator == "192.168.1.10"
    assert result.indicator_type == "ip"
    assert result.provider == "local"

    assert result.reputation == "private"
    assert result.malicious is False
    assert result.confidence == 1.0

    assert "private-ip" in result.tags


def test_known_malicious_ip_enrichment():

    result = enrich_ip("203.45.12.8")

    assert result.indicator == "203.45.12.8"
    assert result.reputation == "malicious"
    assert result.malicious is True
    assert result.confidence == 0.95

    assert "known-malicious" in result.tags


def test_unknown_public_ip_enrichment():

    result = enrich_ip("8.8.8.8")

    assert result.indicator == "8.8.8.8"
    assert result.reputation == "unknown"
    assert result.malicious is False
    assert result.confidence == 0.0