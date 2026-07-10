from app.schemas.ioc import IOC
from app.schemas.threat_intelligence import ThreatIntelligenceResult
from app.services.threat_intelligence_service import enrich_ip


def enrich_iocs(
    iocs: IOC,
) -> list[ThreatIntelligenceResult]:

    enrichment_results = []

    for ip in iocs.ips:
        result = enrich_ip(ip)
        enrichment_results.append(result)

    return enrichment_results