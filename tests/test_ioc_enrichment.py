from app.schemas.ioc import IOC
from app.services.ioc_enrichment_service import enrich_iocs


def test_enrich_multiple_ip_iocs():

    iocs = IOC(
        ips=[
            "192.168.1.10",
            "203.45.12.8",
            "8.8.8.8",
        ]
    )

    results = enrich_iocs(iocs)

    assert len(results) == 3

    results_by_indicator = {
        result.indicator: result
        for result in results
    }

    assert results_by_indicator[
        "192.168.1.10"
    ].reputation == "private"

    assert results_by_indicator[
        "203.45.12.8"
    ].reputation == "malicious"

    assert results_by_indicator[
        "8.8.8.8"
    ].reputation == "unknown"


def test_enrich_empty_iocs():

    iocs = IOC()

    results = enrich_iocs(iocs)

    assert results == []


def test_enrichment_results_have_correct_type():

    iocs = IOC(
        ips=["203.45.12.8"]
    )

    results = enrich_iocs(iocs)

    assert len(results) == 1
    assert results[0].indicator_type == "ip"
    assert results[0].provider == "local"