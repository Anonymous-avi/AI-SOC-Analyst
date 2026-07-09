from nlp.ioc_extractor import extract_iocs


def test_extract_multiple_iocs():

    text = """
    Failed login from 192.168.1.10

    Visit http://evil.com/login

    CVE-2024-12345

    Email admin@test.com
    """

    iocs = extract_iocs(text)

    assert "192.168.1.10" in iocs.ips

    assert "http://evil.com/login" in iocs.urls

    assert "CVE-2024-12345" in iocs.cves

    assert "admin@test.com" in iocs.emails