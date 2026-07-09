import re

from app.schemas.ioc import IOC


IP_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

URL_REGEX = re.compile(
    r"https?://[^\s]+"
)

DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b"
)

CVE_REGEX = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE
)

MD5_REGEX = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)

SHA256_REGEX = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


def extract_iocs(text: str) -> IOC:

    urls = sorted(set(URL_REGEX.findall(text)))

    ips = sorted(set(IP_REGEX.findall(text)))

    emails = sorted(set(EMAIL_REGEX.findall(text)))

    cves = sorted({
        match.upper()
        for match in CVE_REGEX.findall(text)
    })

    md5_hashes = MD5_REGEX.findall(text)

    sha256_hashes = SHA256_REGEX.findall(text)

    hashes = sorted(
        set(md5_hashes + sha256_hashes)
    )

    domains = []

    for match in DOMAIN_REGEX.findall(text):

        if match not in urls:
            domains.append(match)

    domains = sorted(set(domains))

    return IOC(
        ips=ips,
        domains=domains,
        urls=urls,
        cves=cves,
        hashes=hashes,
        emails=emails,
        malware=[]
    )