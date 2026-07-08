import re


APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip_address>\S+) '
    r'\S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status_code>\d{3}) '
    r'(?P<response_size>\S+)'
)


def parse_apache_log(log_line: str):

    match = APACHE_LOG_PATTERN.fullmatch(log_line.strip())

    if not match:
        return None

    response_size = match.group("response_size")

    return {
        "timestamp": match.group("timestamp"),
        "source_ip": match.group("ip_address"),
        "service": "apache",
        "event_type": "http_request",
        "method": match.group("method"),
        "path": match.group("path"),
        "protocol": match.group("protocol"),
        "status_code": int(match.group("status_code")),
        "response_size": (
            int(response_size)
            if response_size.isdigit()
            else None
        )
    }