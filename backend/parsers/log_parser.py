import re

def parse_ssh_log(log_line):

    pattern = (
        r'(\w+\s+\d+\s+\d+:\d+:\d+) '
        r'(\S+) '
        r'(\w+)\[\d+\]: '
        r'(Failed|Accepted) password for '
        r'(\w+) from '
        r'([\d\.]+) port '
        r'(\d+) '
        r'(\w+)'
    )

    match = re.match(pattern, log_line)

    if not match:
        return None

    return {
        "timestamp": match.group(1),
        "hostname": match.group(2),
        "service": match.group(3),
        "event": match.group(4),
        "username": match.group(5),
        "ip_address": match.group(6),
        "port": int(match.group(7)),
        "protocol": match.group(8)
    }