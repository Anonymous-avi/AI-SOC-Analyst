import re


def detect_log_type(content: str):

    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
    ]

    if not lines:
        return "unknown"

    sample_lines = lines[:20]

    ssh_pattern = re.compile(
        r"\bsshd\[\d+\]:\s+(Failed|Accepted) password\b"
    )

    ssh_matches = sum(
        1 for line in sample_lines
        if ssh_pattern.search(line)
    )

    if ssh_matches >= max(1, len(sample_lines) // 2):
        return "ssh"

    return "unknown"