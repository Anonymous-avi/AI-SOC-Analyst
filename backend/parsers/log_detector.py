import re


SSH_PATTERN = re.compile(
    r"\bsshd\[\d+\]:\s+(Failed|Accepted) password\b"
)

APACHE_PATTERN = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] '
    r'"[A-Z]+ \S+ HTTP/\d(?:\.\d)?" '
    r'\d{3} \S+$'
)


def calculate_match_ratio(lines, pattern):

    if not lines:
        return 0.0

    matches = sum(
        1 for line in lines
        if pattern.search(line)
    )

    return matches / len(lines)


def detect_log_type(content: str):

    lines = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
    ]

    if not lines:
        return "unknown"

    sample_lines = lines[:20]

    ssh_ratio = calculate_match_ratio(
        sample_lines,
        SSH_PATTERN
    )

    apache_ratio = calculate_match_ratio(
        sample_lines,
        APACHE_PATTERN
    )

    scores = {
        "ssh": ssh_ratio,
        "apache": apache_ratio
    }

    detected_type = max(scores, key=scores.get)

    if scores[detected_type] < 0.5:
        return "unknown"

    return detected_type