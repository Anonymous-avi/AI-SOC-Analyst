from parsers.log_detector import detect_log_type
from parsers.parser_registry import get_parser


def parse_log_content(content: str):

    log_type = detect_log_type(content)

    parser = get_parser(log_type)

    if parser is None:
        return {
            "log_type": "unknown",
            "parsed_logs": [],
            "failed_lines": 0
        }

    parsed_logs = []
    failed_lines = 0

    for line in content.splitlines():

        if not line.strip():
            continue

        parsed = parser(line)

        if parsed:
            parsed_logs.append(parsed)
        else:
            failed_lines += 1

    return {
        "log_type": log_type,
        "parsed_logs": parsed_logs,
        "failed_lines": failed_lines
    }