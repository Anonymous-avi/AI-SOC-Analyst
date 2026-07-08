from parsers.log_detector import detect_log_type
from parsers.ssh_parser import parse_ssh_log


def parse_log_content(content: str):

    log_type = detect_log_type(content)

    parsed_logs = []

    if log_type == "ssh":

        for line in content.splitlines():

            if not line.strip():
                continue

            parsed = parse_ssh_log(line)

            if parsed:
                parsed_logs.append(parsed)

    return {
        "log_type": log_type,
        "parsed_logs": parsed_logs
    }