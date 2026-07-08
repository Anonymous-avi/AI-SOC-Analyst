from parsers.log_parser import parse_ssh_log


def parse_log_content(content: str):

    parsed_logs = []

    lines = content.splitlines()

    for line in lines:

        if line.strip():

            parsed = parse_ssh_log(line)

            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs