from parsers.ssh_parser import parse_ssh_log
from parsers.apache_parser import parse_apache_log


PARSER_REGISTRY = {
    "ssh": parse_ssh_log,
    "apache": parse_apache_log
}


def get_parser(log_type: str):

    return PARSER_REGISTRY.get(log_type)