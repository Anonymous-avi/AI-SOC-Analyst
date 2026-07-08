from parsers.ssh_parser import parse_ssh_log
from parsers.apache_parser import parse_apache_log
from parsers.log_detector import detect_log_type


def test_parse_valid_ssh_log():
    line = (
        "Jul 08 10:15:20 server sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 22 ssh2"
    )

    result = parse_ssh_log(line)

    assert result is not None
    assert result["event"] == "Failed"
    assert result["username"] == "admin"
    assert result["ip_address"] == "192.168.1.10"
    assert result["port"] == 22


def test_parse_invalid_ssh_log():
    result = parse_ssh_log("This is not an SSH log.")

    assert result is None


def test_parse_valid_apache_log():
    line = (
        '203.45.12.8 - - [08/Jul/2026:10:20:15 +0000] '
        '"GET /../../etc/passwd HTTP/1.1" 400 128'
    )

    result = parse_apache_log(line)

    assert result is not None
    assert result["source_ip"] == "203.45.12.8"
    assert result["method"] == "GET"
    assert result["path"] == "/../../etc/passwd"
    assert result["status_code"] == 400


def test_detect_ssh_log_type():
    content = "\n".join([
        "Jul 08 10:15:20 server sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 22 ssh2",

        "Jul 08 10:15:30 server sshd[1235]: "
        "Failed password for admin from 192.168.1.10 port 22 ssh2",
    ])

    assert detect_log_type(content) == "ssh"


def test_detect_apache_log_type():
    content = "\n".join([
        '192.168.1.20 - - [08/Jul/2026:10:15:20 +0000] '
        '"GET /index.html HTTP/1.1" 200 1024',

        '203.45.12.8 - - [08/Jul/2026:10:20:15 +0000] '
        '"GET /../../etc/passwd HTTP/1.1" 400 128',
    ])

    assert detect_log_type(content) == "apache"


def test_detect_unknown_log_type():
    assert detect_log_type(
        "This is an ordinary document."
    ) == "unknown"