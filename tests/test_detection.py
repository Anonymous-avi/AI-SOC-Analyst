from datetime import datetime

from app.schemas.security_event import (
    EventOutcome,
    SecurityEvent,
)
from ml.anomaly_detection import (
    detect_brute_force,
    detect_path_traversal,
)


def make_ssh_failure(timestamp: datetime) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        source_type="ssh",
        source_ip="192.168.1.10",
        hostname="server",
        service="sshd",
        event_type="authentication_failure",
        user="admin",
        action="login",
        outcome=EventOutcome.FAILURE,
        raw_event={}
    )


def test_detect_brute_force_inside_time_window():
    events = [
        make_ssh_failure(datetime(2026, 7, 8, 10, 15, 20)),
        make_ssh_failure(datetime(2026, 7, 8, 10, 15, 30)),
        make_ssh_failure(datetime(2026, 7, 8, 10, 15, 40)),
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "Brute Force"
    assert alerts[0]["failed_attempts"] == 3


def test_no_brute_force_outside_time_window():
    events = [
        make_ssh_failure(datetime(2026, 7, 8, 10, 15, 20)),
        make_ssh_failure(datetime(2026, 7, 8, 10, 17, 20)),
        make_ssh_failure(datetime(2026, 7, 8, 10, 19, 20)),
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_detect_path_traversal():
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 8, 10, 20, 15),
        source_type="apache",
        source_ip="203.45.12.8",
        service="apache",
        event_type="http_request",
        action="GET",
        outcome=EventOutcome.CLIENT_ERROR,
        raw_event={
            "path": "/../../etc/passwd",
            "status_code": 400,
        }
    )

    alerts = detect_path_traversal([event])

    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "Path Traversal"
    assert alerts[0]["attacker_ip"] == "203.45.12.8"


def test_normal_http_request_is_not_path_traversal():
    event = SecurityEvent(
        timestamp=datetime(2026, 7, 8, 10, 20, 15),
        source_type="apache",
        source_ip="192.168.1.20",
        service="apache",
        event_type="http_request",
        action="GET",
        outcome=EventOutcome.SUCCESS,
        raw_event={
            "path": "/index.html",
            "status_code": 200,
        }
    )

    alerts = detect_path_traversal([event])

    assert alerts == []