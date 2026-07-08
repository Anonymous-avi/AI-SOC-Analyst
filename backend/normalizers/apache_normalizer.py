from app.schemas.security_event import (
    EventOutcome,
    SecurityEvent,
)


def normalize_apache_event(log: dict) -> SecurityEvent:

    status_code = log["status_code"]

    if 200 <= status_code < 300:
        outcome = EventOutcome.SUCCESS

    elif 400 <= status_code < 500:
        outcome = EventOutcome.CLIENT_ERROR

    elif 500 <= status_code < 600:
        outcome = EventOutcome.SERVER_ERROR

    else:
        outcome = EventOutcome.UNKNOWN

    return SecurityEvent(
        timestamp=log["timestamp"],
        source_type="apache",
        source_ip=log["source_ip"],
        destination_ip=None,
        hostname=None,
        service=log["service"],
        event_type="http_request",
        user=None,
        action=log["method"],
        outcome=outcome,
        raw_event=log
    )