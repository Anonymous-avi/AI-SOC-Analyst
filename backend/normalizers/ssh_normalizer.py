from app.schemas.security_event import (
    EventOutcome,
    SecurityEvent,
)


def normalize_ssh_event(log: dict) -> SecurityEvent:

    event = log["event"]

    if event == "Failed":
        event_type = "authentication_failure"
        outcome = EventOutcome.FAILURE

    elif event == "Accepted":
        event_type = "authentication_success"
        outcome = EventOutcome.SUCCESS

    else:
        event_type = "authentication_event"
        outcome = EventOutcome.UNKNOWN

    return SecurityEvent(
        timestamp=log["timestamp"],
        source_type="ssh",
        source_ip=log["ip_address"],
        destination_ip=None,
        hostname=log["hostname"],
        service=log["service"],
        event_type=event_type,
        user=log["username"],
        action="login",
        outcome=outcome,
        raw_event=log
    )