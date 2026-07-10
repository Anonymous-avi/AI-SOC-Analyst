from datetime import datetime, timezone

from app.schemas.security_event import (
    EventOutcome,
    SecurityEvent,
)


SSH_TIMESTAMP_FORMAT = "%Y %b %d %H:%M:%S"


def parse_ssh_timestamp(timestamp: str) -> datetime:

    current_year = datetime.now(timezone.utc).year

    timestamp_with_year = (
        f"{current_year} {timestamp}"
    )

    return datetime.strptime(
        timestamp_with_year,
        SSH_TIMESTAMP_FORMAT,
    ).replace(tzinfo=timezone.utc)


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
        timestamp=parse_ssh_timestamp(
            log["timestamp"]
        ),
        source_type="ssh",
        source_ip=log["ip_address"],
        destination_ip=None,
        hostname=log["hostname"],
        service=log["service"],
        event_type=event_type,
        user=log["username"],
        action="login",
        outcome=outcome,
        raw_event=log,
    )