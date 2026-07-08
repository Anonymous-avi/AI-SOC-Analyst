from datetime import datetime, timezone
from app.schemas.security_event import (
    EventOutcome,
    SecurityEvent,
)
APACHE_TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_timestamp(timestamp: str) -> datetime:

    parsed_timestamp = datetime.strptime(
        timestamp,
        APACHE_TIMESTAMP_FORMAT
    )

    return parsed_timestamp.astimezone(
        timezone.utc
    ).replace(tzinfo=None)


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
        timestamp=parse_apache_timestamp(log["timestamp"]),
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