from app.schemas.security_event import SecurityEvent
from normalizers.normalizer_registry import get_normalizer


def normalize_logs(
    log_type: str,
    parsed_logs: list
) -> list[SecurityEvent]:

    normalizer = get_normalizer(log_type)

    if normalizer is None:
        return []

    normalized_events = []

    for log in parsed_logs:
        normalized_event = normalizer(log)
        normalized_events.append(normalized_event)

    return normalized_events