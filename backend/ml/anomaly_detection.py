from collections import defaultdict
from datetime import datetime, timedelta

from app.schemas.security_event import SecurityEvent


SSH_TIMESTAMP_FORMAT = "%b %d %H:%M:%S"


def parse_ssh_timestamp(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, SSH_TIMESTAMP_FORMAT)


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_seconds: int = 60
):
    failures_by_ip = defaultdict(list)

    for event in events:
        if event.event_type != "authentication_failure":
            continue

        if event.source_ip is None:
            continue

        event_time = parse_ssh_timestamp(event.timestamp)

        failures_by_ip[event.source_ip].append(
            (event_time, event)
        )

    alerts = []

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda item: item[0])

        window_start = 0

        for window_end in range(len(failures)):
            current_time = failures[window_end][0]

            while (
                current_time - failures[window_start][0]
                > timedelta(seconds=window_seconds)
            ):
                window_start += 1

            window_size = window_end - window_start + 1

            if window_size >= threshold:
                window_events = failures[
                    window_start:window_end + 1
                ]

                targeted_users = sorted({
                    event.user
                    for _, event in window_events
                    if event.user
                })

                start_time = window_events[0][0]
                end_time = window_events[-1][0]

                alerts.append({
                    "attack_type": "Brute Force",
                    "severity": "high",
                    "attacker_ip": source_ip,
                    "failed_attempts": window_size,
                    "target_users": targeted_users,
                    "window_start": start_time.isoformat(),
                    "window_end": end_time.isoformat(),
                    "window_seconds": (
                        end_time - start_time
                    ).total_seconds(),
                    "recommendation": (
                        "Investigate the source IP, review authentication "
                        "activity around the detection window, reset affected "
                        "credentials if compromise is suspected, and enforce MFA."
                    )
                })

                break

    return alerts
def detect_path_traversal(events: list[SecurityEvent]):

    suspicious_patterns = [
        "../",
        "..\\",
        "%2e%2e",
        "%252e%252e"
    ]

    alerts = []

    for event in events:

        if event.event_type != "http_request":
            continue

        path = event.raw_event.get("path")

        if not path:
            continue

        normalized_path = path.lower()

        matched_pattern = next(
            (
                pattern
                for pattern in suspicious_patterns
                if pattern in normalized_path
            ),
            None
        )

        if matched_pattern:

            alerts.append({
                "attack_type": "Path Traversal",
                "severity": "high",
                "attacker_ip": event.source_ip,
                "request_method": event.action,
                "requested_path": path,
                "status_code": event.raw_event.get("status_code"),
                "evidence": (
                    f"Suspicious path pattern detected: {matched_pattern}"
                ),
                "recommendation": (
                    "Investigate the source IP and affected endpoint, review "
                    "related web requests, validate and canonicalize paths, "
                    "and ensure the web server cannot access files outside "
                    "intended directories."
                )
            })

    return alerts