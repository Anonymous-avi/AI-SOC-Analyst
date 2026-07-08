from collections import defaultdict
from app.schemas.security_event import SecurityEvent

def detect_brute_force(events: list[SecurityEvent]):

    failed_attempts = defaultdict(int)
    targeted_users = defaultdict(set)

    for event in events:

        if event.event_type != "authentication_failure":
            continue

        if event.source_ip is None:
            continue

        failed_attempts[event.source_ip] += 1

        if event.user:
            targeted_users[event.source_ip].add(event.user)

    alerts = []

    for source_ip, count in failed_attempts.items():

        if count >= 3:

            alerts.append({
                "attack_type": "Brute Force",
                "severity": "high",
                "attacker_ip": source_ip,
                "failed_attempts": count,
                "target_users": sorted(targeted_users[source_ip]),
                "recommendation": (
                    "Investigate the source IP, review authentication activity, "
                    "reset affected credentials if compromise is suspected, "
                    "and enforce MFA."
                )
            })

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