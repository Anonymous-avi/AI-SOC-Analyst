from app.schemas.security_event import SecurityEvent
from ml.anomaly_detection import (
    detect_brute_force,
    detect_path_traversal,
)


DETECTORS = [
    detect_brute_force,
    detect_path_traversal,
]


def detect_security_incidents(
    events: list[SecurityEvent]
):

    alerts = []

    for detector in DETECTORS:
        detector_alerts = detector(events)
        alerts.extend(detector_alerts)

    return alerts