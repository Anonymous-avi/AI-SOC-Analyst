from app.schemas.security_event import SecurityEvent
from app.services.alert_builder import build_security_alert

from ml.anomaly_detection import (
    detect_brute_force,
    detect_path_traversal,
)


DETECTORS = [
    detect_brute_force,
    detect_path_traversal,
]


def detect_security_incidents(
    events: list[SecurityEvent],
):
    security_alerts = []

    for detector in DETECTORS:
        detector_results = detector(events)

        for result in detector_results:
            alert = build_security_alert(
                detector_output=result,
            )

            security_alerts.append(alert)

    return security_alerts