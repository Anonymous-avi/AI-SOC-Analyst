from ml.anomaly_detection import (
    detect_brute_force,
    detect_path_traversal
)


DETECTOR_REGISTRY = {
    "ssh": [
        detect_brute_force
    ],
    "apache": [
        detect_path_traversal
    ]
}


def detect_security_incidents(log_type, parsed_logs):

    detectors = DETECTOR_REGISTRY.get(log_type, [])

    alerts = []

    for detector in detectors:
        detector_alerts = detector(parsed_logs)
        alerts.extend(detector_alerts)

    return alerts