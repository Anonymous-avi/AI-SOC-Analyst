from ml.anomaly_detection import detect_brute_force


def detect_security_incidents(parsed_logs):

    alerts = detect_brute_force(parsed_logs)

    return alerts