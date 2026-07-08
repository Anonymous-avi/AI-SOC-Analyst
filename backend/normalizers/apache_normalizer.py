def normalize_apache_event(log: dict):

    status_code = log["status_code"]

    if 200 <= status_code < 300:
        outcome = "success"

    elif 400 <= status_code < 500:
        outcome = "client_error"

    elif 500 <= status_code < 600:
        outcome = "server_error"

    else:
        outcome = "unknown"

    return {
        "timestamp": log["timestamp"],
        "source_type": "apache",
        "source_ip": log["source_ip"],
        "destination_ip": None,
        "hostname": None,
        "service": log["service"],
        "event_type": "http_request",
        "severity": "unknown",
        "user": None,
        "action": log["method"],
        "outcome": outcome,
        "raw_event": log
    }