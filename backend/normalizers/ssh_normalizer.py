def normalize_ssh_event(log: dict):

    event = log["event"]

    if event == "Failed":
        event_type = "authentication_failure"
        outcome = "failure"

    elif event == "Accepted":
        event_type = "authentication_success"
        outcome = "success"

    else:
        event_type = "authentication_event"
        outcome = "unknown"

    return {
        "timestamp": log["timestamp"],
        "source_type": "ssh",
        "source_ip": log["ip_address"],
        "destination_ip": None,
        "hostname": log["hostname"],
        "service": log["service"],
        "event_type": event_type,
        "severity": "unknown",
        "user": log["username"],
        "action": "login",
        "outcome": outcome,
        "raw_event": log
    }