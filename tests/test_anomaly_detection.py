from datetime import datetime, timedelta, timezone

from app.schemas.security_event import EventOutcome, SecurityEvent
from ml.anomaly_detection import detect_anomalies


def build_event(
    *,
    timestamp: datetime,
    source_ip: str,
    source_type: str,
    event_type: str,
    service: str,
    outcome: EventOutcome,
    user: str | None = None,
    path: str = "/index.html",
    status_code: int = 200,
):
    return SecurityEvent(
        timestamp=timestamp,
        source_type=source_type,
        source_ip=source_ip,
        service=service,
        event_type=event_type,
        outcome=outcome,
        user=user,
        action="GET" if event_type == "http_request" else "login",
        raw_event={
            "path": path,
            "status_code": status_code,
            "port": 443,
        },
    )


def test_detect_anomalies_flags_clear_outlier():
    base_time = datetime(2026, 7, 8, 10, 15, tzinfo=timezone.utc)

    normal_events = [
        build_event(
            timestamp=base_time + timedelta(minutes=index),
            source_ip="192.168.1.10",
            source_type="apache",
            event_type="http_request",
            service="apache",
            outcome=EventOutcome.SUCCESS,
            user="web",
            path="/app/home",
            status_code=200,
        )
        for index in range(10)
    ]

    outlier = build_event(
        timestamp=base_time + timedelta(minutes=11),
        source_ip="203.0.113.99",
        source_type="apache",
        event_type="http_request",
        service="apache",
        outcome=EventOutcome.CLIENT_ERROR,
        user="unknown",
        path="/../../../../var/www/html/.env?cmd=powershell",
        status_code=500,
    )

    alerts = detect_anomalies(normal_events + [outlier])

    assert len(alerts) >= 1

    alert = alerts[0]

    assert alert.attack_type == "Anomaly Detection"
    assert alert.confidence >= 0.7
    assert alert.metadata["anomaly_confidence"] == alert.confidence
    assert "top_contributing_factors" in alert.metadata
    assert alert.evidence_events[0].source_ip == "203.0.113.99"


def test_detect_anomalies_stays_quiet_on_small_batches():
    events = [
        build_event(
            timestamp=datetime(2026, 7, 8, 10, 15, tzinfo=timezone.utc),
            source_ip="192.168.1.10",
            source_type="apache",
            event_type="http_request",
            service="apache",
            outcome=EventOutcome.SUCCESS,
        )
        for _ in range(3)
    ]

    assert detect_anomalies(events) == []