from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.detection_result import DetectionResult
from app.schemas.security_alert import AlertSeverity
from app.schemas.security_event import SecurityEvent


def create_test_event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_type="test",
        source_ip="192.168.1.10",
        destination_ip=None,
        hostname=None,
        service="ssh",
        event_type="authentication_failure",
        user="admin",
        action=None,
        raw_event={
            "message": (
                "Failed password for admin "
                "from 192.168.1.10"
            )
        },
    )


def test_create_valid_detection_result():

    event = create_test_event()

    result = DetectionResult(
        attack_type="Brute Force",
        severity=AlertSeverity.HIGH,
        attacker_ip="192.168.1.10",
        confidence=0.95,
        recommendation="Investigate the source IP.",
        evidence_events=[event],
        metadata={
            "failed_attempts": 3,
            "target_users": ["admin"],
        },
    )

    assert result.attack_type == "Brute Force"
    assert result.severity == AlertSeverity.HIGH
    assert result.attacker_ip == "192.168.1.10"
    assert result.confidence == 0.95

    assert len(result.evidence_events) == 1
    assert result.evidence_events[0] == event

    assert result.metadata["failed_attempts"] == 3
    assert result.metadata["target_users"] == ["admin"]


def test_detection_result_uses_default_values():

    result = DetectionResult(
        attack_type="Unknown Detection",
        severity=AlertSeverity.LOW,
        recommendation="Review the event.",
    )

    assert result.confidence == 0.95
    assert result.attacker_ip is None
    assert result.evidence_events == []
    assert result.metadata == {}


def test_detection_result_rejects_invalid_confidence():

    with pytest.raises(ValidationError):
        DetectionResult(
            attack_type="Brute Force",
            severity=AlertSeverity.HIGH,
            confidence=1.50,
            recommendation="Investigate the source IP.",
        )


def test_detection_result_rejects_empty_attack_type():

    with pytest.raises(ValidationError):
        DetectionResult(
            attack_type="",
            severity=AlertSeverity.HIGH,
            recommendation="Investigate the event.",
        )


def test_detection_result_rejects_empty_recommendation():

    with pytest.raises(ValidationError):
        DetectionResult(
            attack_type="Brute Force",
            severity=AlertSeverity.HIGH,
            recommendation="",
        )