from datetime import datetime, timezone
from unittest.mock import MagicMock

from app.repositories.alert_repository import AlertRepository
from app.schemas.ioc import IOC
from app.services.mitre_service import get_mitre_mapping
from app.schemas.security_alert import (
    AlertSeverity,
    SecurityAlert,
)


def create_test_alert() -> SecurityAlert:
    return SecurityAlert(
        alert_id="ALT-TEST1234",
        title="Brute Force Detected",
        attack_type="Brute Force",
        severity=AlertSeverity.HIGH,
        confidence=0.95,
        attacker_ip="192.168.1.10",
        recommendation="Investigate the source IP.",
        mitre=get_mitre_mapping("Brute Force"),
        iocs=IOC(
            ips=["192.168.1.10"],
        ),
        threat_intelligence=[],
        threat_score=85,
        risk_level="High",
        created_at=datetime.now(timezone.utc),
    )


def test_save_alert():

    mock_database = MagicMock()
    mock_collection = MagicMock()

    mock_database.__getitem__.return_value = mock_collection

    repository = AlertRepository(mock_database)

    alert = create_test_alert()

    mock_collection.insert_one.return_value.inserted_id = (
        "mongo-id-123"
    )

    inserted_id = repository.save(alert)

    assert inserted_id == "mongo-id-123"

    mock_database.__getitem__.assert_called_once_with(
        "alerts"
    )

    mock_collection.insert_one.assert_called_once()

    saved_document = (
        mock_collection.insert_one.call_args.args[0]
    )

    assert saved_document["alert_id"] == "ALT-TEST1234"
    assert saved_document["attack_type"] == "Brute Force"
    assert saved_document["severity"] == AlertSeverity.HIGH
    assert saved_document["threat_score"] == 85


def test_find_all_alerts():

    mock_database = MagicMock()
    mock_collection = MagicMock()

    mock_database.__getitem__.return_value = mock_collection

    repository = AlertRepository(mock_database)

    expected_alerts = [
        {
            "alert_id": "ALT-2",
            "created_at": datetime(
                2026,
                7,
                11,
                tzinfo=timezone.utc,
            ),
        },
        {
            "alert_id": "ALT-1",
            "created_at": datetime(
                2026,
                7,
                10,
                tzinfo=timezone.utc,
            ),
        },
    ]

    mock_cursor = MagicMock()

    mock_collection.find.return_value = mock_cursor
    mock_cursor.sort.return_value = mock_cursor
    mock_cursor.limit.return_value = expected_alerts

    results = repository.find_all(limit=50)

    assert results == expected_alerts

    mock_collection.find.assert_called_once_with({})

    mock_cursor.sort.assert_called_once_with(
        "created_at",
        -1,
    )

    mock_cursor.limit.assert_called_once_with(50)


def test_find_alert_by_alert_id():

    mock_database = MagicMock()
    mock_collection = MagicMock()

    mock_database.__getitem__.return_value = mock_collection

    repository = AlertRepository(mock_database)

    expected_alert = {
        "alert_id": "ALT-TEST1234",
        "attack_type": "Brute Force",
    }

    mock_collection.find_one.return_value = expected_alert

    result = repository.find_by_alert_id(
        "ALT-TEST1234"
    )

    assert result == expected_alert

    mock_collection.find_one.assert_called_once_with({
        "alert_id": "ALT-TEST1234"
    })


def test_find_alert_by_alert_id_returns_none():

    mock_database = MagicMock()
    mock_collection = MagicMock()

    mock_database.__getitem__.return_value = mock_collection

    repository = AlertRepository(mock_database)

    mock_collection.find_one.return_value = None

    result = repository.find_by_alert_id(
        "ALT-NOTFOUND"
    )

    assert result is None