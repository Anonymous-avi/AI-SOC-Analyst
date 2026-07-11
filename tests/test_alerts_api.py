from unittest.mock import MagicMock

from bson import ObjectId
from fastapi.testclient import TestClient

from app.dependencies.database import get_alert_repository
from main import app


client = TestClient(app)


def create_sample_alert_document():

    return {
        "_id": ObjectId(),
        "alert_id": "ALT-TEST1234",
        "title": "Brute Force Detected",
        "attack_type": "Brute Force",
        "severity": "HIGH",
        "confidence": 0.95,
        "attacker_ip": "192.168.1.10",
        "recommendation": "Investigate the source IP.",
        "mitre": {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "technique_id": "T1110",
        },
        "threat_score": 85,
        "risk_level": "High",
        "iocs": {
            "ips": ["192.168.1.10"],
            "domains": [],
            "urls": [],
            "cves": [],
            "hashes": [],
            "emails": [],
            "malware": [],
        },
        "threat_intelligence": [],
    }


def test_get_all_alerts():

    mock_repository = MagicMock()

    mock_repository.find_all.return_value = [
        create_sample_alert_document()
    ]

    app.dependency_overrides[get_alert_repository] = (
        lambda: mock_repository
    )

    try:
        response = client.get(
            "/alerts/",
            params={"limit": 50},
        )

        assert response.status_code == 200

        response_data = response.json()

        assert len(response_data) == 1

        alert = response_data[0]

        assert alert["alert_id"] == "ALT-TEST1234"
        assert alert["attack_type"] == "Brute Force"

        # Confirms ObjectId is JSON serializable.
        assert isinstance(alert["_id"], str)

        mock_repository.find_all.assert_called_once_with(
            limit=50
        )

    finally:
        app.dependency_overrides.clear()


def test_get_alert_by_alert_id():

    mock_repository = MagicMock()

    mock_repository.find_by_alert_id.return_value = (
        create_sample_alert_document()
    )

    app.dependency_overrides[get_alert_repository] = (
        lambda: mock_repository
    )

    try:
        response = client.get(
            "/alerts/ALT-TEST1234"
        )

        assert response.status_code == 200

        alert = response.json()

        assert alert["alert_id"] == "ALT-TEST1234"
        assert alert["attack_type"] == "Brute Force"

        assert isinstance(alert["_id"], str)

        mock_repository.find_by_alert_id.assert_called_once_with(
            "ALT-TEST1234"
        )

    finally:
        app.dependency_overrides.clear()


def test_get_alert_by_alert_id_returns_404():

    mock_repository = MagicMock()

    mock_repository.find_by_alert_id.return_value = None

    app.dependency_overrides[get_alert_repository] = (
        lambda: mock_repository
    )

    try:
        response = client.get(
            "/alerts/ALT-NOTFOUND"
        )

        assert response.status_code == 404

        assert response.json() == {
            "detail": "Alert not found"
        }

        mock_repository.find_by_alert_id.assert_called_once_with(
            "ALT-NOTFOUND"
        )

    finally:
        app.dependency_overrides.clear()