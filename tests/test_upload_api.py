from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from app.dependencies.database import get_alert_repository
from main import app


client = TestClient(app)


def test_upload_persists_generated_alerts():

    mock_repository = MagicMock()

    app.dependency_overrides[get_alert_repository] = (
        lambda: mock_repository
    )

    ssh_log_content = (
    "Jul  8 10:15:20 server sshd[1234]: "
    "Failed password for admin from 192.168.1.10 port 22 ssh2\n"

    "Jul  8 10:15:30 server sshd[1234]: "
    "Failed password for admin from 192.168.1.10 port 22 ssh2\n"

    "Jul  8 10:15:40 server sshd[1234]: "
    "Failed password for admin from 192.168.1.10 port 22 ssh2\n"
    )

    try:
        response = client.post(
            "/upload/",
            files={
                "file": (
                    "test_ssh_logs.txt",
                    ssh_log_content,
                    "text/plain",
                )
            },
        )

        assert response.status_code == 200

        response_data = response.json()

        assert response_data["detected_log_type"] == "ssh"
        assert response_data["total_logs"] == 3

        assert len(response_data["alerts"]) == 1

        mock_repository.save.assert_called_once()

        saved_alert = (
            mock_repository.save.call_args.args[0]
        )

        assert saved_alert.attack_type == "Brute Force"
        assert saved_alert.attacker_ip == "192.168.1.10"

    finally:
        app.dependency_overrides.clear()