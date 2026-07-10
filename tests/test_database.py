from unittest.mock import MagicMock, patch

from app.core.database import (
    check_database_connection,
    get_database,
)


def test_get_database_returns_configured_database():

    database = get_database()

    assert database.name == "ai_soc_analyst"


@patch("app.core.database.client")
def test_database_connection_success(mock_client):

    mock_client.admin.command.return_value = {
        "ok": 1
    }

    result = check_database_connection()

    assert result is True

    mock_client.admin.command.assert_called_once_with(
        "ping"
    )


@patch("app.core.database.client")
def test_database_connection_failure(mock_client):

    mock_client.admin.command.side_effect = Exception(
        "Database unavailable"
    )

    result = check_database_connection()

    assert result is False

    mock_client.admin.command.assert_called_once_with(
        "ping"
    )