from app.core.database import get_database
from app.repositories.alert_repository import AlertRepository


def get_alert_repository() -> AlertRepository:
    database = get_database()

    return AlertRepository(database)