from pymongo.collection import Collection
from pymongo.database import Database

from app.schemas.security_alert import SecurityAlert


class AlertRepository:

    def __init__(
        self,
        database: Database,
    ):
        self.collection: Collection = database["alerts"]

    def save(
        self,
        alert: SecurityAlert,
    ) -> str:

        document = alert.model_dump(
            mode="python"
        )

        result = self.collection.insert_one(
            document
        )

        return str(result.inserted_id)

    def find_all(
        self,
        limit: int = 100,
    ) -> list[dict]:

        cursor = (
            self.collection
            .find({})
            .sort("created_at", -1)
            .limit(limit)
        )

        return list(cursor)

    def find_by_alert_id(
        self,
        alert_id: str,
    ) -> dict | None:

        return self.collection.find_one({
            "alert_id": alert_id
        })