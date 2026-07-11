from fastapi import APIRouter, Depends, HTTPException, Query

from app.dependencies.database import get_alert_repository
from app.repositories.alert_repository import AlertRepository


router = APIRouter(
    prefix="/alerts",
    tags=["Security Alerts"],
)


def serialize_alert_document(document: dict) -> dict:

    serialized_document = document.copy()

    if "_id" in serialized_document:
        serialized_document["_id"] = str(
            serialized_document["_id"]
        )

    return serialized_document


@router.get("/")
def get_alerts(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    alert_repository: AlertRepository = Depends(
        get_alert_repository
    ),
):

    alerts = alert_repository.find_all(
        limit=limit
    )

    return [
        serialize_alert_document(alert)
        for alert in alerts
    ]


@router.get("/{alert_id}")
def get_alert_by_id(
    alert_id: str,
    alert_repository: AlertRepository = Depends(
        get_alert_repository
    ),
):

    alert = alert_repository.find_by_alert_id(
        alert_id
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return serialize_alert_document(alert)