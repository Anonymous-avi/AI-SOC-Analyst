from fastapi import APIRouter, Depends, HTTPException

from app.dependencies.database import get_alert_repository
from app.repositories.alert_repository import AlertRepository
from app.schemas.ai_summary import (
    AISummaryRequest,
    AISummaryResponse,
)
from app.schemas.security_alert import SecurityAlert
from app.services.ai_summary_service import generate_ai_summary


router = APIRouter(
    prefix="/ai",
    tags=["AI Copilot"],
)


@router.post(
    "/summary",
    response_model=AISummaryResponse,
)
def generate_summary(
    request: AISummaryRequest,
    alert_repository: AlertRepository = Depends(
        get_alert_repository
    ),
):

    alert_document = alert_repository.find_by_alert_id(
        request.alert_id
    )

    if alert_document is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # MongoDB stores an internal _id which our Pydantic model
    # doesn't expect.
    alert_document.pop("_id", None)

    alert = SecurityAlert.model_validate(
        alert_document
    )

    summary = generate_ai_summary(alert)

    return AISummaryResponse(
        summary=summary,
    )