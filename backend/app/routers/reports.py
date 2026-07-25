from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.dependencies.database import get_alert_repository
from app.repositories.alert_repository import AlertRepository
from app.schemas.security_alert import SecurityAlert
from app.services.ai_summary_service import generate_ai_summary
from app.services.pdf_report_service import generate_pdf_report


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


@router.get("/{alert_id}")
def download_report(
    alert_id: str,
    alert_repository: AlertRepository = Depends(
        get_alert_repository
    ),
):

    alert_document = alert_repository.find_by_alert_id(
        alert_id
    )

    if alert_document is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    # Remove MongoDB internal id
    alert_document.pop("_id", None)

    # Convert dictionary to SecurityAlert model
    alert = SecurityAlert.model_validate(
        alert_document
    )

    # Generate AI Summary
    ai_summary = generate_ai_summary(alert)

    # Generate PDF
    pdf_buffer = generate_pdf_report(
        alert_document,
        ai_summary,
    )

    filename = (
        f"Incident_Report_{alert.alert_id}.pdf"
    )

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            f'attachment; filename="{filename}"'
        },
    )