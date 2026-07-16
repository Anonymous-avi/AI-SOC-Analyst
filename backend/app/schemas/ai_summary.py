from pydantic import BaseModel


class AISummaryRequest(BaseModel):
    alert_id: str


class AISummaryResponse(BaseModel):
    summary: str