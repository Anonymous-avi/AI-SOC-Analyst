from fastapi import APIRouter, UploadFile, File
from app.services.detection_service import detect_security_incidents
from app.services.upload_service import (
    save_uploaded_file,
    read_log_file
)

from app.services.parser_service import parse_log_content

router = APIRouter(
    prefix="/upload",
    tags=["Log Upload"]
)


@router.post("/")
async def upload_log(file: UploadFile = File(...)):

    file_path = save_uploaded_file(file)

    content = read_log_file(file_path)

    parse_result = parse_log_content(content)

    parsed_logs = parse_result["parsed_logs"]

    alerts = detect_security_incidents(
    parse_result["log_type"],
    parsed_logs
    )

    return {
    "filename": file.filename,
    "detected_log_type": parse_result["log_type"],
    "total_logs": len(parsed_logs),
    "failed_lines": parse_result["failed_lines"],
    "alerts": alerts,
    "logs": parsed_logs
}