from nlp.ioc_extractor import extract_iocs
from fastapi import APIRouter, UploadFile, File
from app.services.detection_service import detect_security_incidents
from app.services.upload_service import (
    save_uploaded_file,
    read_log_file
)
from app.services.normalization_service import normalize_logs

from app.services.parser_service import parse_log_content

router = APIRouter(
    prefix="/upload",
    tags=["Log Upload"]
)


@router.post("/")
async def upload_log(file: UploadFile = File(...)):

    file_path = save_uploaded_file(file)

    content = read_log_file(file_path)

    iocs = extract_iocs(content)

    parse_result = parse_log_content(content)

    parsed_logs = parse_result["parsed_logs"]

    normalized_events = normalize_logs(
    parse_result["log_type"],
    parsed_logs
    )

    alerts = detect_security_incidents(
    normalized_events,
    iocs,
    )

    return {
        "filename": file.filename,
        "detected_log_type": parse_result["log_type"],
        "total_logs": len(parsed_logs),
        "failed_lines": parse_result["failed_lines"],
        "alerts": alerts,
        "normalized_events": normalized_events,
        "logs": parsed_logs
    }