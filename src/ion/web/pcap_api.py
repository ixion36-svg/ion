"""PCAP file upload and analysis API."""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File

from ion.auth.dependencies import require_permission
from ion.models.user import User

router = APIRouter(tags=["pcap"])

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    user: User = Depends(require_permission("alert:read")),
):
    """Upload and analyze a PCAP file."""
    # Validate extension
    filename = file.filename or "upload.pcap"
    ext = ""
    for e in ALLOWED_EXTENSIONS:
        if filename.lower().endswith(e):
            ext = e
            break
    if not ext:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Read file content
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(400, f"File too large. Maximum size: {MAX_FILE_SIZE // (1024 * 1024)} MB")
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Parse
    try:
        from ion.services.pcap_service import parse_pcap
        result = parse_pcap(content, filename)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {e}")

    return result.to_dict()
