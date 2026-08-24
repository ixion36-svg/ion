"""PCAP file upload and analysis API."""

import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ion.auth.dependencies import require_permission
from ion.core.safe_errors import safe_error
from ion.models.user import User

# Shared with the Arkime auto-case pipeline (pcap_analysis_service) — the
# canonical implementations live in services.pcap_enrichment_service.
from ion.services.pcap_enrichment_service import (
    enrich_pcap_observables as _enrich_pcap_observables,
)
from ion.services.pcap_enrichment_service import (
    ti_findings as _ti_findings,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pcap"])

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.post("/analyze")
async def analyze_pcap(
    file: UploadFile = File(...),
    user: User = Depends(require_permission("alert:read")),
):
    """Upload and analyze a PCAP file, then enrich external IPs/domains."""
    # Validate extension
    filename = file.filename or "upload.pcap"
    ext = ""
    for e in ALLOWED_EXTENSIONS:
        if filename.lower().endswith(e):
            ext = e
            break
    if not ext:
        raise HTTPException(400, f"Unsupported file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    # Read file content.
    # was `await file.read()` followed by a post-hoc size
    # check, which buffered the entire upload (potentially multi-GB)
    # into memory before the 100 MB cap was evaluated. Stream-read
    # with a running cap so oversize uploads are rejected before the
    # allocation completes — returns 413 instead of 400 to match
    # standard semantics.
    from ion.core.uploads import read_upload_capped
    content = await read_upload_capped(file, MAX_FILE_SIZE)
    if len(content) == 0:
        raise HTTPException(400, "Empty file")

    # Parse
    try:
        from ion.services.pcap_service import _is_private, parse_pcap
        result = parse_pcap(content, filename)
    except ValueError as e:
        # Validation errors carry user-meaningful messages — return a class label.
        raise HTTPException(400, f"Invalid PCAP: {safe_error(e, 'pcap_parse')}")
    except Exception as e:
        raise HTTPException(500, f"Analysis failed: {safe_error(e, 'pcap_parse')}")

    response = result.to_dict()

    # Extract and enrich observables (non-blocking — failures don't break the response)
    try:
        enrichments = await _enrich_pcap_observables(result, _is_private)
        if enrichments:
            response["threat_intel"] = enrichments
            # Escalate: any pcap observable that threat intel flags as known-bad
            # becomes a finding, and the verdict is recomputed to reflect it.
            _apply_ti_findings(response, enrichments)
    except Exception as e:
        response["threat_intel"] = {"error": safe_error(e, "pcap_enrich"), "observables": []}

    return response


def _apply_ti_findings(response: dict, enrichments: dict) -> None:
    """Append TI-match findings and recompute the verdict to fold in IOC hits."""
    ti = _ti_findings(enrichments)
    if not ti:
        return
    response["findings"] = (response.get("findings") or []) + ti
    try:
        from ion.services.pcap_service import Finding, _attach_mitre, _build_mitre_summary, _compute_verdict
        fobjs = [Finding(category=f["category"], severity=f["severity"],
                         title=f.get("title", ""), detail=f.get("detail", ""),
                         mitre=f.get("mitre") or []) for f in response["findings"]]
        _attach_mitre(fobjs)
        response["verdict"] = _compute_verdict(fobjs)
        response["mitre_techniques"] = _build_mitre_summary(fobjs)
    except Exception:
        pass
