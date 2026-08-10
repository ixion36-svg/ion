"""KEV catalog endpoints.

Reads are open to any analyst (``alert:read``) — "is this CVE known-exploited"
is a triage question. The import is an administrative action (``system:settings``)
because it REPLACES security data for everyone, so it is gated, size-limited,
validated before anything is written, and audited with the resulting catalog
version.

There is deliberately no "refresh from CISA" endpoint. ION runs air-gapped; the
snapshot arrives in the image, and between releases an operator uploads a file
they fetched themselves.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services import kev_service
from ion.storage.auth_repository import AuditLogRepository
from ion.storage.database import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["kev"])

# A KEV catalog is ~1.5 MB. 12 MB leaves generous headroom for growth while
# still refusing an upload that is obviously not this file.
_MAX_IMPORT_BYTES = 12 * 1024 * 1024


@router.get("/kev/status", dependencies=[Depends(require_permission("alert:read"))])
def kev_status(session: Session = Depends(get_db_session)):
    """Catalog version, size and age.

    Age matters: "not in KEV" is only meaningful relative to a snapshot date.
    """
    return kev_service.status(session)


@router.get("/kev", dependencies=[Depends(require_permission("alert:read"))])
def kev_search(
    q: str = "",
    ransomware_only: bool = False,
    limit: int = 50,
    session: Session = Depends(get_db_session),
):
    rows = kev_service.search(session, q=q, ransomware_only=ransomware_only, limit=limit)
    return {
        "results": [r.to_dict() for r in rows],
        "count": len(rows),
        "status": kev_service.status(session),
    }


@router.get("/kev/{cve_id}", dependencies=[Depends(require_permission("alert:read"))])
def kev_lookup(cve_id: str, session: Session = Depends(get_db_session)):
    """Look up one CVE.

    A miss returns ``in_kev: false`` with the catalog version rather than a 404:
    "this CVE is not in the catalog I hold, and here is which catalog that is"
    is a real answer, and a 404 would read as "the endpoint is broken".
    """
    entry = kev_service.lookup(session, cve_id)
    st = kev_service.status(session)
    if entry is None:
        return {
            "cve_id": cve_id.strip().upper(),
            "in_kev": False,
            "catalog_version": st.get("catalog_version"),
            "age_days": st.get("age_days"),
        }
    return {"in_kev": True, **entry.to_dict(), "age_days": st.get("age_days")}


@router.post("/kev/import", dependencies=[Depends(require_permission("system:settings"))])
async def kev_import(
    file: UploadFile = File(...),
    current_user: User = Depends(require_permission("system:settings")),
    session: Session = Depends(get_db_session),
):
    """Replace the catalog from an operator-supplied KEV JSON file."""
    raw = await file.read()
    if len(raw) > _MAX_IMPORT_BYTES:
        raise HTTPException(status_code=400, detail="File too large for a KEV catalog")

    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="File is not valid UTF-8 JSON")

    # Validate and write in one call — parse_catalog raises before anything is
    # committed, so a malformed upload cannot leave a half-replaced catalog.
    try:
        result = kev_service.import_catalog(session, payload)
    except kev_service.KevImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        AuditLogRepository(session).create(
            action="kev_catalog_import",
            user_id=current_user.id,
            resource_type="kev_catalog",
            resource_id=None,
            details=(f"version={result['version']}; added={result['added']}; "
                     f"updated={result['updated']}; removed={result['removed']}"),
        )
        session.commit()
    except Exception:
        logger.exception("kev_catalog_import audit log write failed (non-fatal)")

    return {"message": f"KEV catalog {result['version']} imported", **result}
