"""Skill publisher API — export AlertPromptTemplate rows as SKILL.md ZIPs.

Routes (all under prefix /api/admin from server.py):
  GET /skills/templates/{template_id}/export.zip  — single-template export
  GET /skills/templates/export.zip                — bulk export (all or ?ids=1,2,3)

Auth: system:settings  (same as all other admin_api routes).
"""

from __future__ import annotations

import io
import zipfile
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.skill_publisher_service import _slug, render_skill_md
from ion.storage.alert_prompt_repository import AlertPromptRepository
from ion.web.api import get_db_session

router = APIRouter(tags=["skill-publisher"])

_SETTINGS_PERM = "system:settings"


def _zip_bytes(folder_name: str, skill_md: str, extras: dict[str, bytes]) -> bytes:
    """Return in-memory ZIP bytes containing the skill folder."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{folder_name}/SKILL.md", skill_md.encode("utf-8"))
        for rel_path, data in extras.items():
            zf.writestr(f"{folder_name}/{rel_path}", data)
    return buf.getvalue()


@router.get("/skills/templates/{template_id}/export.zip")
def export_single_template(
    template_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission(_SETTINGS_PERM)),
) -> StreamingResponse:
    """Stream a ZIP containing the SKILL.md folder for one template."""
    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(template_id)
    if tmpl is None:
        raise HTTPException(status_code=404, detail="Template not found")
    if not tmpl.enabled:
        raise HTTPException(
            status_code=422, detail="Template is disabled; enable it before exporting"
        )

    skill_md, extras = render_skill_md(tmpl)
    folder_name = _slug(tmpl.name)
    data = _zip_bytes(folder_name, skill_md, extras)

    filename = f"{folder_name}.zip"
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/skills/templates/export.zip")
def export_bulk_templates(
    ids: Optional[str] = Query(
        default=None,
        description="Comma-separated template IDs to export. Omit for all enabled templates.",
    ),
    session: Session = Depends(get_db_session),
    _user: User = Depends(require_permission(_SETTINGS_PERM)),
) -> StreamingResponse:
    """Stream a ZIP with one folder per template plus a MANIFEST.txt.

    Skips disabled / inactive templates. If ``ids`` is provided only those
    templates (that are also enabled) are included.
    """
    repo = AlertPromptRepository(session)

    if ids is not None:
        try:
            id_list: List[int] = [int(x.strip()) for x in ids.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=422, detail="ids must be comma-separated integers")
        templates = [
            t for t in (repo.get_by_id(i) for i in id_list)
            if t is not None and t.enabled
        ]
    else:
        templates = repo.list_all(enabled_only=True)

    if not templates:
        raise HTTPException(status_code=404, detail="No enabled templates found to export")

    buf = io.BytesIO()
    exported_ids: List[int] = []

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for tmpl in templates:
            skill_md, extras = render_skill_md(tmpl)
            folder_name = _slug(tmpl.name)
            zf.writestr(f"{folder_name}/SKILL.md", skill_md.encode("utf-8"))
            for rel_path, data in extras.items():
                zf.writestr(f"{folder_name}/{rel_path}", data)
            exported_ids.append(tmpl.id)

        manifest = (
            "# ION Skill Export Manifest\n"
            f"# Exported template IDs: {', '.join(str(i) for i in exported_ids)}\n"
            + "\n".join(str(i) for i in exported_ids)
            + "\n"
        )
        zf.writestr("MANIFEST.txt", manifest.encode("utf-8"))

    data = buf.getvalue()
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="ion-skills-export.zip"'},
    )
