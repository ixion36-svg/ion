"""CyAB Onboarding Studio API (v0.12.0+).

Mounted at ``/api/cyab/studio`` (see ``server.py``). Decorators below
use relative paths per the FastAPI prefix convention.

Routes:

- ``GET    /pillars``                                    list pillars
- ``GET    /pillars/{pillar_id}/subprofiles``            list sub-profiles in a pillar
- ``GET    /subprofiles/{sub_id}``                       full catalogue for one sub-profile
- ``PATCH  /subprofiles/{sub_id}``                       operator overlay (flips is_custom)
- ``GET    /subprofiles/{sub_id}/use-cases/{uc_id}``     single use case
- ``POST   /use-cases/{uc_id}/tide-stub``                generate a TIDE rule stub
- ``GET    /systems``                                    list CyAB systems for the dropdown (v0.12.1)
- ``GET    /systems/{sys_id}/answers``                   merged intake answers (v0.12.1)
- ``POST   /systems/{sys_id}/answers``                   merge new intake answers (v0.12.1)
- ``GET    /systems/{sys_id}/coverage``                  per-sub-profile rollup
- ``GET    /systems/{sys_id}/onboarding-pack``           render Onboarding Pack PDF
- ``POST   /systems/{sys_id}/onboarding-pack/sign``      mark approved + persist sign-off
"""

from __future__ import annotations

import html as html_mod
import json
import logging
import re
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.cyab import (
    CyabAssessment,
    CyabDataSource,
    CyabSystem,
    CyabSystemAssessment,
)
from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.models.user import User
from ion.services import cyab_doc_checklist_service as _doc_svc
from ion.services.cyab_subprofile_service import (
    get_subprofile_full,
    get_use_case,
    list_pillars,
    list_subprofiles_for_pillar,
    patch_subprofile,
    system_coverage,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Pydantic
# ---------------------------------------------------------------------------

class SubprofilePatch(BaseModel):
    label: Optional[str] = None
    icon: Optional[str] = None
    description: Optional[str] = None
    ecs_anchors: Optional[List[str]] = None
    expected_feeds: Optional[List[str]] = None
    catalogue: Optional[Dict[str, Any]] = None


class TideStubRequest(BaseModel):
    subprofile_id: str


class SignOffRequest(BaseModel):
    sign_dept_name: Optional[str] = None
    sign_soc_name: Optional[str] = None
    containment_authority: Optional[str] = None


class AnswersPatch(BaseModel):
    answers: Dict[str, Any]
    subprofile_id: Optional[str] = None  # for telemetry / future use; not required


class UseCaseStatusPatch(BaseModel):
    """Per-data-source use-case status patch (v0.12.3).

    The JSON column ``cyab_data_sources.use_case_status`` is reframed
    from free-text into a JSON map keyed by use-case id with one of the
    four values: shipped / partial / gap / n/a. Sending None for a key
    clears it.
    """
    statuses: Dict[str, Optional[str]]


_VALID_UC_STATUSES = {"shipped", "partial", "gap", "n/a"}


class SubprofileCreate(BaseModel):
    """Operator-authored sub-profile (v0.12.4).

    The new row is created with ``is_custom=true`` so the seeder won't
    overwrite it. Catalogue starts empty; operators populate via the
    add-question / add-use-case affordances.
    """
    id: str
    pillar_id: str
    label: str
    icon: Optional[str] = "cpu"
    description: Optional[str] = None
    ecs_anchors: Optional[List[str]] = None
    expected_feeds: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Catalogue read
# ---------------------------------------------------------------------------

@router.get("/pillars")
def get_pillars(session: Session = Depends(get_db_session)):
    """Return the 6 pillars ordered by priority."""
    return {"pillars": list_pillars(session)}


@router.get("/pillars/{pillar_id}/subprofiles")
def get_subprofiles_in_pillar(
    pillar_id: str,
    session: Session = Depends(get_db_session),
):
    """Return summary entries for sub-profiles in one pillar."""
    pillar = session.get(CyabPillar, pillar_id)
    if pillar is None:
        raise HTTPException(status_code=404, detail="Unknown pillar")
    return {
        "pillar": {
            "id": pillar.id,
            "label": pillar.label,
            "icon": pillar.icon,
            "priority": pillar.priority,
            "description": pillar.description,
        },
        "subprofiles": list_subprofiles_for_pillar(session, pillar_id),
    }


@router.get("/subprofiles/{sub_id}")
def get_subprofile(
    sub_id: str,
    session: Session = Depends(get_db_session),
):
    """Return one sub-profile with full catalogue."""
    full = get_subprofile_full(session, sub_id)
    if full is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    return full


@router.post(
    "/subprofiles",
    dependencies=[Depends(require_permission("case:update"))],
)
def create_subprofile_route(
    body: SubprofileCreate,
    session: Session = Depends(get_db_session),
):
    """Create a new operator-authored sub-profile under a pillar.

    Validates id is unique + pillar exists. Catalogue starts empty;
    operators populate via the add-question / add-use-case routes
    (PATCH /subprofiles/{id}).
    """
    # Validate id shape — keep it filesystem-safe + URL-safe
    if not re.fullmatch(r"[a-z0-9_]{2,64}", body.id):
        raise HTTPException(
            status_code=400,
            detail="id must be 2–64 chars of [a-z0-9_]",
        )
    pillar = session.get(CyabPillar, body.pillar_id)
    if pillar is None:
        raise HTTPException(status_code=404, detail="Unknown pillar")
    existing = session.get(CyabSubProfile, body.id)
    if existing is not None:
        raise HTTPException(status_code=409, detail="Sub-profile id already exists")
    row = CyabSubProfile(
        id=body.id,
        pillar_id=body.pillar_id,
        label=body.label,
        icon=body.icon or "cpu",
        ecs_anchors=json.dumps(body.ecs_anchors or []),
        expected_feeds=json.dumps(body.expected_feeds or []),
        catalogue_json=json.dumps({
            "intake_questions": [],
            "recommended_tasks": [],
            "detection_use_cases": [],
            "audit_use_cases": [],
            "references": [],
        }, sort_keys=True),
        catalogue_version=1,
        is_custom=True,
        description=body.description,
    )
    session.add(row)
    session.commit()
    return _row_to_full_dict_for_api(row)


def _row_to_full_dict_for_api(row: CyabSubProfile) -> Dict[str, Any]:
    """Local mirror of svc._row_to_full_dict to avoid private-import."""
    return {
        "id": row.id,
        "pillar_id": row.pillar_id,
        "label": row.label,
        "icon": row.icon,
        "description": row.description,
        "ecs_anchors": json.loads(row.ecs_anchors or "[]"),
        "expected_feeds": json.loads(row.expected_feeds or "[]"),
        "catalogue": json.loads(row.catalogue_json or "{}"),
        "catalogue_version": row.catalogue_version,
        "is_custom": row.is_custom,
    }


@router.patch(
    "/subprofiles/{sub_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_subprofile_route(
    sub_id: str,
    patch: SubprofilePatch,
    session: Session = Depends(get_db_session),
):
    """Operator overlay — flips is_custom=True; the seeder skips the row thereafter."""
    payload = patch.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=400, detail="Empty patch")
    updated = patch_subprofile(session, sub_id, payload)
    if updated is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    return updated


@router.get("/subprofiles/{sub_id}/use-cases/{uc_id}")
def get_use_case_route(
    sub_id: str,
    uc_id: str,
    session: Session = Depends(get_db_session),
):
    """Drawer fetch for one use case (detection or audit)."""
    uc = get_use_case(session, sub_id, uc_id)
    if uc is None:
        raise HTTPException(status_code=404, detail="Unknown use case")
    return uc


# ---------------------------------------------------------------------------
# TIDE stub generation
# ---------------------------------------------------------------------------

@router.post(
    "/use-cases/{uc_id}/tide-stub",
    dependencies=[Depends(require_permission("case:update"))],
)
def generate_tide_stub(
    uc_id: str,
    body: TideStubRequest,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Create a TIDE rule stub from a catalogue use case.

    Resolves the use case via (subprofile_id, uc_id), maps the
    catalogue fields to a TIDE rule shape, calls the TIDE service,
    and on success appends the new rule id into the use case's
    ``tide_rule_ids`` list (operator overlay — flips is_custom=True).
    """
    uc = get_use_case(session, body.subprofile_id, uc_id)
    if uc is None:
        raise HTTPException(status_code=404, detail="Unknown use case")

    # Best-effort: find the TIDE service. If TIDE isn't configured,
    # return 503 so the UI can show a helpful message.
    try:
        from ion.services.tide_service import get_tide_service
        tide = get_tide_service()
        if tide is None or not getattr(tide, "is_configured", lambda: False)():
            raise HTTPException(status_code=503, detail="TIDE not configured")
    except ImportError:
        raise HTTPException(status_code=503, detail="TIDE service unavailable")

    severity_map = {
        "critical": "Critical", "high": "High",
        "medium": "Medium", "low": "Low",
    }
    rule_payload = {
        "name": uc.get("title", uc_id),
        "description": uc.get("description") or uc.get("summary") or "",
        "severity": severity_map.get(uc.get("risk", "medium"), "Medium"),
        "mitre_techniques": list(uc.get("mitre_ids") or []),
        "language": uc.get("logic_lang", "esql"),
        "rule_body": uc.get("logic_snippet", ""),
        "tags": ["cyab-onboarding-studio", f"subprofile:{body.subprofile_id}"],
        "source": "ion.cyab.onboarding_studio",
    }

    try:
        # The TIDE service exposes a generic create_rule method on most
        # clients. If the running TIDE version lacks it, surface 501.
        create_fn = getattr(tide, "create_rule_stub", None) or getattr(
            tide, "create_rule", None
        )
        if create_fn is None:
            raise HTTPException(
                status_code=501,
                detail="TIDE client lacks create_rule support",
            )
        new_rule_id = create_fn(rule_payload)
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("TIDE stub generation failed: %s", e)
        raise HTTPException(status_code=502, detail=f"TIDE create failed: {e}")

    # Persist the new id back onto the catalogue via patch_subprofile
    full = get_subprofile_full(session, body.subprofile_id)
    if full is None:
        raise HTTPException(status_code=404, detail="Unknown sub-profile")
    cat = full.get("catalogue") or {}
    for kind in ("detection_use_cases", "audit_use_cases"):
        for entry in cat.get(kind) or []:
            if entry.get("id") == uc_id:
                ids = list(entry.get("tide_rule_ids") or [])
                ids.append(new_rule_id)
                entry["tide_rule_ids"] = ids
                break
    patch_subprofile(session, body.subprofile_id, {"catalogue": cat})

    return {"tide_rule_id": new_rule_id, "use_case_id": uc_id}


# ---------------------------------------------------------------------------
# System list (dropdown) + per-system intake answers
# ---------------------------------------------------------------------------
#
# Answers are persisted into a marker-tagged CyabSystemAssessment row
# (notes='STUDIO_AUTOSAVE'). One such row per system; auto-save merges
# into its responses_json. The legacy 6-step wizard continues to create
# its own immutable rows separately — this Studio row is independent
# and explicitly tagged.

_STUDIO_NOTES_MARKER = "STUDIO_AUTOSAVE"


def _get_or_create_studio_assessment(
    session: Session, sys_id: int, user_id: Optional[int],
) -> CyabSystemAssessment:
    row = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes == _STUDIO_NOTES_MARKER)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    if row is not None:
        return row
    from ion.services.cyab_assessment_questions import SCHEMA_VERSION
    row = CyabSystemAssessment(
        system_id=sys_id,
        schema_version=SCHEMA_VERSION,
        submitted_by=user_id,
        responses_json="{}",
        notes=_STUDIO_NOTES_MARKER,
    )
    session.add(row)
    session.flush()
    return row


@router.get("/systems")
def list_studio_systems(session: Session = Depends(get_db_session)):
    """Lightweight system list for the Studio header selector."""
    rows = session.scalars(
        select(CyabSystem).order_by(CyabSystem.department.asc(), CyabSystem.name.asc())
    ).all()
    return {
        "systems": [
            {
                "id": r.id,
                "name": r.name,
                "department": r.department,
                "status": r.status,
                "readiness_score": r.readiness_score,
            }
            for r in rows
        ]
    }


@router.get("/systems/{sys_id}/answers")
def get_system_answers(
    sys_id: int,
    session: Session = Depends(get_db_session),
):
    """Return the merged answers blob for the system.

    Merges the studio autosave row over the legacy wizard's most-recent
    row so the operator sees both — studio edits override wizard
    captures for shared keys.
    """
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    legacy = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes != _STUDIO_NOTES_MARKER)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    studio = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys_id)
        .where(CyabSystemAssessment.notes == _STUDIO_NOTES_MARKER)
        .limit(1)
    ).first()
    merged: Dict[str, Any] = {}
    for src in (legacy, studio):
        if src and src.responses_json:
            try:
                merged.update(json.loads(src.responses_json) or {})
            except json.JSONDecodeError:
                pass
    return {
        "system_id": sys_id,
        "answers": merged,
        "studio_assessment_id": studio.id if studio else None,
    }


@router.post(
    "/systems/{sys_id}/answers",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_system_answers(
    sys_id: int,
    body: AnswersPatch,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Merge intake answers into the studio's autosave assessment.

    Only the keys present in the request body are written; existing
    keys not mentioned stay put. To clear a key, send it with value
    None — the merge respects None as 'unset'.
    """
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    row = _get_or_create_studio_assessment(
        session, sys_id, current_user.id if current_user else None,
    )
    try:
        existing = json.loads(row.responses_json or "{}")
    except json.JSONDecodeError:
        existing = {}
    for k, v in (body.answers or {}).items():
        if v is None:
            existing.pop(k, None)
        else:
            existing[k] = v
    row.responses_json = json.dumps(existing, default=str, sort_keys=True)
    row.submitted_at = datetime.utcnow()
    if current_user is not None:
        row.submitted_by = current_user.id
    session.commit()
    return {
        "system_id": sys_id,
        "studio_assessment_id": row.id,
        "answer_count": len(existing),
    }


# ---------------------------------------------------------------------------
# Per-data-source use-case status (v0.12.3)
# ---------------------------------------------------------------------------

@router.get("/systems/{sys_id}/data-sources")
def list_data_sources_for_system(
    sys_id: int,
    subprofile_id: Optional[str] = None,
    session: Session = Depends(get_db_session),
):
    """List data sources for a system, optionally filtered by sub-profile.

    Used by the Studio to resolve which data source's use_case_status
    column to read/write for the current (system, sub-profile) context.
    """
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    q = select(CyabDataSource).where(CyabDataSource.system_id == sys_id)
    if subprofile_id:
        q = q.where(CyabDataSource.subprofile_id == subprofile_id)
    q = q.order_by(CyabDataSource.name.asc())
    rows = session.scalars(q).all()
    return {
        "system_id": sys_id,
        "subprofile_id": subprofile_id,
        "data_sources": [
            {
                "id": r.id,
                "name": r.name,
                "data_source_type": r.data_source_type,
                "subprofile_id": r.subprofile_id,
                "data_namespace": r.data_namespace,
            }
            for r in rows
        ],
    }


@router.get("/data-sources/{ds_id}/use-case-status")
def get_data_source_uc_status(
    ds_id: int,
    session: Session = Depends(get_db_session),
):
    """Return the parsed use_case_status JSON for one data source.

    The column may carry pre-v0.12.3 free-text — return ``{}`` in that
    case rather than raising, and surface the raw text under
    ``legacy_text`` so the UI can flag it for migration.
    """
    ds = session.get(CyabDataSource, ds_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Unknown data source")
    raw = ds.use_case_status
    parsed: Dict[str, str] = {}
    legacy: Optional[str] = None
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                parsed = {k: v for k, v in obj.items() if v in _VALID_UC_STATUSES}
            else:
                legacy = raw
        except json.JSONDecodeError:
            legacy = raw
    return {
        "data_source_id": ds_id,
        "subprofile_id": ds.subprofile_id,
        "statuses": parsed,
        "legacy_text": legacy,
    }


@router.post(
    "/data-sources/{ds_id}/use-case-status",
    dependencies=[Depends(require_permission("case:update"))],
)
def patch_data_source_uc_status(
    ds_id: int,
    body: UseCaseStatusPatch,
    session: Session = Depends(get_db_session),
):
    """Merge use-case statuses into a data source.

    Sending value None for a key removes it. Unknown status values
    (anything outside shipped/partial/gap/n/a) are rejected with 400.
    """
    ds = session.get(CyabDataSource, ds_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Unknown data source")
    raw = ds.use_case_status
    existing: Dict[str, str] = {}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                existing = {k: v for k, v in obj.items() if v in _VALID_UC_STATUSES}
        except json.JSONDecodeError:
            pass  # legacy free-text: starting fresh
    for k, v in (body.statuses or {}).items():
        if v is None:
            existing.pop(k, None)
            continue
        if v not in _VALID_UC_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{v}' for {k}; must be one of {sorted(_VALID_UC_STATUSES)}",
            )
        existing[k] = v
    ds.use_case_status = json.dumps(existing, sort_keys=True)
    session.commit()
    return {
        "data_source_id": ds_id,
        "statuses": existing,
        "count": len(existing),
    }


# ---------------------------------------------------------------------------
# Per-system coverage
# ---------------------------------------------------------------------------

@router.get("/systems/{sys_id}/coverage")
def get_system_coverage(
    sys_id: int,
    session: Session = Depends(get_db_session),
):
    """Per-sub-profile rollup of intake / detection / audit coverage."""
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    return system_coverage(session, sys_id)


# ---------------------------------------------------------------------------
# Onboarding Pack PDF
# ---------------------------------------------------------------------------

def _h(v: Any) -> str:
    """HTML-escape any value, including None / ints."""
    return html_mod.escape("" if v is None else str(v), quote=True)


def _render_onboarding_pack_html(
    session: Session, sys: CyabSystem,
) -> str:
    """Build the Onboarding Pack HTML body.

    Sections (per dossier §13):
      1. Cover (system + governance)
      2. Strategic context (latest org assessment)
      3. System scope (data sources)
      4. Per-sub-profile readiness (intake + detection + audit)
      5. Containment authority
      6. Sign-off block
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Latest assessments
    org_asmt = session.scalars(
        select(CyabAssessment).order_by(CyabAssessment.submitted_at.desc()).limit(1)
    ).first()
    sys_asmt = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == sys.id)
        .order_by(CyabSystemAssessment.submitted_at.desc()).limit(1)
    ).first()

    # Data sources
    sources = session.scalars(
        select(CyabDataSource).where(CyabDataSource.system_id == sys.id)
    ).all()

    coverage = system_coverage(session, sys.id)

    # ---- Cover -----------------------------------------------------------
    cover = f"""
    <h1 style="border:none;margin:0;padding:0;">CyAB Onboarding Pack</h1>
    <p class="pdf-subtitle">{_h(sys.name)} &bull; {_h(sys.department)} &bull; {now} &bull; ION</p>
    <table class="pdf-meta">
        <tr><td>System</td><td><strong>{_h(sys.name)}</strong></td></tr>
        <tr><td>Department</td><td>{_h(sys.department)}</td></tr>
        <tr><td>Business unit</td><td>{_h(sys.business_unit)}</td></tr>
        <tr><td>Data classification</td><td>{_h(sys.data_classification)}</td></tr>
        <tr><td>Status</td><td>{_h(sys.status)}</td></tr>
        <tr><td>Reference</td><td>{_h(sys.reference)}</td></tr>
        <tr><td>Version</td><td>{_h(sys.version)}</td></tr>
        <tr><td>Readiness score</td><td>{_h(sys.readiness_score)}%</td></tr>
        <tr><td>Risk rating</td><td>{_h(sys.risk_rating)}</td></tr>
    </table>
    """

    # ---- Strategic context ----------------------------------------------
    context = "<h2>Strategic context</h2>"
    if org_asmt and org_asmt.computed_profile_json:
        try:
            profile = json.loads(org_asmt.computed_profile_json)
        except json.JSONDecodeError:
            profile = {}
        rows = "".join(
            f"<tr><td>{_h(k)}</td><td>{_h(v)}</td></tr>"
            for k, v in profile.items()
        )
        context += f"<table class='pdf-meta'>{rows}</table>"
    else:
        context += "<p><em>No org-wide assessment captured yet.</em></p>"

    # ---- System scope ----------------------------------------------------
    scope = "<h2>System scope &mdash; data sources</h2><table>"
    scope += (
        "<thead><tr><th>Name</th><th>Type</th><th>Sub-profile</th>"
        "<th>SAL</th><th>Retention</th><th>P1 SLA</th><th>Namespace</th></tr></thead><tbody>"
    )
    for ds in sources:
        scope += (
            f"<tr><td>{_h(ds.name)}</td><td>{_h(ds.data_source_type)}</td>"
            f"<td>{_h(ds.subprofile_id) or '<em>not set</em>'}</td>"
            f"<td>{_h(ds.sal_tier)}</td><td>{_h(ds.retention)}</td>"
            f"<td>{_h(ds.p1_sla)}</td><td>{_h(ds.data_namespace)}</td></tr>"
        )
    scope += "</tbody></table>"

    # ---- Per-sub-profile readiness --------------------------------------
    readiness_html = "<h2>Per-sub-profile readiness</h2>"
    answers: Dict[str, Any] = {}
    if sys_asmt and sys_asmt.responses_json:
        try:
            answers = json.loads(sys_asmt.responses_json)
        except json.JSONDecodeError:
            answers = {}
    if not coverage["subprofiles"]:
        readiness_html += "<p><em>No sub-profiles assigned to data sources yet.</em></p>"
    else:
        for sp in coverage["subprofiles"]:
            sub_full = get_subprofile_full(session, sp["subprofile_id"]) or {}
            cat = sub_full.get("catalogue") or {}
            readiness_html += (
                f"<h3>{_h(sp['label'])}</h3>"
                f"<p class='pdf-meta'>"
                f"Intake: {_h(sp['intake']['answered'])}/{_h(sp['intake']['total'])} "
                f"({_h(sp['intake']['pct'])}%) &bull; "
                f"Detection: {_h(sp['detection']['shipped'])}/{_h(sp['detection']['total'])} "
                f"({_h(sp['detection']['pct'])}%) &bull; "
                f"Audit: {_h(sp['audit']['shipped'])}/{_h(sp['audit']['total'])} "
                f"({_h(sp['audit']['pct'])}%)</p>"
            )

            # Intake answers table
            qs = cat.get("intake_questions") or []
            if qs:
                readiness_html += (
                    "<table><thead><tr><th>Question</th><th>Answer</th></tr></thead><tbody>"
                )
                for q in qs:
                    ans = answers.get(q["key"], "<em>not answered</em>")
                    readiness_html += (
                        f"<tr><td>{_h(q['text'])}</td><td>{_h(ans)}</td></tr>"
                    )
                readiness_html += "</tbody></table>"

            # Detection table
            dets = cat.get("detection_use_cases") or []
            if dets:
                readiness_html += (
                    "<h4>Detection coverage</h4>"
                    "<table><thead><tr><th>Use case</th><th>MITRE</th><th>Risk</th></tr></thead><tbody>"
                )
                for d in dets:
                    readiness_html += (
                        f"<tr><td>{_h(d.get('title'))}</td>"
                        f"<td>{_h(', '.join(d.get('mitre_ids') or []))}</td>"
                        f"<td>{_h(d.get('risk'))}</td></tr>"
                    )
                readiness_html += "</tbody></table>"

            # Audit table
            auds = cat.get("audit_use_cases") or []
            if auds:
                readiness_html += (
                    "<h4>Audit / compliance coverage</h4>"
                    "<table><thead><tr><th>Use case</th><th>Compliance</th><th>Risk</th></tr></thead><tbody>"
                )
                for a in auds:
                    readiness_html += (
                        f"<tr><td>{_h(a.get('title'))}</td>"
                        f"<td>{_h(', '.join(a.get('compliance_frames') or []))}</td>"
                        f"<td>{_h(a.get('risk'))}</td></tr>"
                    )
                readiness_html += "</tbody></table>"

    # ---- Containment authority ------------------------------------------
    containment = (
        f"<h2>Containment authority</h2><p>{_h(sys.containment_authority)}</p>"
        if sys.containment_authority else
        "<h2>Containment authority</h2><p><em>Not yet captured. Required before sign-off.</em></p>"
    )

    # ---- Documentation checklist (v0.18.0) -----------------------------
    try:
        doc_items = _doc_svc.list_for_system(session, sys.id)
        doc_cov = _doc_svc.coverage_summary(session, sys.id)
    except Exception:
        doc_items, doc_cov = [], None

    if doc_items:
        rows = []
        # Group rows by category for readable output.
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for it in doc_items:
            by_cat.setdefault(it.get("category", "design"), []).append(it)
        cat_labels = {
            "design":      "Architecture & Design",
            "operational": "Operational",
            "security":    "Security & Risk",
            "compliance":  "Compliance",
        }
        STATUS_LABEL = {
            "done":        "Done",
            "in_progress": "In progress",
            "missing":     "Missing",
            "na":          "N/A",
            "unknown":     "Unknown",
        }
        for cat in ["design", "operational", "security", "compliance"]:
            if cat not in by_cat:
                continue
            rows.append(f'<h3>{_h(cat_labels.get(cat, cat.title()))}</h3>')
            rows.append(
                "<table><tr>"
                "<th>Item</th><th>Status</th><th>Link</th><th>Notes</th>"
                "</tr>"
            )
            for it in by_cat[cat]:
                star = " ★" if it.get("is_critical") else ""
                status_lbl = STATUS_LABEL.get(it.get("status", "unknown"), it.get("status", ""))
                url = it.get("url") or ""
                url_cell = f'<a href="{_h(url)}">{_h(url)[:60]}</a>' if url else ""
                rows.append(
                    f"<tr><td>{_h(it.get('label', ''))}{star}</td>"
                    f"<td>{_h(status_lbl)}</td>"
                    f"<td>{url_cell}</td>"
                    f"<td>{_h((it.get('notes') or '')[:160])}</td></tr>"
                )
            rows.append("</table>")
        critical_block = ""
        if doc_cov and doc_cov.get("critical_missing"):
            missing = ", ".join(doc_cov["critical_missing"])
            critical_block = (
                f'<p style="color:#a40000;"><strong>Critical documents missing:</strong> '
                f'{_h(missing)}</p>'
            )
        doc_section = (
            "<h2>Documentation checklist</h2>"
            f'<p>★ marks critical items. Coverage: '
            f'<strong>{(doc_cov or {}).get("done", 0)}/{(doc_cov or {}).get("total", 0)}</strong> '
            f'done · {(doc_cov or {}).get("completion_pct", 0)}%.</p>'
            f"{critical_block}"
            + "".join(rows)
        )
    else:
        doc_section = ""

    # ---- Sign-off -------------------------------------------------------
    signoff = f"""
    <h2>Sign-off</h2>
    <table class="pdf-meta">
        <tr>
            <td>Department lead</td>
            <td>{_h(sys.sign_dept_name) or '<em>pending</em>'}</td>
            <td>{_h(sys.sign_dept_date) or ''}</td>
        </tr>
        <tr>
            <td>SOC lead</td>
            <td>{_h(sys.sign_soc_name) or '<em>pending</em>'}</td>
            <td>{_h(sys.sign_soc_date) or ''}</td>
        </tr>
    </table>
    """

    # ---- Wrap -----------------------------------------------------------
    style = """
    <style>
        @page { size: A4; margin: 18mm; }
        body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; color: #1a1a1a; font-size: 11pt; }
        h1 { font-size: 24pt; color: #0b3d91; }
        h2 { color: #0b3d91; border-bottom: 2px solid #0b3d91; padding-bottom: 4px; margin-top: 28px; }
        h3 { color: #1a4ea3; margin-top: 18px; }
        h4 { color: #444; margin-top: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 10pt; }
        th, td { border: 1px solid #d0d7de; padding: 6px 8px; text-align: left; vertical-align: top; }
        th { background: #f6f8fa; }
        table.pdf-meta { width: auto; }
        table.pdf-meta td { border: none; padding: 3px 12px 3px 0; }
        .pdf-subtitle { color: #555; font-size: 10pt; margin-top: 0; }
    </style>
    """
    return f"<!DOCTYPE html><html><head>{style}</head><body>{cover}{context}{scope}{readiness_html}{containment}{doc_section}{signoff}</body></html>"


@router.get(
    "/systems/{sys_id}/onboarding-pack",
    dependencies=[Depends(require_permission("case:read"))],
)
def render_onboarding_pack(
    sys_id: int,
    session: Session = Depends(get_db_session),
):
    """Render the bundled Onboarding Pack as a PDF (HTML fallback)."""
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")
    full_html = _render_onboarding_pack_html(session, sys)
    try:
        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", sys.name or "system").strip("_")[:60] or "system"
        filename = f"onboarding_pack_{slug}_{date.today().isoformat()}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        return Response(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )


@router.post(
    "/systems/{sys_id}/onboarding-pack/sign",
    dependencies=[Depends(require_permission("case:update"))],
)
def sign_onboarding_pack(
    sys_id: int,
    body: SignOffRequest,
    session: Session = Depends(get_db_session),
    current_user: Optional[User] = Depends(get_current_user),
):
    """Persist sign-off + containment authority into the system row."""
    sys = session.get(CyabSystem, sys_id)
    if sys is None:
        raise HTTPException(status_code=404, detail="Unknown system")

    today = date.today()
    if body.sign_dept_name is not None:
        sys.sign_dept_name = body.sign_dept_name
        sys.sign_dept_date = today
    if body.sign_soc_name is not None:
        sys.sign_soc_name = body.sign_soc_name
        sys.sign_soc_date = today
    if body.containment_authority is not None:
        sys.containment_authority = body.containment_authority

    if sys.sign_dept_name and sys.sign_soc_name:
        sys.status = "ACTIVE"
    session.commit()
    session.refresh(sys)

    # v0.18.0: include checklist coverage in the sign-off response so
    # the UI can show a "critical docs missing" warning banner. Soft
    # gate only — the sign-off proceeds either way; analyst sees the
    # gap and can override via a comment.
    try:
        coverage = _doc_svc.coverage_summary(session, sys.id)
    except Exception:
        coverage = None

    return {
        "system_id": sys.id,
        "status": sys.status,
        "sign_dept_name": sys.sign_dept_name,
        "sign_dept_date": sys.sign_dept_date.isoformat() if sys.sign_dept_date else None,
        "sign_soc_name": sys.sign_soc_name,
        "sign_soc_date": sys.sign_soc_date.isoformat() if sys.sign_soc_date else None,
        "containment_authority": sys.containment_authority,
        "doc_checklist_coverage": coverage,
    }


# ═══════════════════════════════════════════════════════════════════════
#   v0.18.0 — Documentation Checklist
# ═══════════════════════════════════════════════════════════════════════
#
# Per-system checklist of expected documentation artifacts (HLD, LLD,
# network topology, runbook, etc.). Lazy-seeded on first access via the
# service module's default catalogue. Three "critical" items (HLD,
# NETWORK_TOPOLOGY, OWNERS) drive a soft warning on Pack export.



class DocChecklistUpdate(BaseModel):
    status: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    label: Optional[str] = None        # only honoured for is_custom rows
    is_critical: Optional[bool] = None  # only honoured for is_custom rows


class DocChecklistAdd(BaseModel):
    kind: str
    label: str
    category: str = "design"
    is_critical: bool = False
    status: str = "unknown"
    url: Optional[str] = None
    notes: Optional[str] = None


@router.get("/systems/{sys_id}/checklist")
def get_doc_checklist(
    sys_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(get_current_user),
):
    """Return the documentation checklist for a system + a coverage rollup.
    Lazy-seeds the default catalogue on first call so existing systems
    don't need a migration."""
    sys_row = session.get(CyabSystem, sys_id)
    if not sys_row:
        raise HTTPException(status_code=404, detail=f"System {sys_id} not found")
    return {
        "system_id": sys_id,
        "items": _doc_svc.list_for_system(session, sys_id),
        "coverage": _doc_svc.coverage_summary(session, sys_id),
    }


@router.put(
    "/checklist/{item_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def update_doc_checklist_item(
    item_id: int,
    body: DocChecklistUpdate,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Update one checklist item. Default-catalogue rows can have
    status/url/notes edited; is_custom rows can also rename label /
    flip is_critical."""
    try:
        out = _doc_svc.update_item(
            session, item_id,
            status=body.status, url=body.url, notes=body.notes,
            label=body.label, is_critical=body.is_critical,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if out is None:
        raise HTTPException(status_code=404, detail=f"Checklist item {item_id} not found")
    return out


@router.post(
    "/systems/{sys_id}/checklist",
    dependencies=[Depends(require_permission("case:update"))],
)
def add_custom_doc_checklist_item(
    sys_id: int,
    body: DocChecklistAdd,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """Add a custom (operator-defined) checklist row beyond the default catalogue."""
    sys_row = session.get(CyabSystem, sys_id)
    if not sys_row:
        raise HTTPException(status_code=404, detail=f"System {sys_id} not found")
    try:
        out = _doc_svc.add_custom_item(
            session, sys_id,
            kind=body.kind, label=body.label, category=body.category,
            is_critical=body.is_critical, status=body.status,
            url=body.url, notes=body.notes,
            user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return out


@router.delete(
    "/checklist/{item_id}",
    dependencies=[Depends(require_permission("case:update"))],
)
def delete_custom_doc_checklist_item(
    item_id: int,
    session: Session = Depends(get_db_session),
    _user: User = Depends(get_current_user),
):
    """Remove a custom checklist row. Default rows return 400."""
    ok = _doc_svc.delete_custom_item(session, item_id)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail="Item not found, or it is a default-catalogue row (cannot be deleted).",
        )
    return {"ok": True, "deleted": item_id}
