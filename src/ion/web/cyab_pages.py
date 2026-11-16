"""CyAB pages and the forms they post.

Five places: the Board (/cyab), Systems (/cyab/systems, as a list or a
matrix), one System page with a tab per stage of onboarding, Onboard, and
History. Scoping (/cyab/scoping) stays public: it is the stakeholder-facing
"given your stack, here is the coverage you would get" questionnaire, and
converting it into a system goes through an authenticated route.

Every form posts through htmx (the CSRF token rides in a header) and the
handler answers with a 303 back to the page it came from, which htmx
follows and swaps in by #cyab-main. Errors come back the same way, as a
message on that page, so there is one rendering path for both.
"""

from __future__ import annotations

import csv
import io
import json
import math
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_page_permission, require_permission
from ion.models.cyab import CyabDataSource, CyabSystem
from ion.models.cyab_assurance import SIGNOFF_ROLES, CyabChecklistException
from ion.models.cyab_doc_checklist import ALL_STATUSES, CyabDocChecklistItem
from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile
from ion.models.user import User
from ion.services import cyab_assurance_service as assurance
from ion.services import cyab_doc_checklist_service as checklist
from ion.services import cyab_readiness_service as readiness
from ion.services import cyab_sal
from ion.services.cyab_assessment_service import load_answers, save_answers
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

router = APIRouter(tags=["cyab-pages"])

READ = "alert:read"
EDIT = "case:update"
# Signing, accepting a gap and removing a source carry more weight than an
# edit, so they need what closing a case needs.
APPROVE = "case:close"

PAGE_SIZE = 25
STALLED_DAYS = 14
EXPIRING_DAYS = 14
CLASSIFICATIONS = ("OFFICIAL", "OFFICIAL-SENSITIVE", "SECRET", "TOP SECRET")
TABS = (
    ("summary", "Summary"),
    ("profile", "Profile & intake"),
    ("sources", "Sources"),
    ("use-cases", "Use cases"),
    ("signoff", "Docs & sign-off"),
)
UC_STATUSES = ("shipped", "partial", "gap", "n/a")
VIEWS = {
    "all": "All",
    "mine": "Mine",
    "attention": "Needs attention",
    "stalled": f"Stalled {STALLED_DAYS}+ days",
    "review_due": "Review due",
    "expiring": "Exceptions expiring",
}


# ── helpers ───────────────────────────────────────────────────────────────


def _me(user: User) -> str:
    return (user.display_name or user.username or "").strip()


def _sal_change_refused(user: User, current: str, new: str) -> Optional[str]:
    """A lower SAL needs fewer documents and allows longer accepted gaps, so
    lowering one needs the same authority as accepting a gap."""
    lower = cyab_sal.LEVELS.index(new) < cyab_sal.LEVELS.index(cyab_sal.normalise(current))
    if lower and not user.has_permission(APPROVE):
        return f"Lowering a system's SAL needs the {APPROVE} permission"
    return None


def _set_sal(system: CyabSystem, level: str) -> None:
    system.sal_tier = level
    system.review_cadence_days = cyab_sal.REVIEW_DAYS[level]


def _is_mine(system: CyabSystem, user: User) -> bool:
    owner = (system.soc_analyst_owner or "").strip().lower()
    return bool(owner) and owner in {(user.display_name or "").lower(), (user.username or "").lower()}


def _back(path: str, msg: Optional[str] = None, err: Optional[str] = None) -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    sep = "&" if "?" in path else "?"
    return RedirectResponse(path + (sep + urlencode(params) if params else ""), status_code=303)


def _safe_back(value: str, default: str) -> str:
    """A same-site CyAB path from a form field, or the default."""
    value = (value or "").strip()
    if value.startswith("/cyab/") and not value.startswith("//") and "\\" not in value:
        return value.split("#", 1)[0]
    return default


def _flash(request: Request) -> dict:
    return {"flash_msg": request.query_params.get("msg") or "",
            "flash_err": request.query_params.get("err") or ""}


def _clean_url(value: str) -> Optional[str]:
    try:
        return checklist.clean_url(value)
    except ValueError:
        raise assurance.AssuranceError("Links must start with http:// or https://")


def _get_system(session: Session, system_id: int) -> CyabSystem:
    system = session.get(CyabSystem, system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return system


def _subprofile_index(session: Session) -> Dict[str, dict]:
    pillars = {p.id: p for p in session.scalars(select(CyabPillar))}
    out = {}
    for sp in session.scalars(select(CyabSubProfile)):
        pillar = pillars.get(sp.pillar_id)
        out[sp.id] = {
            "id": sp.id, "label": sp.label, "pillar_id": sp.pillar_id,
            "pillar": pillar.label if pillar else sp.pillar_id,
            "priority": pillar.priority if pillar else 99,
            "catalogue": readiness._catalogue(sp),
        }
    return out


def _grouped_subprofiles(index: Dict[str, dict]) -> List[dict]:
    groups: Dict[str, dict] = {}
    for sp in sorted(index.values(), key=lambda s: (s["priority"], s["pillar"], s["label"])):
        groups.setdefault(sp["pillar"], {"pillar": sp["pillar"], "items": []})["items"].append(sp)
    return list(groups.values())


def _expiring_system_ids(session: Session, today: date) -> set:
    return set(session.scalars(
        select(CyabChecklistException.system_id).where(
            CyabChecklistException.revoked_at.is_(None),
            CyabChecklistException.until >= today,
            CyabChecklistException.until <= today + timedelta(days=EXPIRING_DAYS),
        )
    ))


def _base(request: Request, user: User, section: str, title: str) -> dict:
    return {
        "request": request, "user": user, "section": section, "page_title": title,
        "can_edit": user.has_permission(EDIT), "can_approve": user.has_permission(APPROVE),
        "stage_labels": readiness.STAGE_LABELS, "sal_names": cyab_sal.NAMES,
        **_flash(request),
    }


# ── public scoping ────────────────────────────────────────────────────────


@router.get("/cyab/scoping", response_class=HTMLResponse)
async def cyab_scoping_page(request: Request):
    """Anonymous scoping questionnaire. No system is created here."""
    from ion.services import cyab_scoping_engine
    questions = cyab_scoping_engine.load_questions()
    initial = cyab_scoping_engine.score_answers({})
    return templates.TemplateResponse(
        request=request, name="cyab/scoping.html",
        context={"questions": questions, "initial_scores": initial},
    )


# ── board ─────────────────────────────────────────────────────────────────


@router.get("/cyab", response_class=HTMLResponse)
def cyab_board(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    today = date.today()
    systems = list(session.scalars(select(CyabSystem)))
    rd = readiness.compute_many(session, systems, today)
    by_id = {s.id: s for s in systems}
    counts = readiness.stage_counts(rd.values())
    pipeline = [(key, readiness.STAGE_LABELS[key], counts[key])
                for key in readiness.STEPS + ("signed", "review_due")]

    open_stages = set(readiness.STEPS) | {"review_due"}
    queue = sorted(
        (r for r in rd.values() if r.stage in open_stages and _is_mine(by_id[r.system_id], user)),
        key=lambda r: (r.stage != "review_due", r.pct),
    )
    stale_before = datetime.now() - timedelta(days=STALLED_DAYS)
    expiring = _expiring_system_ids(session, today)
    attention = [
        ("review_due", "Review overdue", counts["review_due"]),
        ("attention", "Required documents missing",
         sum(1 for r in rd.values() if r.stage in ("docs", "signoff") and r.missing_docs)),
        ("stalled", f"No progress for {STALLED_DAYS} days",
         sum(1 for r in rd.values() if r.stage in readiness.STEPS
             and by_id[r.system_id].updated_at and by_id[r.system_id].updated_at < stale_before)),
        ("expiring", f"Exceptions ending within {EXPIRING_DAYS} days", len(expiring & set(by_id))),
    ]
    ctx = _base(request, user, "board", "Board")
    ctx.update({
        "total": len(systems),
        "pipeline": pipeline,
        "queue": [(by_id[r.system_id], r) for r in queue[:8]],
        "queue_total": len(queue),
        "attention": attention,
        "activity": assurance.activity(session, limit=10),
        "signed_pct": round((counts["signed"]) * 100 / len(systems)) if systems else 0,
    })
    return templates.TemplateResponse(request=request, name="cyab/board.html", context=ctx)


# ── systems list / matrix ─────────────────────────────────────────────────


def _filtered(session: Session, user: User, params) -> tuple:
    today = date.today()
    q = (params.get("q") or "").strip()
    stage = params.get("stage") or ""
    sal = params.get("sal") or ""
    view = params.get("view") if params.get("view") in VIEWS else "all"

    stmt = select(CyabSystem)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(CyabSystem.name.ilike(like) | CyabSystem.department.ilike(like)
                          | CyabSystem.soc_analyst_owner.ilike(like))
    if sal in cyab_sal.LEVELS:
        stmt = stmt.where(CyabSystem.sal_tier == sal)
    systems = list(session.scalars(stmt))
    rd = readiness.compute_many(session, systems, today)

    stale_before = datetime.now() - timedelta(days=STALLED_DAYS)
    expiring = _expiring_system_ids(session, today) if view == "expiring" else set()

    def keep(s: CyabSystem) -> bool:
        r = rd[s.id]
        if stage and r.stage != stage:
            return False
        if view == "mine":
            return _is_mine(s, user)
        if view == "attention":
            return r.needs_attention
        if view == "stalled":
            return r.stage in readiness.STEPS and bool(s.updated_at) and s.updated_at < stale_before
        if view == "review_due":
            return r.stage == "review_due"
        if view == "expiring":
            return s.id in expiring
        return True

    rows = [(s, rd[s.id]) for s in systems if keep(s)]
    sort = params.get("sort") or "readiness"
    keys = {
        "name": lambda row: row[0].name.lower(),
        "readiness": lambda row: (row[1].pct, row[0].name.lower()),
        "stage": lambda row: (readiness.STAGES.index(row[1].stage), row[0].name.lower()),
        "updated": lambda row: row[0].updated_at or datetime.min,
    }
    rows.sort(key=keys.get(sort, keys["readiness"]), reverse=(params.get("dir") == "desc"))
    filters = {"q": q, "stage": stage, "sal": sal, "view": view, "sort": sort, "dir": params.get("dir") or ""}
    return rows, filters


@router.get("/cyab/systems", response_class=HTMLResponse)
def cyab_systems(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    params = request.query_params
    rows, filters = _filtered(session, user, params)
    try:
        page = max(1, int(params.get("page") or 1))
    except ValueError:
        page = 1
    pages = max(1, math.ceil(len(rows) / PAGE_SIZE))
    page = min(page, pages)
    shown = rows[(page - 1) * PAGE_SIZE: page * PAGE_SIZE]
    mode = "matrix" if params.get("mode") == "matrix" else "list"

    def link(**changes) -> str:
        merged = {**filters, "mode": mode, "page": page, **changes}
        return "/cyab/systems?" + urlencode({k: v for k, v in merged.items() if v not in ("", None, 1, "all", "list")})

    ctx = _base(request, user, "systems", "Systems")
    ctx.update({
        "rows": shown, "count": len(rows), "page": page, "pages": pages, "mode": mode,
        "filters": filters, "views": VIEWS, "link": link, "subprofiles": _subprofile_index(session),
        "stages": readiness.STAGES, "sal_levels": cyab_sal.LEVELS, "steps": readiness.STEPS,
        "back": str(request.url.path) + ("?" + request.url.query if request.url.query else ""),
        "csv_href": "/cyab/systems.csv?" + urlencode({k: v for k, v in filters.items() if v}),
    })
    return templates.TemplateResponse(request=request, name="cyab/systems.html", context=ctx)


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@router.get("/cyab/systems.csv")
def cyab_systems_csv(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    rows, _ = _filtered(session, user, request.query_params)
    buf = io.StringIO()
    out = csv.writer(buf)
    out.writerow(["id", "name", "department", "owner", "sal", "stage", "readiness_pct",
                  "next_action", "missing_documents", "next_review"])
    for s, r in rows:
        out.writerow([_csv_cell(v) for v in (
            s.id, s.name, s.department, s.soc_analyst_owner, r.sal, r.stage_label, r.pct,
            r.next_action, "; ".join(r.missing_docs), r.next_review.isoformat() if r.next_review else "",
        )])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cyab-systems.csv"'})


@router.post("/cyab/systems/bulk")
async def cyab_systems_bulk(
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    form = await request.form()
    back = _safe_back(form.get("back") or "", "/cyab/systems")
    try:
        ids = [int(v) for v in form.getlist("ids")][:500]
    except ValueError:
        return _back(back, err="Bad selection")
    if not ids:
        return _back(back, err="Select at least one system")
    systems = list(session.scalars(select(CyabSystem).where(CyabSystem.id.in_(ids))))
    action = form.get("action") or ""
    if action == "owner":
        owner = (form.get("owner") or "").strip()[:255]
        if not owner:
            return _back(back, err="Name the new owner")
        for s in systems:
            s.soc_analyst_owner = owner
        msg = f"{owner} now owns {len(systems)} systems"
    elif action == "sal":
        level = form.get("sal") or ""
        if level not in cyab_sal.LEVELS:
            return _back(back, err="Choose a SAL")
        for s in systems:
            refused = _sal_change_refused(user, s.sal_tier, level)
            if refused:
                return _back(back, err=f"{s.name}: {refused}")
        for s in systems:
            _set_sal(s, level)
        msg = f"{len(systems)} systems set to {level}"
    else:
        return _back(back, err="Choose an action")
    session.commit()
    return _back(back, msg=msg)


# ── one system ────────────────────────────────────────────────────────────


@router.get("/cyab/systems/{system_id}")
def cyab_system_root(system_id: int, user: User = Depends(require_page_permission(READ))):
    return RedirectResponse(f"/cyab/systems/{system_id}/summary", status_code=307)


def _use_case_grid(system: CyabSystem, rd: readiness.Readiness, index: Dict[str, dict]) -> List[dict]:
    grid = []
    for sid in rd.subprofile_ids:
        sp = index.get(sid)
        if sp is None:
            continue
        sources = [ds for ds in system.data_sources if ds.subprofile_id == sid]
        statuses = {ds.id: readiness.parse_uc_status(ds.use_case_status) for ds in sources}
        rows = []
        for kind, key in (("Detection", "detection_use_cases"), ("Audit", "audit_use_cases")):
            for uc in sp["catalogue"].get(key) or []:
                cells = [(ds, statuses[ds.id].get(uc["id"], "")) for ds in sources]
                rows.append({"uc": uc, "kind": kind, "cells": cells})
        grid.append({"subprofile": sp, "sources": sources, "rows": rows,
                     "shipped": sum(1 for r in rows if any(c[1] == "shipped" for c in r["cells"])),
                     "set": sum(1 for r in rows if any(c[1] for c in r["cells"]))})
    return grid


def _intake_sections(rd: readiness.Readiness, index: Dict[str, dict], answers: dict) -> List[dict]:
    seen = set()
    out = []
    for sid in rd.subprofile_ids:
        sp = index.get(sid)
        if sp is None:
            continue
        qs = [q for q in sp["catalogue"].get("intake_questions") or [] if q["key"] not in seen]
        seen.update(q["key"] for q in qs)
        answered = sum(1 for q in qs if answers.get(q["key"]) not in (None, "", []))
        out.append({"subprofile": sp, "questions": qs, "answered": answered})
    return out


def _checklist_rows(session: Session, system: CyabSystem, sal: str, today: date) -> dict:
    checklist.seed_for_system(session, system.id)
    items = list(session.scalars(select(CyabDocChecklistItem).where(CyabDocChecklistItem.system_id == system.id)))
    active = {}
    for e in assurance.exceptions_for_system(session, system.id):
        if e.active_on(today) and e.item_id not in active:
            active[e.item_id] = e
    order = {c: i for i, c in enumerate(checklist._CATEGORY_ORDER)}
    items.sort(key=lambda i: (order.get(i.category, 99), i.label.lower()))
    def is_open(i):
        return i.status not in ("done", "na") and i.id not in active

    required = [i for i in items if cyab_sal.is_required(i.kind, i.is_critical, sal)]
    other = [i for i in items if i not in required]
    required.sort(key=lambda i: (not is_open(i), i.id not in active))
    return {"required": required, "other": other, "exceptions": active,
            "open": sum(1 for i in required if is_open(i))}


@router.get("/cyab/systems/{system_id}/{tab}", response_class=HTMLResponse)
def cyab_system(
    system_id: int,
    tab: str,
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    if tab not in dict(TABS):
        raise HTTPException(status_code=404, detail="Unknown tab")
    today = date.today()
    system = _get_system(session, system_id)
    rd = readiness.compute(session, system, today)
    index = _subprofile_index(session)

    ctx = _base(request, user, "systems", system.name)
    ctx.update({
        "system": system, "rd": rd, "tab": tab, "tabs": TABS, "steps": rd.steps,
        "subprofiles": index, "sal_levels": cyab_sal.LEVELS,
        "sal_review_days": cyab_sal.REVIEW_DAYS,
        "here": f"/cyab/systems/{system.id}/{tab}",
    })
    if tab == "summary":
        ctx["activity"] = assurance.activity(session, system_id=system.id, limit=12)
    elif tab == "profile":
        answers = load_answers(session, system.id)
        ctx.update({"answers": answers, "intake": _intake_sections(rd, index, answers),
                    "classifications": CLASSIFICATIONS})
    elif tab == "sources":
        ctx["groups"] = _grouped_subprofiles(index)
        ctx["uc_set"] = {ds.id: len(readiness.parse_uc_status(ds.use_case_status)) for ds in system.data_sources}
    elif tab == "use-cases":
        ctx.update({"grid": _use_case_grid(system, rd, index), "uc_statuses": UC_STATUSES})
    elif tab == "signoff":
        ctx.update({
            "docs": _checklist_rows(session, system, rd.sal, today),
            "doc_statuses": ALL_STATUSES,
            "history": assurance.history(session, system.id),
            "approver": cyab_sal.APPROVER[rd.sal],
            "max_until": today + timedelta(days=cyab_sal.MAX_EXCEPTION_DAYS[rd.sal]),
            "default_until": today + timedelta(days=min(90, cyab_sal.MAX_EXCEPTION_DAYS[rd.sal])),
            "today": today,
            "gate": [s for s in rd.steps if s.key != "signoff" and not s.complete],
            "roles": SIGNOFF_ROLES,
        })
    return templates.TemplateResponse(request=request, name="cyab/system.html", context=ctx)


@router.post("/cyab/systems/{system_id}/profile")
async def cyab_save_profile(
    system_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    system = _get_system(session, system_id)
    here = f"/cyab/systems/{system_id}/profile"
    form = await request.form()
    name = (form.get("name") or "").strip()
    department = (form.get("department") or "").strip()
    if not name or not department:
        return _back(here, err="A system needs a name and a department")
    try:
        runbook = _clean_url(form.get("ir_runbook_url") or "")
    except assurance.AssuranceError as exc:
        return _back(here, err=str(exc))
    level = form.get("sal_tier") or ""
    sal_changes = level in cyab_sal.LEVELS and level != cyab_sal.normalise(system.sal_tier)
    refused = _sal_change_refused(user, system.sal_tier, level) if sal_changes else None
    if refused:
        return _back(here, err=refused)
    system.name, system.department = name[:255], department[:255]
    for field in ("department_lead", "dept_lead_email", "soc_lead", "soc_analyst_owner", "business_unit"):
        setattr(system, field, (form.get(field) or "").strip()[:255] or None)
    classification = form.get("data_classification") or ""
    system.data_classification = classification if classification in CLASSIFICATIONS else None
    if sal_changes:
        _set_sal(system, level)
    system.ir_runbook_url = runbook
    session.commit()
    return _back(here, msg="Profile saved")


@router.post("/cyab/systems/{system_id}/intake")
async def cyab_save_intake(
    system_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    system = _get_system(session, system_id)
    rd = readiness.compute(session, system)
    index = _subprofile_index(session)
    form = await request.form()
    answers = {}
    for section in _intake_sections(rd, index, {}):
        for q in section["questions"]:
            field = "q:" + q["key"]
            values = [v for v in form.getlist(field) if v]
            answers[q["key"]] = values if q.get("answer_type") == "multi" else (values[0] if values else "")
    save_answers(session, system.id, answers, user.id)
    system.updated_at = datetime.now()
    session.commit()
    return _back(f"/cyab/systems/{system_id}/profile", msg="Intake answers saved")


@router.post("/cyab/systems/{system_id}/sources")
async def cyab_add_source(
    system_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    system = _get_system(session, system_id)
    here = f"/cyab/systems/{system_id}/sources"
    form = await request.form()
    name = (form.get("name") or "").strip()
    if not name:
        return _back(here, err="Name the data source")
    sub_id = form.get("subprofile_id") or None
    if sub_id and session.get(CyabSubProfile, sub_id) is None:
        return _back(here, err="Unknown sub-profile")
    session.add(CyabDataSource(
        system_id=system.id, name=name[:255], subprofile_id=sub_id, sal_tier=system.sal_tier,
        data_source_type=(form.get("data_source_type") or "").strip()[:64] or None,
        data_namespace=(form.get("data_namespace") or "").strip()[:128] or None,
    ))
    system.updated_at = datetime.now()
    session.commit()
    return _back(here, msg=f"Added {name}")


def _get_source(session: Session, source_id: int) -> CyabDataSource:
    ds = session.get(CyabDataSource, source_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Data source not found")
    return ds


@router.post("/cyab/sources/{source_id}/subprofile")
async def cyab_source_subprofile(
    source_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    ds = _get_source(session, source_id)
    here = f"/cyab/systems/{ds.system_id}/sources"
    sub_id = (await request.form()).get("subprofile_id") or None
    if sub_id and session.get(CyabSubProfile, sub_id) is None:
        return _back(here, err="Unknown sub-profile")
    ds.subprofile_id = sub_id
    ds.system.updated_at = datetime.now()
    session.commit()
    return _back(here, msg=f"{ds.name} updated")


@router.post("/cyab/sources/{source_id}/delete")
def cyab_source_delete(
    source_id: int,
    user: User = Depends(require_permission(APPROVE)),
    session: Session = Depends(get_db_session),
):
    ds = _get_source(session, source_id)
    here = f"/cyab/systems/{ds.system_id}/sources"
    name = ds.name
    session.delete(ds)
    session.commit()
    return _back(here, msg=f"Removed {name}")


@router.post("/cyab/sources/{source_id}/use-case")
async def cyab_source_use_case(
    source_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    ds = _get_source(session, source_id)
    here = f"/cyab/systems/{ds.system_id}/use-cases"
    form = await request.form()
    uc_id, status = form.get("uc") or "", form.get("status") or ""
    sp = session.get(CyabSubProfile, ds.subprofile_id) if ds.subprofile_id else None
    cat = readiness._catalogue(sp)
    known = {u["id"] for u in (cat.get("detection_use_cases") or []) + (cat.get("audit_use_cases") or [])}
    if uc_id not in known:
        return _back(here, err="That use case does not belong to this source's sub-profile")
    statuses = readiness.parse_uc_status(ds.use_case_status)
    if status in UC_STATUSES:
        statuses[uc_id] = status
    elif not status:
        statuses.pop(uc_id, None)
    else:
        return _back(here, err="Unknown status")
    ds.use_case_status = json.dumps(statuses, sort_keys=True)
    ds.system.updated_at = datetime.now()
    session.commit()
    return _back(here)


def _get_item(session: Session, item_id: int) -> CyabDocChecklistItem:
    item = session.get(CyabDocChecklistItem, item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Checklist item not found")
    return item


@router.post("/cyab/checklist/{item_id}")
async def cyab_checklist_item(
    item_id: int,
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    item = _get_item(session, item_id)
    here = f"/cyab/systems/{item.system_id}/signoff"
    form = await request.form()
    try:
        checklist.update_item(session, item.id, status=form.get("status") or None,
                              url=(form.get("url") or "").strip(), user_id=user.id)
    except ValueError as exc:
        return _back(here, err=str(exc))
    return _back(here, msg=f"{item.label} saved")


@router.post("/cyab/checklist/{item_id}/accept")
async def cyab_accept_gap(
    item_id: int,
    request: Request,
    user: User = Depends(require_permission(APPROVE)),
    session: Session = Depends(get_db_session),
):
    item = _get_item(session, item_id)
    here = f"/cyab/systems/{item.system_id}/signoff"
    form = await request.form()
    try:
        until = date.fromisoformat(form.get("until") or "")
    except ValueError:
        return _back(here, err="Give the date the acceptance ends")
    try:
        assurance.accept_gap(session, item, form.get("reason") or "", form.get("approver") or "", until, user)
    except assurance.AssuranceError as exc:
        return _back(here, err=str(exc))
    return _back(here, msg=f"{item.label} gap accepted until {until:%d %b %Y}")


@router.post("/cyab/exceptions/{exception_id}/revoke")
def cyab_revoke_gap(
    exception_id: int,
    user: User = Depends(require_permission(APPROVE)),
    session: Session = Depends(get_db_session),
):
    exc = session.get(CyabChecklistException, exception_id)
    if exc is None:
        raise HTTPException(status_code=404, detail="Exception not found")
    assurance.revoke_gap(session, exc)
    return _back(f"/cyab/systems/{exc.system_id}/signoff", msg="Acceptance revoked")


@router.post("/cyab/systems/{system_id}/sign")
async def cyab_sign(
    system_id: int,
    request: Request,
    user: User = Depends(require_permission(APPROVE)),
    session: Session = Depends(get_db_session),
):
    system = _get_system(session, system_id)
    here = f"/cyab/systems/{system_id}/signoff"
    form = await request.form()
    try:
        row = assurance.sign(session, system, form.get("role") or "", user, form.get("note"))
    except assurance.AssuranceError as exc:
        return _back(here, err=str(exc))
    who = "department" if row.role == "department" else "SOC"
    return _back(here, msg=f"Signed off as {who}")


@router.post("/cyab/systems/{system_id}/review")
async def cyab_review(
    system_id: int,
    request: Request,
    user: User = Depends(require_permission(APPROVE)),
    session: Session = Depends(get_db_session),
):
    system = _get_system(session, system_id)
    here = f"/cyab/systems/{system_id}/signoff"
    form = await request.form()
    try:
        assurance.mark_reviewed(session, system, user, form.get("note"))
    except assurance.AssuranceError as exc:
        return _back(here, err=str(exc))
    return _back(here, msg=f"Reviewed. Next review {system.next_review_date:%d %b %Y}")


# ── onboard ───────────────────────────────────────────────────────────────


_SCOPING_MAX = 64 * 1024


def _scoping_prefill(request: Request) -> str:
    """Answers carried over from the public scoping page, as JSON text."""
    answers = None
    try:
        answers = request.session.get("scoping_prefill")
    except (AssertionError, AttributeError):
        pass
    if answers is None and request.query_params.get("answers"):
        try:
            answers = json.loads(request.query_params["answers"][:_SCOPING_MAX])
        except ValueError:
            answers = None
    return json.dumps(answers) if isinstance(answers, dict) else ""


@router.get("/cyab/onboard", response_class=HTMLResponse)
def cyab_onboard(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
):
    ctx = _base(request, user, "onboard", "Onboard a system")
    ctx.update({
        "sal_levels": cyab_sal.LEVELS, "sal_review_days": cyab_sal.REVIEW_DAYS,
        "classifications": CLASSIFICATIONS, "me": _me(user),
        "scoping_answers": _scoping_prefill(request),
    })
    return templates.TemplateResponse(request=request, name="cyab/onboard.html", context=ctx)


@router.post("/cyab/onboard")
async def cyab_onboard_create(
    request: Request,
    user: User = Depends(require_permission(EDIT)),
    session: Session = Depends(get_db_session),
):
    form = await request.form()
    name = (form.get("name") or "").strip()
    department = (form.get("department") or "").strip()
    if not name or not department:
        return _back("/cyab/onboard", err="A system needs a name and a department")
    level = form.get("sal_tier") if form.get("sal_tier") in cyab_sal.LEVELS else cyab_sal.DEFAULT
    classification = form.get("data_classification") or ""
    system = CyabSystem(
        name=name[:255], department=department[:255], status="DRAFT", sal_tier=level,
        department_lead=(form.get("department_lead") or "").strip()[:255] or None,
        soc_analyst_owner=(form.get("soc_analyst_owner") or "").strip()[:255] or None,
        data_classification=classification if classification in CLASSIFICATIONS else None,
        review_cadence_days=cyab_sal.REVIEW_DAYS[level], created_by=user.id,
    )
    session.add(system)
    session.commit()
    checklist.seed_for_system(session, system.id)

    raw = (form.get("scoping_answers") or "")[:_SCOPING_MAX]
    if raw:
        try:
            carried = json.loads(raw)
        except ValueError:
            carried = None
        if isinstance(carried, dict):
            save_answers(session, system.id, {str(k)[:128]: v for k, v in list(carried.items())[:300]}, user.id)
        try:
            request.session.pop("scoping_prefill", None)
        except (AssertionError, AttributeError):
            pass
    return _back(f"/cyab/systems/{system.id}/sources", msg=f"{system.name} created. Add its first data source.")


# ── history ───────────────────────────────────────────────────────────────


def _history(session: Session, params) -> tuple:
    try:
        sid = int(params.get("system") or 0) or None
    except ValueError:
        sid = None
    return sid, assurance.activity(session, system_id=sid, limit=300)


@router.get("/cyab/history", response_class=HTMLResponse)
def cyab_history(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    sid, events = _history(session, request.query_params)
    ctx = _base(request, user, "history", "History")
    ctx.update({
        "events": events, "system_id": sid,
        "systems": session.execute(select(CyabSystem.id, CyabSystem.name).order_by(CyabSystem.name)).all(),
        "csv_href": "/cyab/history.csv" + (f"?system={sid}" if sid else ""),
    })
    return templates.TemplateResponse(request=request, name="cyab/history.html", context=ctx)


@router.get("/cyab/history.csv")
def cyab_history_csv(
    request: Request,
    user: User = Depends(require_page_permission(READ)),
    session: Session = Depends(get_db_session),
):
    _, events = _history(session, request.query_params)
    buf = io.StringIO()
    out = csv.writer(buf)
    out.writerow(["when", "who", "system", "what", "note"])
    for e in events:
        out.writerow([_csv_cell(v) for v in (e["at"].isoformat(timespec="seconds"), e["who"],
                                             e["system"], e["text"], e["note"])])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="cyab-history.csv"'})


# ── old addresses ─────────────────────────────────────────────────────────


@router.get("/cyab/coverage")
def cyab_coverage(user: User = Depends(require_page_permission(READ))):
    return RedirectResponse("/cyab/systems?mode=matrix", status_code=301)


@router.get("/cyab/audit")
def cyab_audit(user: User = Depends(require_page_permission(READ))):
    return RedirectResponse("/cyab/history", status_code=301)
