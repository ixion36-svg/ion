"""CyAB onboarding wizard — session lifecycle.

State shape (state_json):
    {
        "step":     int 1..4,
        "identity": {name, hostname, pillar, owner, department, containment_authority},
        "intake":   {question_id: answer, ...},
        "source":   {name, data_source_type, subprofile_id},
        "docs":     {kind: {is_critical: bool, url: str|None, mark_later: bool}},
        "system_id": int|None,
        "source_id": int|None,
    }

The wizard NEVER blocks: each save_* helper persists what it can and
advances `step` so the user can come back. start_wizard creates the row
empty; finish() flips is_complete=True and seeds the doc checklist.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource, CyabSystem
from ion.models.cyab_wizard import CyabWizardSession


_EMPTY_STATE: Dict[str, Any] = {
    "step": 1,
    "identity": {},
    "intake": {},
    "source": {},
    "docs": {},
    "system_id": None,
    "source_id": None,
}


def _load(session: Session, wizard_id: str) -> CyabWizardSession:
    row = session.get(CyabWizardSession, wizard_id)
    if row is None:
        raise LookupError(f"Unknown wizard session: {wizard_id}")
    return row


def _state(row: CyabWizardSession) -> Dict[str, Any]:
    return json.loads(row.state_json) if row.state_json else dict(_EMPTY_STATE)


def _save_state(row: CyabWizardSession, state: Dict[str, Any]) -> None:
    row.state_json = json.dumps(state)


# -- Public API ------------------------------------------------------------


def start_wizard(session: Session, user_id: Optional[int]) -> str:
    wid = uuid.uuid4().hex
    row = CyabWizardSession(
        id=wid, user_id=user_id, step=1,
        state_json=json.dumps(_EMPTY_STATE),
    )
    session.add(row)
    session.commit()
    return wid


def load_state(session: Session, wizard_id: str) -> Dict[str, Any]:
    return _state(_load(session, wizard_id))


def save_identity(session: Session, wizard_id: str, identity: Dict[str, Any]) -> Dict[str, Any]:
    """Persist Step 1 fields and create the real CyabSystem row.

    Required (per spec): name, department. Everything else is optional --
    blank strings are fine because the wizard never blocks.
    """
    row = _load(session, wizard_id)
    state = _state(row)
    state["identity"] = identity

    # Create or update the backing CyabSystem
    if state.get("system_id"):
        sys_row = session.get(CyabSystem, state["system_id"])
    else:
        sys_row = CyabSystem(
            name=identity.get("name") or "untitled",
            department=identity.get("department") or "Unassigned",
        )
        session.add(sys_row)
        session.flush()
        state["system_id"] = sys_row.id
        row.system_id = sys_row.id

    sys_row.name = identity.get("name") or sys_row.name
    sys_row.department = identity.get("department") or sys_row.department
    sys_row.soc_analyst_owner = identity.get("owner") or sys_row.soc_analyst_owner
    sys_row.containment_authority = identity.get("containment_authority") or sys_row.containment_authority

    state["step"] = max(state["step"], 2)
    row.step = state["step"]
    _save_state(row, state)
    session.commit()
    return state


def save_intake(session: Session, wizard_id: str, answers: Dict[str, Any]) -> Dict[str, Any]:
    """Persist Step 2 answers in the wizard blob (real autosave goes via
    /api/cyab/systems/{sys_id}/answers -- this just records the
    snapshot for resume). Advances step -> 3."""
    row = _load(session, wizard_id)
    state = _state(row)
    state["intake"] = {**state.get("intake", {}), **answers}
    state["step"] = max(state["step"], 3)
    row.step = state["step"]
    _save_state(row, state)
    session.commit()
    return state


def save_source(session: Session, wizard_id: str, source: Dict[str, Any]) -> Dict[str, Any]:
    """Create a single CyabDataSource for the system. Step 3."""
    row = _load(session, wizard_id)
    state = _state(row)
    if not state.get("system_id"):
        raise ValueError("save_source called before save_identity")

    if state.get("source_id"):
        src = session.get(CyabDataSource, state["source_id"])
    else:
        src = CyabDataSource(system_id=state["system_id"], name=source.get("name") or "source-1")
        session.add(src)
        session.flush()
        state["source_id"] = src.id
        row.source_id = src.id

    src.name = source.get("name") or src.name
    src.data_source_type = source.get("data_source_type")
    src.subprofile_id = source.get("subprofile_id")

    state["source"] = source
    state["step"] = max(state["step"], 4)
    row.step = state["step"]
    _save_state(row, state)
    session.commit()
    return state


def save_docs(session: Session, wizard_id: str, docs: Dict[str, Any]) -> Dict[str, Any]:
    """Record per-checklist-item overrides (is_critical override + URL +
    'mark later' flag). The actual seed happens in finish()."""
    row = _load(session, wizard_id)
    state = _state(row)
    state["docs"] = docs
    _save_state(row, state)
    session.commit()
    return state


def finish(session: Session, wizard_id: str, doc_overrides: Dict[str, Any]) -> int:
    """Lazy-seed the doc checklist + apply overrides + close the wizard.

    Returns the system_id so the caller can redirect to /cyab/systems/{id}.
    """
    from ion.services import cyab_doc_checklist_service

    row = _load(session, wizard_id)
    state = _state(row)
    if not state.get("system_id"):
        raise ValueError("finish called before save_identity")

    cyab_doc_checklist_service.seed_for_system(session, state["system_id"])

    # Apply per-item URL / critical / mark-later overrides if the service
    # supports them (no-op fallback if it doesn't).
    apply = getattr(cyab_doc_checklist_service, "apply_wizard_overrides", None)
    if apply:
        apply(session, state["system_id"], doc_overrides or {})

    state["docs"] = doc_overrides or {}
    _save_state(row, state)
    row.is_complete = True
    session.commit()
    return state["system_id"]
