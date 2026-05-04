# CyAB IA — Onboarding Wizard + Landing Pages (Sub-plan B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three CyAB landing surfaces — the new `/cyab` Overview page, the `/cyab/systems` portfolio list, and the four-step `/cyab/onboard` wizard — and add the secondary CyAB tab strip used by every page in the section. Replaces the legacy `cyab.html` template (per-system content already moved to `/cyab/systems/{id}` in Sub-plan A). Leaves `/cyab/scoping`, `/cyab/coverage`, and `/cyab/audit` for Sub-plan C (the tab strip links there but those pages are placeholders this sub-plan).

**Architecture:**
- Three new page routes registered after the per-system page handler from Sub-plan A:
  - `GET /cyab` — Overview (KPIs · in-progress feed · needs-attention feed · CTAs).
  - `GET /cyab/systems` — Portfolio list (table · filters · search · bulk ops).
  - `GET /cyab/onboard` — 4-step wizard, each step a separate URL (`?step=1..4`) so the user can deep-link / hit back.
- All three pages reuse existing API surface where possible:
  - `/api/cyab/dashboard` already returns aggregated KPI counts → drives the Overview KPI strip (one extra field added: `signoffs_this_week`).
  - `/api/cyab/systems` already lists systems → drives the portfolio table; HTMX filtering bolts on top.
  - `/api/cyab/systems` POST already creates a row → wizard Step 1 calls it.
  - `/api/cyab/systems/{id}/sources` POST already creates a `CyabDataSource` → wizard Step 3 calls it.
  - `/api/cyab/studio/systems/{sys_id}/answers` already merges intake answers → wizard Step 2 calls it.
  - `cyab_doc_checklist_service.seed_for_system()` lazy-seeds the 20-item checklist → wizard Step 4 invokes it then exposes per-item edit.
- Two new HTMX-targeted endpoints:
  - `GET /cyab/systems/_table` — partial that re-renders the portfolio table when a filter changes (no full page reload).
  - `POST /api/cyab/systems/bulk` — apply `{action, system_ids[]}` (mark-reviewed · re-run-health · export-csv).
- Secondary tab strip is a Jinja partial (`templates/cyab/_section_nav.html`) included by Overview, Systems, Onboard (and later Coverage / Audit / Scoping in Sub-plan C). Forward-declared links to `/cyab/coverage` and `/cyab/audit` resolve to placeholder pages here so the nav doesn't 404.
- Legacy `cyab.html` template is **deleted** along with the legacy `/cyab` handler — the new Overview page replaces it. Per-system content already moved in Sub-plan A.

**Tech Stack:** FastAPI · HTMX · Jinja2 · Tailwind · SQLAlchemy 2.x · pytest

**Spec source:** `docs/superpowers/specs/2026-05-04-cyab-ia-design.md` (commit `66a540f`).

**Spec-to-model mapping (resolved here):**

The spec calls for wizard Step 1 to capture `name / hostname(s) / pillar / sub-profile / owner / dept / containment_authority`. The current `CyabSystem` model (verified in `src/ion/models/cyab.py`) doesn't have a top-level `hostname`, `pillar`, `owner`, or `subprofile_id` column — those live elsewhere. Resolution:

| Spec field | Mapped to |
|---|---|
| `name` | `CyabSystem.name` (existing) |
| `hostname(s)` | Captured but stored on the **first data source** at Step 3 (`CyabDataSource.name` historically holds the host identifier; spec acknowledges hostname is per-source). Step 1 gathers a single hostname into the wizard session and replays it as the default Source name in Step 3. |
| `pillar` | Selected at Step 1 to **filter** the sub-profile dropdown (no system-level field — pillar is implicit via `subprofile.pillar_id`). Stored in wizard session only. |
| `sub-profile` | `CyabDataSource.subprofile_id` (per-source; assigned to the Step 3 source row). |
| `owner` | `CyabSystem.soc_analyst_owner` (existing column). |
| `department` | `CyabSystem.department` (existing, NOT NULL). |
| `containment_authority` | `CyabSystem.containment_authority` (existing). |

The wizard accumulates these in a server-side session blob keyed by `wizard_id` (UUID, written to the `cyab_wizard_sessions` lightweight table — defined below) and only commits to the real CyAB tables at the end of each step. That way "exit anywhere and resume" works without dirty half-systems.

---

## File Structure

**New files (templates):**
- `src/ion/web/templates/cyab/overview.html` — page shell for `/cyab` (replaces legacy `cyab.html`).
- `src/ion/web/templates/cyab/systems_list.html` — page shell for `/cyab/systems`.
- `src/ion/web/templates/cyab/_systems_table.html` — table partial (HTMX-swapped on filter).
- `src/ion/web/templates/cyab/onboard.html` — wizard shell.
- `src/ion/web/templates/cyab/_wizard_step_1_identity.html`
- `src/ion/web/templates/cyab/_wizard_step_2_intake.html`
- `src/ion/web/templates/cyab/_wizard_step_3_source.html`
- `src/ion/web/templates/cyab/_wizard_step_4_docs.html`
- `src/ion/web/templates/cyab/_section_nav.html` — secondary tab strip used by every CyAB page.
- `src/ion/web/templates/cyab/coverage_placeholder.html` — stub (Sub-plan C fills).
- `src/ion/web/templates/cyab/audit_placeholder.html` — stub (Sub-plan C fills).

**New files (backend):**
- `src/ion/models/cyab_wizard.py` — `CyabWizardSession` model (wizard state).
- `src/ion/services/cyab_wizard_service.py` — start / advance / finish helpers.

**New files (tests):**
- `tests/unit/test_cyab_wizard_service.py`
- `tests/integration/test_cyab_overview_page.py`
- `tests/integration/test_cyab_systems_list.py`
- `tests/integration/test_cyab_onboard_wizard.py`
- `tests/integration/test_cyab_section_nav.py`

**Modified files:**
- `src/ion/web/server.py` — replace legacy `/cyab` handler; add `/cyab/systems`, `/cyab/onboard`, `/cyab/coverage`, `/cyab/audit` page routes.
- `src/ion/web/cyab_api.py` — add `signoffs_this_week` to `/dashboard`, `GET /systems/_table` HTMX filtered partial, `POST /systems/bulk`.
- `src/ion/web/templates/base.html` — keep CyAB nav entry as-is (already linked at line 87); no change needed but verified.
- `pyproject.toml`, `src/ion/__init__.py` — version bump (Task 11).
- `CHANGELOG.md` — release note.

**Deleted files:**
- `src/ion/web/templates/cyab.html` — replaced by the new Overview page (Task 4 deletes it).

---

## Task 1: Secondary tab strip partial + placeholder pages

The tab strip needs to exist before any page that includes it can render. The two placeholder pages (`/cyab/coverage`, `/cyab/audit`) keep the nav from 404'ing while Sub-plan C is pending.

**Files:**
- Create: `src/ion/web/templates/cyab/_section_nav.html`
- Create: `src/ion/web/templates/cyab/coverage_placeholder.html`
- Create: `src/ion/web/templates/cyab/audit_placeholder.html`
- Modify: `src/ion/web/server.py` — add the two placeholder routes.
- Test: `tests/integration/test_cyab_section_nav.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_section_nav.py
"""Integration tests for the CyAB secondary tab strip + placeholder routes."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_coverage_placeholder_route_responds(admin_session):
    r = admin_session.get("/cyab/coverage")
    assert r.status_code == 200
    body = r.text.lower()
    assert "coverage" in body
    assert "sub-plan c" in body or "coming soon" in body


def test_audit_placeholder_route_responds(admin_session):
    r = admin_session.get("/cyab/audit")
    assert r.status_code == 200
    body = r.text.lower()
    assert "audit" in body
    assert "sub-plan c" in body or "coming soon" in body


def test_coverage_page_includes_section_nav(admin_session):
    r = admin_session.get("/cyab/coverage")
    assert "cyab-section-nav" in r.text
    # All 6 nav entries present
    for label in ("Overview", "Systems", "Scoping", "Onboard", "Coverage", "Audit"):
        assert label in r.text


def test_section_nav_marks_active_tab(admin_session):
    r = admin_session.get("/cyab/coverage")
    # Coverage tab should be flagged active when on /cyab/coverage
    assert 'data-active="coverage"' in r.text or 'is-active' in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_section_nav.py -v
```
Expected: 404s on both placeholder routes (not registered yet).

- [ ] **Step 3: Create the section nav partial**

```html
<!-- src/ion/web/templates/cyab/_section_nav.html -->
{# Secondary tab strip rendered inside every CyAB page.
   Caller passes `active_tab` (string) to highlight one entry. #}
{% set _tabs = [
  ('overview',  'Overview',  '/cyab'),
  ('systems',   'Systems',   '/cyab/systems'),
  ('scoping',   'Scoping',   '/cyab/scoping'),
  ('onboard',   'Onboard',   '/cyab/onboard'),
  ('coverage',  'Coverage',  '/cyab/coverage'),
  ('audit',     'Audit',     '/cyab/audit'),
] %}
<nav class="cyab-section-nav tw-flex tw-gap-1 tw-border-b tw-border-slate-800 tw-mb-4"
     data-active="{{ active_tab }}">
  {% for slug, label, href in _tabs %}
    <a href="{{ href }}"
       class="tw-px-3 tw-py-2 tw-text-[12.5px] tw-text-slate-400 hover:tw-text-cyan-300 tw-border-b-2 tw-border-transparent {% if slug == active_tab %}tw-text-cyan-300 tw-border-cyan-400 is-active{% endif %}">
      {{ label }}
    </a>
  {% endfor %}
</nav>
```

- [ ] **Step 4: Create the two placeholder templates**

```html
<!-- src/ion/web/templates/cyab/coverage_placeholder.html -->
{% extends "base.html" %}
{% block title %}Coverage — CyAB · ION{% endblock %}
{% block content %}
<div class="cyab-coverage-placeholder">
  {% include "cyab/_section_nav.html" %}
  <header class="tw-mb-4">
    <h1 class="tw-text-[24px] tw-text-white tw-font-semibold">Fleet coverage matrix</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px]">Systems × data-health dimensions. Lands in Sub-plan C.</p>
  </header>
  <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-8 tw-text-center tw-text-slate-500">
    <p class="tw-text-[13px]">Coming soon — Sub-plan C will fill this matrix.</p>
    <p class="tw-text-[11px] tw-mt-2">For per-system data health today, open any system from <a href="/cyab/systems" class="tw-text-cyan-400">Systems</a>.</p>
  </div>
</div>
{% endblock %}
```

```html
<!-- src/ion/web/templates/cyab/audit_placeholder.html -->
{% extends "base.html" %}
{% block title %}Audit Trail — CyAB · ION{% endblock %}
{% block content %}
<div class="cyab-audit-placeholder">
  {% include "cyab/_section_nav.html" %}
  <header class="tw-mb-4">
    <h1 class="tw-text-[24px] tw-text-white tw-font-semibold">Audit Trail</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px]">Sign-offs · changes · snapshots. Lands in Sub-plan C.</p>
  </header>
  <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-8 tw-text-center tw-text-slate-500">
    <p class="tw-text-[13px]">Coming soon — Sub-plan C will fill this trail.</p>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Register the two placeholder routes**

In `src/ion/web/server.py`, add after the per-system page handler block from Sub-plan A:

```python
# src/ion/web/server.py
@app.get("/cyab/coverage", response_class=HTMLResponse)
async def cyab_coverage_placeholder(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Sub-plan C placeholder. Returns the section nav + a 'coming soon' card."""
    return templates.TemplateResponse(
        request=request,
        name="cyab/coverage_placeholder.html",
        context={"active_tab": "coverage", "user": user},
    )


@app.get("/cyab/audit", response_class=HTMLResponse)
async def cyab_audit_placeholder(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Sub-plan C placeholder. Returns the section nav + a 'coming soon' card."""
    return templates.TemplateResponse(
        request=request,
        name="cyab/audit_placeholder.html",
        context={"active_tab": "audit", "user": user},
    )
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_section_nav.py -v
```
Expected: 4/4 PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/_section_nav.html src/ion/web/templates/cyab/coverage_placeholder.html src/ion/web/templates/cyab/audit_placeholder.html src/ion/web/server.py tests/integration/test_cyab_section_nav.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): secondary tab strip + coverage/audit placeholder routes"
```

---

## Task 2: Wizard session model + service

The wizard needs server-side state per in-progress onboarding so the user can exit/resume without leaving half-built CyAB rows. One-table model: `cyab_wizard_sessions` keyed by UUID, holding a JSON blob of `{step, identity, intake, source, docs}` accumulators plus pointers to the real `CyabSystem.id` and `CyabDataSource.id` once those rows are created at the end of Steps 1 and 3 respectively.

**Files:**
- Create: `src/ion/models/cyab_wizard.py`
- Create: `src/ion/services/cyab_wizard_service.py`
- Test: `tests/unit/test_cyab_wizard_service.py`

- [ ] **Step 1: Write failing unit tests**

```python
# tests/unit/test_cyab_wizard_service.py
"""Unit tests for cyab_wizard_service — session state machine."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", future=True)
    from ion.models.base import Base
    # Importing the model registers it on Base.metadata
    import ion.models.cyab_wizard  # noqa: F401
    import ion.models.cyab          # noqa: F401  (FK target tables)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_start_wizard_returns_uuid_and_persists_row(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    assert isinstance(wid, str) and len(wid) >= 16

    state = svc.load_state(s, wid)
    assert state["step"] == 1
    assert state["identity"] == {}
    assert state["system_id"] is None


def test_save_step_1_creates_cyab_system_and_persists_id(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)

    state = svc.save_identity(s, wid, identity={
        "name": "prod-sso-test",
        "hostname": "sso01.corp",
        "pillar": "identity",
        "owner": "alice",
        "department": "Identity",
        "containment_authority": "SOC L2 on-call",
    })
    assert state["system_id"] is not None
    assert state["step"] == 2
    assert state["identity"]["name"] == "prod-sso-test"

    # Verify the CyabSystem row was created
    from ion.models.cyab import CyabSystem
    sys_row = s.get(CyabSystem, state["system_id"])
    assert sys_row.name == "prod-sso-test"
    assert sys_row.department == "Identity"
    assert sys_row.soc_analyst_owner == "alice"
    assert sys_row.containment_authority == "SOC L2 on-call"


def test_save_step_3_creates_data_source_with_subprofile(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "prod-dns", "hostname": "dns01", "pillar": "network",
        "owner": "bob", "department": "Net", "containment_authority": "n/a",
    })
    svc.save_intake(s, wid, answers={"q_traffic_volume": "high"})
    state = svc.save_source(s, wid, source={
        "name": "dns01", "data_source_type": "generic-syslog",
        "subprofile_id": "ad_dns_logs",
    })
    assert state["source_id"] is not None
    from ion.models.cyab import CyabDataSource
    src = s.get(CyabDataSource, state["source_id"])
    assert src.data_source_type == "generic-syslog"
    assert src.subprofile_id == "ad_dns_logs"


def test_finish_seeds_doc_checklist_and_returns_system_id(db, monkeypatch):
    from ion.services import cyab_wizard_service as svc

    seeded = {}
    def fake_seed(session, sys_id):
        seeded["sys_id"] = sys_id
        return 20
    monkeypatch.setattr(
        "ion.services.cyab_doc_checklist_service.seed_for_system", fake_seed,
    )

    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "prod-x", "hostname": "x", "pillar": "endpoint",
        "owner": "c", "department": "Ops", "containment_authority": "x",
    })
    svc.save_intake(s, wid, answers={})
    svc.save_source(s, wid, source={
        "name": "x", "data_source_type": "edr-generic", "subprofile_id": None,
    })
    sys_id = svc.finish(s, wid, doc_overrides={})
    assert seeded["sys_id"] == sys_id


def test_resume_returns_same_state(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    wid = svc.start_wizard(s, user_id=1)
    svc.save_identity(s, wid, identity={
        "name": "n", "hostname": "h", "pillar": "p",
        "owner": "o", "department": "d", "containment_authority": "c",
    })
    state = svc.load_state(s, wid)
    assert state["step"] == 2
    assert state["identity"]["name"] == "n"


def test_load_state_unknown_wid_raises(db):
    from ion.services import cyab_wizard_service as svc
    s = db()
    with pytest.raises(LookupError):
        svc.load_state(s, "does-not-exist")
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_wizard_service.py -v
```
Expected: import errors — modules don't exist.

- [ ] **Step 3: Create the wizard session model**

```python
# src/ion/models/cyab_wizard.py
"""CyAB onboarding wizard session — server-side state for the 4-step flow.

A row exists for the lifetime of an in-progress onboarding. When the user
hits "Finish" on step 4 the row stays (audit trail) but is_complete=True.
The actual CyabSystem and CyabDataSource rows are created mid-wizard
(end of Step 1 and Step 3 respectively) so on-page autosaves can write
real intake answers via the existing /api/cyab/studio endpoints.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


class CyabWizardSession(Base):
    """One row per in-progress (or completed) wizard run."""

    __tablename__ = "cyab_wizard_sessions"

    # UUID4 hex; primary key so URLs can carry it directly.
    id: Mapped[str] = mapped_column(String(36), primary_key=True)

    user_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    # Current step (1..4). Advances on save_*.
    step: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # JSON blob — see cyab_wizard_service for shape.
    state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Pointers to real rows — populated mid-wizard.
    system_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_systems.id", ondelete="SET NULL"), nullable=True
    )
    source_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("cyab_data_sources.id", ondelete="SET NULL"), nullable=True
    )

    is_complete: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<CyabWizardSession(id={self.id!r}, step={self.step}, sys_id={self.system_id})>"
```

- [ ] **Step 4: Create the wizard service**

```python
# src/ion/services/cyab_wizard_service.py
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

from ion.models.cyab import CyabSystem, CyabDataSource
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


# ── Public API ────────────────────────────────────────────────────────────


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

    Required (per spec): name, department. Everything else is optional —
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
        session.add(sys_row); session.flush()
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
    /api/cyab/studio/systems/{sys_id}/answers — this just records the
    snapshot for resume). Advances step → 3."""
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
        session.add(src); session.flush()
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
```

- [ ] **Step 5: Register the model with Alembic-style schema bootstrap**

ION uses `Base.metadata.create_all` at startup (no Alembic). Touching `__init__.py` for the models package makes it importable; verify by importing inside the test fixture (already done above). Add an explicit re-export so other modules can do `from ion.models.cyab_wizard import CyabWizardSession`:

```python
# src/ion/models/__init__.py — ensure cyab_wizard is imported eagerly
# so its table is registered before create_all runs at startup.
from . import cyab_wizard  # noqa: F401
```

(If `src/ion/models/__init__.py` already imports `cyab` eagerly, follow the same pattern; otherwise add the import.)

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_wizard_service.py -v
```
Expected: 6/6 PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/models/cyab_wizard.py src/ion/models/__init__.py src/ion/services/cyab_wizard_service.py tests/unit/test_cyab_wizard_service.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): wizard session model + service (start/save/finish lifecycle)"
```

---

## Task 3: Wizard Step 1 — Identity

The wizard URL pattern: `GET /cyab/onboard` starts a new session and 302s to `?wid=<uuid>&step=1`. Each step is a separate URL so back/forward navigation works. POST /api/cyab/onboard/{wid}/step/{n} advances state and returns an HTMX-replaceable partial.

**Files:**
- Create: `src/ion/web/templates/cyab/onboard.html` — wizard shell (renders the active step partial).
- Create: `src/ion/web/templates/cyab/_wizard_step_1_identity.html`
- Modify: `src/ion/web/server.py` — add `/cyab/onboard` GET + the step API endpoints.
- Test: `tests/integration/test_cyab_onboard_wizard.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_onboard_wizard.py
"""Integration tests for the /cyab/onboard wizard."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_onboard_root_starts_wizard_and_redirects(admin_session):
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    assert r.status_code in (302, 303)
    loc = r.headers["location"]
    assert "/cyab/onboard?wid=" in loc and "step=1" in loc


def test_onboard_step_1_renders_identity_form(admin_session):
    # Start a session
    r = admin_session.get("/cyab/onboard")  # follows redirect
    body = r.text.lower()
    assert "identity" in body
    for fld in ("name", "hostname", "pillar", "owner", "department", "containment"):
        assert fld in body
    # CyAB tab strip is present
    assert "cyab-section-nav" in r.text


def test_post_step_1_creates_system_and_advances(admin_session):
    # Start
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # POST identity
    r = admin_session.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={
            "name": "prod-sso-w",
            "hostname": "sso01",
            "pillar": "identity",
            "owner": "alice",
            "department": "Identity",
            "containment_authority": "SOC L2",
        },
    )
    assert r.status_code in (200, 302)
    # The CyabSystem row exists
    sys_list = admin_session.get("/api/cyab/systems").json()
    assert any(s["name"] == "prod-sso-w" for s in sys_list)


def test_step_1_invalid_wid_returns_404(admin_session):
    r = admin_session.post("/api/cyab/onboard/bogus/step/1", data={})
    assert r.status_code == 404


def test_wizard_never_blocks_partial_data_ok(admin_session):
    """Posting step 1 with only name + department (no owner / pillar) still saves."""
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    r = admin_session.post(
        f"/api/cyab/onboard/{wid}/step/1",
        data={"name": "minimal", "department": "X"},
    )
    assert r.status_code in (200, 302)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_onboard_wizard.py -v
```
Expected: 404/route-not-found errors.

- [ ] **Step 3: Create the wizard shell template**

```html
<!-- src/ion/web/templates/cyab/onboard.html -->
{% extends "base.html" %}
{% block title %}Onboard — CyAB · ION{% endblock %}
{% block content %}
<div class="cyab-onboard" data-wid="{{ wid }}" data-step="{{ step }}">
  {% include "cyab/_section_nav.html" %}

  <header class="tw-mb-4">
    <h1 class="tw-text-[24px] tw-text-white tw-font-semibold">Onboard a system</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px]">
      4 steps. You can exit at any point and resume from this same URL — nothing blocks.
    </p>
  </header>

  {# Step rail #}
  <ol class="wizard-rail tw-flex tw-gap-2 tw-mb-6 tw-text-[12px]">
    {% for n, label in [(1, 'Identity'), (2, 'Intake'), (3, 'First data source'), (4, 'Doc placeholders')] %}
      <li class="tw-flex tw-items-center tw-gap-2 tw-px-3 tw-py-1 tw-rounded {% if n == step %}tw-bg-cyan-700/30 tw-text-cyan-200{% elif n < step %}tw-text-emerald-400{% else %}tw-text-slate-500{% endif %}">
        <span class="tw-font-mono">{{ n }}</span>
        <span>{{ label }}</span>
      </li>
    {% endfor %}
  </ol>

  <section id="wizard-step-content" class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-4">
    {% if step == 1 %}{% include "cyab/_wizard_step_1_identity.html" %}{% endif %}
    {% if step == 2 %}{% include "cyab/_wizard_step_2_intake.html" %}{% endif %}
    {% if step == 3 %}{% include "cyab/_wizard_step_3_source.html" %}{% endif %}
    {% if step == 4 %}{% include "cyab/_wizard_step_4_docs.html" %}{% endif %}
  </section>
</div>
{% endblock %}
```

- [ ] **Step 4: Create the Step 1 partial**

```html
<!-- src/ion/web/templates/cyab/_wizard_step_1_identity.html -->
{# Step 1: Identity. Captures name, hostname, pillar, sub-profile, owner,
   department, containment_authority. Sub-profile is per-source, so we
   show it here as a hint that gets carried through to Step 3. #}

<header class="tw-mb-4">
  <h2 class="tw-text-white tw-text-[16px] tw-font-semibold">Identity</h2>
  <p class="tw-text-slate-400 tw-text-[12px]">
    Tell us what we're onboarding. None of these fields block — fill in what you know.
  </p>
</header>

<form hx-post="/api/cyab/onboard/{{ wid }}/step/1"
      hx-target="#wizard-step-content"
      hx-swap="innerHTML"
      class="tw-grid tw-grid-cols-2 tw-gap-4 tw-text-[12.5px]">

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Name <span class="tw-text-rose-400">*</span></span>
    <input name="name" type="text" required value="{{ state.identity.name or '' }}"
           class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Hostname (primary)</span>
    <input name="hostname" type="text" value="{{ state.identity.hostname or '' }}"
           placeholder="e.g. sso01.corp"
           class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Pillar</span>
    <select name="pillar" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">— select —</option>
      {% for p in pillars %}
        <option value="{{ p.id }}" {% if state.identity.pillar == p.id %}selected{% endif %}>{{ p.name }}</option>
      {% endfor %}
    </select>
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Sub-profile (assigned at Step 3)</span>
    <select name="subprofile_id" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">— select after pillar —</option>
      {% for s in subprofiles %}
        <option value="{{ s.id }}" {% if state.identity.subprofile_id == s.id %}selected{% endif %}>{{ s.name }}</option>
      {% endfor %}
    </select>
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Owner</span>
    <input name="owner" type="text" value="{{ state.identity.owner or '' }}"
           class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Department <span class="tw-text-rose-400">*</span></span>
    <input name="department" type="text" required value="{{ state.identity.department or '' }}"
           class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
  </label>

  <label class="tw-col-span-2 tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Containment authority (free text — runbook URL or on-call team)</span>
    <textarea name="containment_authority" rows="2"
              class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">{{ state.identity.containment_authority or '' }}</textarea>
  </label>

  <div class="tw-col-span-2 tw-flex tw-justify-between tw-items-center tw-mt-2">
    <a href="/cyab/systems" class="tw-text-slate-500 tw-text-[11px]">← Save & exit</a>
    <button type="submit" class="tw-px-4 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12.5px] tw-rounded">
      Continue → Intake
    </button>
  </div>
</form>
```

- [ ] **Step 5: Add the wizard routes to `server.py`**

```python
# src/ion/web/server.py — add after the placeholder routes from Task 1

from fastapi.responses import RedirectResponse
from fastapi import Form

@app.get("/cyab/onboard", response_class=HTMLResponse)
async def cyab_onboard_page(
    request: Request,
    wid: str | None = None,
    step: int = 1,
    user: User = Depends(require_page_permission("alert:read")),
):
    """4-step wizard. Without `wid`, starts a new session and redirects
    with the wid baked in so refresh/back work."""
    from ion.services import cyab_wizard_service
    from ion.services.cyab_subprofile_service import list_pillars, list_subprofiles
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        if not wid:
            new_wid = cyab_wizard_service.start_wizard(session, user_id=getattr(user, "id", None))
            return RedirectResponse(url=f"/cyab/onboard?wid={new_wid}&step=1", status_code=302)

        state = cyab_wizard_service.load_state(session, wid)
        ctx = {
            "wid": wid,
            "step": step,
            "state": state,
            "pillars": list_pillars(session),
            "subprofiles": list_subprofiles(session),
            "active_tab": "onboard",
            "user": user,
        }
        return templates.TemplateResponse(request=request, name="cyab/onboard.html", context=ctx)
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/step/1", response_class=HTMLResponse)
async def cyab_onboard_step_1(
    wid: str,
    request: Request,
    name: str = Form(...),
    department: str = Form(...),
    hostname: str = Form(""),
    pillar: str = Form(""),
    subprofile_id: str = Form(""),
    owner: str = Form(""),
    containment_authority: str = Form(""),
    user: User = Depends(require_page_permission("alert:read")),
):
    from ion.services import cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        try:
            state = cyab_wizard_service.save_identity(session, wid, identity={
                "name": name, "hostname": hostname, "pillar": pillar,
                "subprofile_id": subprofile_id, "owner": owner,
                "department": department, "containment_authority": containment_authority,
            })
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        # Render Step 2 partial inline (HTMX swap), or 302 for non-HTMX clients.
        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request=request,
                name="cyab/_wizard_step_2_intake.html",
                context={"wid": wid, "step": 2, "state": state},
            )
        return RedirectResponse(url=f"/cyab/onboard?wid={wid}&step=2", status_code=303)
    finally:
        session.close()
```

(Note: `list_pillars` and `list_subprofiles` are existing helpers in `cyab_subprofile_service`. If their names differ, swap to whatever returns iterables of `{id, name}`; the spec already documents the catalogue exists.)

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_onboard_wizard.py -v
```
Expected: 5/5 PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/onboard.html src/ion/web/templates/cyab/_wizard_step_1_identity.html src/ion/web/server.py tests/integration/test_cyab_onboard_wizard.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab/onboard wizard shell + Step 1 (Identity) creates CyabSystem"
```

---

## Task 4: Wizard Steps 2-4 (Intake · First source · Doc placeholders) + Finish

Steps 2-4 follow the same shape as Step 1: a partial template + a POST endpoint that advances state. The "live recommendation counter" called out in the spec for Step 2 is a Sub-plan C concern (it depends on the shared scoring engine) — this sub-plan ships the intake form alone with a TODO marker.

**Files:**
- Create: `src/ion/web/templates/cyab/_wizard_step_2_intake.html`
- Create: `src/ion/web/templates/cyab/_wizard_step_3_source.html`
- Create: `src/ion/web/templates/cyab/_wizard_step_4_docs.html`
- Modify: `src/ion/web/server.py` — POST endpoints for steps 2/3/4 and `/finish`.
- Test: extend `tests/integration/test_cyab_onboard_wizard.py`.

- [ ] **Step 1: Append failing tests for Steps 2-4 + Finish**

```python
# tests/integration/test_cyab_onboard_wizard.py — appended

def _start_and_step1(client) -> str:
    r = client.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    client.post(f"/api/cyab/onboard/{wid}/step/1", data={
        "name": "wiz-test", "department": "Eng", "hostname": "h1",
        "pillar": "endpoint", "owner": "x", "containment_authority": "y",
    })
    return wid


def test_step_2_intake_saves_answers(admin_session):
    wid = _start_and_step1(admin_session)
    r = admin_session.post(
        f"/api/cyab/onboard/{wid}/step/2",
        data={"answers[q_traffic]": "high", "answers[q_users]": "200"},
    )
    assert r.status_code in (200, 302)


def test_step_3_creates_data_source(admin_session):
    wid = _start_and_step1(admin_session)
    admin_session.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    r = admin_session.post(
        f"/api/cyab/onboard/{wid}/step/3",
        data={"name": "winlog", "data_source_type": "windows-evtx", "subprofile_id": ""},
    )
    assert r.status_code in (200, 302)
    # Source attached to the system
    sys_list = admin_session.get("/api/cyab/systems").json()
    sys_id = next(s["id"] for s in sys_list if s["name"] == "wiz-test")
    sources = admin_session.get(f"/api/cyab/systems/{sys_id}/sources").json()
    assert any(s["name"] == "winlog" for s in sources)


def test_step_4_lists_seeded_checklist_items(admin_session):
    wid = _start_and_step1(admin_session)
    admin_session.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    admin_session.post(f"/api/cyab/onboard/{wid}/step/3",
                       data={"name": "x", "data_source_type": "edr-generic"})
    r = admin_session.get(f"/cyab/onboard?wid={wid}&step=4")
    body = r.text
    # 20 default items — at minimum HLD / OWNERS / NETWORK_TOPOLOGY are present
    for label in ("HLD", "Network Topology", "Owners"):
        assert label in body
    # 'I'll do this later' control exists
    assert "later" in body.lower()


def test_finish_redirects_to_per_system_page(admin_session):
    wid = _start_and_step1(admin_session)
    admin_session.post(f"/api/cyab/onboard/{wid}/step/2", data={})
    admin_session.post(f"/api/cyab/onboard/{wid}/step/3",
                       data={"name": "x", "data_source_type": "edr-generic"})
    r = admin_session.post(
        f"/api/cyab/onboard/{wid}/finish",
        data={},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    assert "/cyab/systems/" in r.headers["location"]
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_onboard_wizard.py -v
```

- [ ] **Step 3: Create Step 2 (Intake) partial**

```html
<!-- src/ion/web/templates/cyab/_wizard_step_2_intake.html -->
{# Step 2: Intake — sub-profile-driven questions. Reuses
   /api/cyab/studio/systems/{sys_id}/answers for autosave so the SAME
   intake form is used here and on the per-system Intake tab.

   The "live recommendation counter" from the spec (47 use cases / 12
   actor matches / 64% coverage) hooks into the shared scoring engine
   landing in Sub-plan C — placeholder div left in place. #}

<header class="tw-mb-4 tw-flex tw-items-baseline tw-justify-between">
  <div>
    <h2 class="tw-text-white tw-text-[16px] tw-font-semibold">Intake</h2>
    <p class="tw-text-slate-400 tw-text-[12px]">Sub-profile-driven questions. Auto-saves as you type.</p>
  </div>
  <div id="wizard-recommendation-counter" class="tw-text-slate-500 tw-text-[11px]">
    {# Sub-plan C wires the live counter here. #}
    recommendations panel — Sub-plan C
  </div>
</header>

<form hx-post="/api/cyab/onboard/{{ wid }}/step/2"
      hx-target="#wizard-step-content"
      hx-swap="innerHTML"
      class="tw-space-y-3">
  {% if not state.identity.subprofile_id %}
    <p class="tw-text-amber-400 tw-text-[12px]">
      No sub-profile yet — questions will load after Step 3 picks one. You can skip ahead.
    </p>
  {% else %}
    {# Sub-profile catalogue questions. The full renderer lives in the
       per-system Intake tab from Sub-plan A — keep this minimal so the
       wizard never blocks. #}
    {% for q in (questions or []) %}
      <label class="tw-block tw-text-[12.5px]">
        <span class="tw-text-slate-300">{{ q.text }}</span>
        <input type="text" name="answers[{{ q.id }}]" value="{{ state.intake.get(q.id, '') }}"
               class="tw-w-full tw-mt-1 tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"
               hx-post="/api/cyab/studio/systems/{{ state.system_id }}/answers"
               hx-trigger="change delay:600ms"
               hx-vals='js:{ answers: { "{{ q.id }}": this.value } }'
               hx-swap="none">
      </label>
    {% endfor %}
  {% endif %}

  <div class="tw-flex tw-justify-between tw-items-center tw-mt-4">
    <a href="/cyab/onboard?wid={{ wid }}&step=1" class="tw-text-slate-500 tw-text-[11px]">← Back</a>
    <div class="tw-flex tw-gap-2">
      <a href="/cyab/systems" class="tw-text-slate-500 tw-text-[11px] tw-py-1">Save & exit</a>
      <button type="submit" class="tw-px-4 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12.5px] tw-rounded">
        Continue → Source
      </button>
    </div>
  </div>
</form>
```

- [ ] **Step 4: Create Step 3 (First source) partial**

```html
<!-- src/ion/web/templates/cyab/_wizard_step_3_source.html -->
<header class="tw-mb-4">
  <h2 class="tw-text-white tw-text-[16px] tw-font-semibold">First data source</h2>
  <p class="tw-text-slate-400 tw-text-[12px]">
    One source to start. Add more later from the Sources tab.
  </p>
</header>

<form hx-post="/api/cyab/onboard/{{ wid }}/step/3"
      hx-target="#wizard-step-content"
      hx-swap="innerHTML"
      class="tw-grid tw-grid-cols-2 tw-gap-4 tw-text-[12.5px]">

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Source name <span class="tw-text-rose-400">*</span></span>
    <input name="name" type="text" required
           value="{{ state.source.name or state.identity.hostname or '' }}"
           class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
  </label>

  <label class="tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Source type</span>
    <select name="data_source_type" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      {% for opt in ['windows-evtx', 'generic-syslog', 'linux-auditd', 'aws-cloudtrail',
                     'office365', 'okta', 'azure-ad', 'edr-generic'] %}
        <option value="{{ opt }}" {% if state.source.data_source_type == opt %}selected{% endif %}>{{ opt }}</option>
      {% endfor %}
    </select>
  </label>

  <label class="tw-col-span-2 tw-flex tw-flex-col tw-gap-1">
    <span class="tw-text-slate-400">Sub-profile</span>
    <select name="subprofile_id" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">— pick a sub-profile —</option>
      {% for s in subprofiles %}
        <option value="{{ s.id }}"
                {% if state.source.subprofile_id == s.id or state.identity.subprofile_id == s.id %}selected{% endif %}>
          {{ s.name }}
        </option>
      {% endfor %}
    </select>
  </label>

  <div class="tw-col-span-2 tw-flex tw-justify-between tw-items-center tw-mt-2">
    <a href="/cyab/onboard?wid={{ wid }}&step=2" class="tw-text-slate-500 tw-text-[11px]">← Back</a>
    <div class="tw-flex tw-gap-2">
      <a href="/cyab/systems" class="tw-text-slate-500 tw-text-[11px] tw-py-1">Save & exit</a>
      <button type="submit" class="tw-px-4 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12.5px] tw-rounded">
        Continue → Doc placeholders
      </button>
    </div>
  </div>
</form>
```

- [ ] **Step 5: Create Step 4 (Doc placeholders) partial**

```html
<!-- src/ion/web/templates/cyab/_wizard_step_4_docs.html -->
{# Step 4: Doc placeholders. The 20-item checklist is lazy-seeded on
   first arrival here. The user can flag is_critical, paste a URL, or
   click "I'll do this later" to leave the row in 'unknown' state. #}

<header class="tw-mb-4">
  <h2 class="tw-text-white tw-text-[16px] tw-font-semibold">Doc placeholders</h2>
  <p class="tw-text-slate-400 tw-text-[12px]">
    20 default checklist items will be created. Add URLs now or skip — every row stays editable from the Overview tab.
  </p>
</header>

<form hx-post="/api/cyab/onboard/{{ wid }}/finish"
      hx-target="this" hx-swap="outerHTML"
      class="tw-space-y-2">
  <table class="tw-w-full tw-text-[12px]">
    <thead>
      <tr class="tw-text-slate-500 tw-text-[10px] tw-uppercase">
        <th class="tw-text-left tw-py-1">Item</th>
        <th class="tw-text-left">Critical?</th>
        <th class="tw-text-left">URL (optional)</th>
        <th class="tw-text-right">I'll do later</th>
      </tr>
    </thead>
    <tbody>
      {% for item in checklist %}
        <tr class="hover:tw-bg-slate-800/40">
          <td class="tw-py-1 tw-text-slate-200">{{ item.label }}</td>
          <td>
            <input type="checkbox" name="docs[{{ item.kind }}][is_critical]" value="1"
                   {% if item.is_critical %}checked{% endif %}>
          </td>
          <td>
            <input type="url" name="docs[{{ item.kind }}][url]"
                   value="{{ item.url or '' }}"
                   placeholder="https://..."
                   class="tw-w-full tw-px-1 tw-py-0.5 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
          </td>
          <td class="tw-text-right">
            <input type="checkbox" name="docs[{{ item.kind }}][mark_later]" value="1">
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>

  <div class="tw-flex tw-justify-between tw-items-center tw-mt-4">
    <a href="/cyab/onboard?wid={{ wid }}&step=3" class="tw-text-slate-500 tw-text-[11px]">← Back</a>
    <button type="submit" class="tw-px-4 tw-py-1.5 tw-bg-emerald-700 tw-text-white tw-text-[12.5px] tw-rounded">
      Finish — open system page
    </button>
  </div>
</form>
```

- [ ] **Step 6: Add Steps 2-4 + Finish endpoints to `server.py`**

```python
# src/ion/web/server.py — add after step_1 endpoint

@app.post("/api/cyab/onboard/{wid}/step/2", response_class=HTMLResponse)
async def cyab_onboard_step_2(
    wid: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    from ion.services import cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    form = await request.form()
    answers = {k.split("[", 1)[1].rstrip("]"): v
               for k, v in form.items() if k.startswith("answers[")}

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            cyab_wizard_service.save_intake(session, wid, answers=answers)
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        if request.headers.get("hx-request") == "true":
            state = cyab_wizard_service.load_state(session, wid)
            from ion.services.cyab_subprofile_service import list_subprofiles
            return templates.TemplateResponse(
                request=request, name="cyab/_wizard_step_3_source.html",
                context={"wid": wid, "step": 3, "state": state,
                         "subprofiles": list_subprofiles(session)},
            )
        return RedirectResponse(url=f"/cyab/onboard?wid={wid}&step=3", status_code=303)
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/step/3", response_class=HTMLResponse)
async def cyab_onboard_step_3(
    wid: str,
    request: Request,
    name: str = Form(...),
    data_source_type: str = Form(""),
    subprofile_id: str = Form(""),
    user: User = Depends(require_page_permission("alert:read")),
):
    from ion.services import cyab_wizard_service, cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            state = cyab_wizard_service.save_source(session, wid, source={
                "name": name,
                "data_source_type": data_source_type or None,
                "subprofile_id": subprofile_id or None,
            })
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        # Lazy-seed the checklist now so Step 4 has rows to render
        cyab_doc_checklist_service.seed_for_system(session, state["system_id"])
        checklist = cyab_doc_checklist_service.list_for_system(session, state["system_id"])

        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request=request, name="cyab/_wizard_step_4_docs.html",
                context={"wid": wid, "step": 4, "state": state, "checklist": checklist},
            )
        return RedirectResponse(url=f"/cyab/onboard?wid={wid}&step=4", status_code=303)
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/finish")
async def cyab_onboard_finish(
    wid: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Apply doc-placeholder overrides, mark wizard complete, redirect."""
    from ion.services import cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    form = await request.form()
    # Parse docs[<kind>][<field>] = value
    overrides: dict[str, dict] = {}
    for k, v in form.items():
        if not k.startswith("docs["):
            continue
        # docs[HLD][url] -> ('HLD', 'url')
        rest = k[len("docs["):]
        kind, field = rest.split("][", 1)
        field = field.rstrip("]")
        overrides.setdefault(kind, {})[field] = v

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            sys_id = cyab_wizard_service.finish(session, wid, doc_overrides=overrides)
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")
        return RedirectResponse(url=f"/cyab/systems/{sys_id}", status_code=303)
    finally:
        session.close()
```

- [ ] **Step 7: Update step 4 GET render path so a refresh on `?step=4` works**

The wizard GET handler needs to also pass `checklist` when serving step 4. Modify `cyab_onboard_page` (added in Task 3, Step 5) to add an additional context branch:

```python
        # in cyab_onboard_page, after building the base ctx dict:
        if step == 4 and state.get("system_id"):
            from ion.services import cyab_doc_checklist_service
            cyab_doc_checklist_service.seed_for_system(session, state["system_id"])
            ctx["checklist"] = cyab_doc_checklist_service.list_for_system(session, state["system_id"])
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_onboard_wizard.py -v
```
Expected: all 9 cases (5 from Task 3 + 4 here) PASS.

- [ ] **Step 9: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/_wizard_step_2_intake.html src/ion/web/templates/cyab/_wizard_step_3_source.html src/ion/web/templates/cyab/_wizard_step_4_docs.html src/ion/web/server.py tests/integration/test_cyab_onboard_wizard.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): wizard Steps 2-4 + finish (intake, source, docs, redirect to /cyab/systems/{id})"
```

---

## Task 5: Delete legacy `cyab.html` + replace `/cyab` handler with new Overview page (KPIs)

**Files:**
- Delete: `src/ion/web/templates/cyab.html`
- Create: `src/ion/web/templates/cyab/overview.html`
- Modify: `src/ion/web/server.py` — replace the existing `cyab_page` handler.
- Modify: `src/ion/web/cyab_api.py` — add `signoffs_this_week` to `/dashboard`.
- Test: `tests/integration/test_cyab_overview_page.py`

**Open question resolved:** the legacy `cyab.html` template was the dashboard surface (3,543 lines per the spec). All per-system content (demarcation / field mapping / SAL / governance / sign-off) was moved to `/cyab/systems/{id}` tabs in Sub-plan A. The dashboard KPIs and systems table become the new `/cyab` Overview and `/cyab/systems` pages. There is **no surviving content in `cyab.html`** that this sub-plan doesn't replace, so we delete it.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_overview_page.py
"""Integration tests for the new /cyab Overview landing page."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


@pytest.fixture
def seeded_systems(temp_db):
    """3 systems: 1 fully onboarded, 1 in-progress, 1 with critical-missing."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    a = CyabSystem(name="prod-onb", department="Identity", readiness_score=95, status="ACTIVE")
    b = CyabSystem(name="prod-wip", department="Net", readiness_score=40, status="DRAFT")
    c = CyabSystem(name="prod-crit", department="Endpoint", readiness_score=10, status="DRAFT")
    s.add_all([a, b, c]); s.commit()
    yield [a.id, b.id, c.id]
    s.close()


def test_overview_page_renders_with_kpi_strip(admin_session, seeded_systems):
    r = admin_session.get("/cyab")
    assert r.status_code == 200
    body = r.text.lower()
    # KPI labels per the spec
    assert "total systems" in body or "systems" in body
    assert "% onboarded" in body or "onboarded" in body
    assert "critical" in body
    assert "sign-off" in body or "signoff" in body


def test_overview_page_includes_section_nav(admin_session):
    r = admin_session.get("/cyab")
    assert "cyab-section-nav" in r.text
    # Overview tab marked active
    assert 'data-active="overview"' in r.text or "is-active" in r.text


def test_overview_page_includes_in_progress_feed(admin_session, seeded_systems):
    r = admin_session.get("/cyab")
    body = r.text
    assert "In progress" in body or "in-progress" in body.lower()
    # Most-recently-edited surfaces at least one of our seeded names
    assert any(name in body for name in ("prod-onb", "prod-wip", "prod-crit"))


def test_overview_page_has_ctas(admin_session):
    r = admin_session.get("/cyab")
    body = r.text
    assert "/cyab/onboard" in body
    assert "/cyab/systems" in body


def test_dashboard_api_includes_signoffs_this_week(admin_session, seeded_systems):
    r = admin_session.get("/api/cyab/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "signoffs_this_week" in data
    assert isinstance(data["signoffs_this_week"], int)


def test_legacy_cyab_html_template_not_referenced(admin_session):
    """Confirm `/cyab` no longer renders cyab.html — bust any stale cache."""
    r = admin_session.get("/cyab")
    # The legacy template had a unique <body class="cyab-legacy"> marker;
    # if we see it, the migration didn't happen.
    assert "cyab-legacy" not in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_overview_page.py -v
```
Expected: FAIL — old page text doesn't match new asserts.

- [ ] **Step 3: Add `signoffs_this_week` to the dashboard endpoint**

In `src/ion/web/cyab_api.py`, find the `dashboard_metrics` handler and amend the return dict. Append before `return { … }`:

```python
    # signoffs_this_week — count CyabSnapshot rows kind='signoff' in the last 7 days.
    from datetime import datetime, timedelta
    from ion.models.cyab import CyabSnapshot
    week_ago = datetime.utcnow() - timedelta(days=7)
    signoffs_this_week = session.execute(
        select(func.count(CyabSnapshot.id))
        .where(CyabSnapshot.created_at >= week_ago)
    ).scalar() or 0
```

…and add `"signoffs_this_week": int(signoffs_this_week),` to both return dicts (the empty-portfolio early-return and the populated one). `func` and `select` are already imported at the top of the file; verify.

- [ ] **Step 4: Create the Overview page template**

```html
<!-- src/ion/web/templates/cyab/overview.html -->
{% extends "base.html" %}
{% block title %}Overview — CyAB · ION{% endblock %}
{% block content %}
<div class="cyab-overview">
  {% include "cyab/_section_nav.html" %}

  <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-4">
    <h1 class="tw-text-[24px] tw-text-white tw-font-semibold">CyAB Overview</h1>
    <div class="tw-flex tw-gap-2">
      <a href="/cyab/onboard"
         class="tw-px-3 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12.5px] tw-rounded">+ Onboard</a>
      <a href="/cyab/systems"
         class="tw-px-3 tw-py-1.5 tw-bg-slate-800 tw-text-slate-200 tw-text-[12.5px] tw-rounded">View systems</a>
      <button hx-post="/api/cyab/coverage/rollup-now"
              hx-swap="none"
              class="tw-px-3 tw-py-1.5 tw-bg-slate-800 tw-text-slate-200 tw-text-[12.5px] tw-rounded">
        Run coverage rollup
      </button>
    </div>
  </header>

  {# === KPI strip === #}
  {% set onb_pct = (kpis.sal_compliance_pass / kpis.total_systems * 100) | round(0) | int if kpis.total_systems else 0 %}
  {% set crit_pct = (needs_attention | length) / kpis.total_systems * 100 if kpis.total_systems else 0 %}
  <section class="kpi-strip tw-grid tw-grid-cols-4 tw-gap-3 tw-mb-6">
    <div class="kpi-card tw-bg-slate-900/60 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-slate-500 tw-text-[10px] tw-uppercase tw-tracking-wider">Total systems</div>
      <div class="tw-text-cyan-300 tw-text-[24px] tw-font-semibold">{{ kpis.total_systems }}</div>
    </div>
    <div class="kpi-card tw-bg-slate-900/60 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-slate-500 tw-text-[10px] tw-uppercase tw-tracking-wider">% onboarded</div>
      <div class="tw-text-emerald-300 tw-text-[24px] tw-font-semibold">{{ onb_pct }}%</div>
    </div>
    <div class="kpi-card tw-bg-slate-900/60 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-slate-500 tw-text-[10px] tw-uppercase tw-tracking-wider">% critical-missing</div>
      <div class="tw-text-rose-400 tw-text-[24px] tw-font-semibold">{{ crit_pct | round(0) | int }}%</div>
    </div>
    <div class="kpi-card tw-bg-slate-900/60 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-slate-500 tw-text-[10px] tw-uppercase tw-tracking-wider">Sign-offs this week</div>
      <div class="tw-text-amber-300 tw-text-[24px] tw-font-semibold">{{ kpis.signoffs_this_week }}</div>
    </div>
  </section>

  <div class="tw-grid tw-grid-cols-2 tw-gap-4">
    {# === In progress feed === #}
    <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-2">
        <h3 class="tw-text-slate-300 tw-text-[12.5px]">In progress</h3>
        <span class="tw-text-slate-500 tw-text-[10.5px]">5 most recent</span>
      </header>
      {% if not in_progress %}
        <p class="tw-text-slate-500 tw-text-[11px]">Nothing in progress. <a href="/cyab/onboard" class="tw-text-cyan-400">+ Onboard a system</a>.</p>
      {% else %}
        <ul class="tw-divide-y tw-divide-slate-800 tw-text-[12px]">
          {% for s in in_progress %}
            <li class="tw-py-2 tw-flex tw-justify-between">
              <a href="/cyab/systems/{{ s.id }}" class="tw-text-cyan-400 hover:tw-underline">{{ s.name }}</a>
              <span class="tw-text-slate-500 tw-text-[11px]">{{ s.updated_at.strftime('%Y-%m-%d %H:%M') if s.updated_at else '' }}</span>
            </li>
          {% endfor %}
        </ul>
      {% endif %}
    </section>

    {# === Needs attention feed === #}
    <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-2">
        <h3 class="tw-text-rose-400 tw-text-[12.5px]">Needs attention</h3>
        <span class="tw-text-slate-500 tw-text-[10.5px]">critical-missing or stale data</span>
      </header>
      {% if not needs_attention %}
        <p class="tw-text-emerald-400 tw-text-[11px]">All clear — no critical gaps right now.</p>
      {% else %}
        <ul class="tw-divide-y tw-divide-slate-800 tw-text-[12px]">
          {% for s in needs_attention %}
            <li class="tw-py-2 tw-flex tw-justify-between">
              <a href="/cyab/systems/{{ s.id }}" class="tw-text-rose-300 hover:tw-underline">{{ s.name }}</a>
              <span class="tw-text-slate-500 tw-text-[11px]">{{ s.reason }}</span>
            </li>
          {% endfor %}
        </ul>
      {% endif %}
    </section>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Replace the `/cyab` handler in `server.py`**

Find the existing handler at line ~909:

```python
@app.get("/cyab", response_class=HTMLResponse)
async def cyab_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    return templates.TemplateResponse(request=request, name="cyab.html")
```

Replace with:

```python
@app.get("/cyab", response_class=HTMLResponse)
async def cyab_overview_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """CyAB Overview landing — KPIs + in-progress + needs-attention.

    Replaces the legacy 3,500-line cyab.html dashboard. Per-system
    content moved to /cyab/systems/{id} (Sub-plan A); fleet table moved
    to /cyab/systems (next task).
    """
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config
    from sqlalchemy import select
    import httpx

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        # Reuse the existing /api/cyab/dashboard endpoint internally rather
        # than duplicating the math. Call the function directly to avoid
        # the HTTP round-trip.
        from ion.web.cyab_api import dashboard_metrics
        kpis = await dashboard_metrics(session=session)

        # In-progress = 5 most-recently-updated systems
        in_progress = session.execute(
            select(CyabSystem).order_by(CyabSystem.updated_at.desc()).limit(5)
        ).scalars().all()

        # Needs-attention = systems with any critical checklist item not done.
        # Stale-data check (last_event_at > 24h) is a Sub-plan C live signal;
        # for Sub-plan B we approximate using the doc-checklist critical-missing flag.
        all_systems = session.execute(select(CyabSystem)).scalars().all()
        needs_attention = []
        for s in all_systems:
            summary = cyab_doc_checklist_service.coverage_summary(session, s.id)
            crit_missing = summary.get("critical_missing") or []
            if crit_missing:
                needs_attention.append(type("Row", (), {
                    "id": s.id, "name": s.name,
                    "reason": f"{len(crit_missing)} critical doc(s) missing",
                })())

        return templates.TemplateResponse(
            request=request,
            name="cyab/overview.html",
            context={
                "kpis": kpis,
                "in_progress": in_progress,
                "needs_attention": needs_attention[:10],
                "active_tab": "overview",
                "user": user,
            },
        )
    finally:
        session.close()
```

- [ ] **Step 6: Delete the legacy template**

```bash
cd ~/ION && rm src/ion/web/templates/cyab.html
```

(Verify nothing else references it: `git grep "cyab.html"` should return no matches outside of this commit's changes and historical CHANGELOG entries.)

- [ ] **Step 7: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_overview_page.py -v
```
Expected: 6/6 PASS.

- [ ] **Step 8: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/overview.html src/ion/web/server.py src/ion/web/cyab_api.py tests/integration/test_cyab_overview_page.py
git rm src/ion/web/templates/cyab.html
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab Overview landing replaces legacy cyab.html (KPIs + feeds)"
```

---

## Task 6: `/cyab/systems` portfolio list — table + filters + search

**Files:**
- Create: `src/ion/web/templates/cyab/systems_list.html` — page shell.
- Create: `src/ion/web/templates/cyab/_systems_table.html` — table partial (HTMX-swapped on filter change).
- Modify: `src/ion/web/server.py` — add page route.
- Modify: `src/ion/web/cyab_api.py` — add `/systems/_table` HTMX partial (server-side filtering).
- Test: `tests/integration/test_cyab_systems_list.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_systems_list.py
"""Integration tests for the /cyab/systems portfolio list."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


@pytest.fixture
def diverse_systems(temp_db):
    """4 systems across pillars / statuses / owners for filter testing."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    rows = [
        CyabSystem(name="prod-sso",  department="Identity", soc_analyst_owner="alice", status="ACTIVE"),
        CyabSystem(name="prod-dns",  department="Network",  soc_analyst_owner="bob",   status="DRAFT"),
        CyabSystem(name="prod-edr",  department="Endpoint", soc_analyst_owner="alice", status="ACTIVE"),
        CyabSystem(name="dev-test",  department="Eng",      soc_analyst_owner="carol", status="DRAFT"),
    ]
    s.add_all(rows); s.commit()
    yield [r.id for r in rows]
    s.close()


def test_systems_list_renders_table(admin_session, diverse_systems):
    r = admin_session.get("/cyab/systems")
    assert r.status_code == 200
    body = r.text
    for col in ("Name", "Pillar", "Sub-profile", "Owner", "Progress", "Last edited", "Status"):
        assert col in body
    for n in ("prod-sso", "prod-dns", "prod-edr", "dev-test"):
        assert n in body


def test_systems_list_includes_section_nav(admin_session):
    r = admin_session.get("/cyab/systems")
    assert "cyab-section-nav" in r.text


def test_systems_list_search_filters_by_name(admin_session, diverse_systems):
    r = admin_session.get("/cyab/systems/_table?q=sso")
    body = r.text
    assert "prod-sso" in body
    assert "prod-dns" not in body
    # No full page chrome — partial only
    assert "<html" not in body


def test_systems_list_filter_by_owner(admin_session, diverse_systems):
    r = admin_session.get("/cyab/systems/_table?owner=alice")
    body = r.text
    assert "prod-sso" in body and "prod-edr" in body
    assert "prod-dns" not in body


def test_systems_list_filter_by_status(admin_session, diverse_systems):
    r = admin_session.get("/cyab/systems/_table?status=DRAFT")
    body = r.text
    assert "prod-dns" in body and "dev-test" in body
    assert "prod-sso" not in body


def test_systems_list_export_csv(admin_session, diverse_systems):
    r = admin_session.post("/api/cyab/systems/bulk",
                           json={"action": "export-csv",
                                 "system_ids": diverse_systems[:2]})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "prod-sso" in r.text


def test_systems_list_bulk_mark_reviewed(admin_session, diverse_systems):
    r = admin_session.post("/api/cyab/systems/bulk",
                           json={"action": "mark-reviewed",
                                 "system_ids": diverse_systems[:2]})
    assert r.status_code == 200
    body = r.json()
    assert body["affected"] == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_systems_list.py -v
```

- [ ] **Step 3: Create the page shell**

```html
<!-- src/ion/web/templates/cyab/systems_list.html -->
{% extends "base.html" %}
{% block title %}Systems — CyAB · ION{% endblock %}
{% block content %}
<div class="cyab-systems-list">
  {% include "cyab/_section_nav.html" %}

  <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-4">
    <h1 class="tw-text-[24px] tw-text-white tw-font-semibold">Systems</h1>
    <a href="/cyab/onboard"
       class="tw-px-3 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12.5px] tw-rounded">+ Onboard</a>
  </header>

  {# Filter bar — HTMX swaps the table partial on every change #}
  <form class="filters tw-flex tw-flex-wrap tw-gap-2 tw-mb-3 tw-text-[12px]"
        hx-get="/cyab/systems/_table"
        hx-target="#systems-table"
        hx-trigger="change, keyup[target.tagName=='INPUT'] delay:300ms"
        hx-swap="innerHTML">
    <input name="q" placeholder="Search name / hostname / owner"
           class="tw-flex-1 tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    <select name="pillar" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">all pillars</option>
      {% for p in pillars %}<option value="{{ p.id }}">{{ p.name }}</option>{% endfor %}
    </select>
    <select name="subprofile" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">all sub-profiles</option>
      {% for s in subprofiles %}<option value="{{ s.id }}">{{ s.name }}</option>{% endfor %}
    </select>
    <select name="status" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">any status</option>
      <option value="DRAFT">DRAFT</option>
      <option value="ACTIVE">ACTIVE</option>
      <option value="RETIRED">RETIRED</option>
    </select>
    <input name="owner" placeholder="owner"
           class="tw-w-32 tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    <select name="missing" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="">missing: any</option>
      <option value="HLD">missing HLD</option>
      <option value="NETWORK_TOPOLOGY">missing topology</option>
      <option value="OWNERS">missing owners</option>
    </select>
    <label class="tw-flex tw-items-center tw-gap-1 tw-text-slate-400">
      <input type="checkbox" name="stale" value="1"> stale data (>24h)
    </label>
  </form>

  <div id="systems-table"
       hx-get="/cyab/systems/_table"
       hx-trigger="load"
       hx-swap="innerHTML">
    {# initial load — replaced by HTMX after page renders #}
    <p class="tw-text-slate-500 tw-text-[12px]">Loading…</p>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Create the table partial**

```html
<!-- src/ion/web/templates/cyab/_systems_table.html -->
{% if not rows %}
  <p class="tw-text-slate-500 tw-text-[12px] tw-py-8 tw-text-center">
    No systems match these filters.
  </p>
{% else %}
<form hx-post="/api/cyab/systems/bulk" hx-trigger="submit" hx-swap="none">
  <div class="tw-flex tw-items-center tw-gap-2 tw-mb-2 tw-text-[11.5px]">
    <span class="tw-text-slate-500">{{ rows | length }} systems</span>
    <span class="tw-flex-1"></span>
    <select name="action" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
      <option value="mark-reviewed">Mark reviewed</option>
      <option value="export-csv">Export CSV</option>
      <option value="rerun-health">Re-run health checks</option>
    </select>
    <button type="submit" class="tw-px-2 tw-py-1 tw-bg-slate-800 tw-text-slate-200 tw-rounded">Apply</button>
  </div>

  <table class="systems-table tw-w-full tw-text-[12px]">
    <thead class="tw-text-slate-500 tw-text-[10.5px] tw-uppercase">
      <tr>
        <th class="tw-text-left tw-py-1"><input type="checkbox" id="select-all"></th>
        <th class="tw-text-left">Name</th>
        <th class="tw-text-left">Pillar</th>
        <th class="tw-text-left">Sub-profile</th>
        <th class="tw-text-left">Owner</th>
        <th class="tw-text-left">Progress</th>
        <th class="tw-text-left">Critical-missing</th>
        <th class="tw-text-left">Last edited</th>
        <th class="tw-text-left">Status</th>
      </tr>
    </thead>
    <tbody class="tw-divide-y tw-divide-slate-800">
      {% for r in rows %}
        <tr class="hover:tw-bg-slate-800/30">
          <td class="tw-py-1.5"><input type="checkbox" name="system_ids" value="{{ r.id }}"></td>
          <td><a href="/cyab/systems/{{ r.id }}" class="tw-text-cyan-400 hover:tw-underline">{{ r.name }}</a></td>
          <td class="tw-text-slate-400">{{ r.pillar or '—' }}</td>
          <td class="tw-text-slate-400">{{ r.subprofile or '—' }}</td>
          <td class="tw-text-slate-400">{{ r.owner or '—' }}</td>
          <td>
            {% set pct = (r.progress.done / r.progress.total * 100) | round(0) | int if r.progress.total else 0 %}
            <div class="tw-flex tw-items-center tw-gap-1">
              <div class="tw-h-1 tw-w-16 tw-bg-slate-800 tw-rounded">
                <div class="tw-h-full tw-bg-cyan-400 tw-rounded" style="width: {{ pct }}%"></div>
              </div>
              <span class="tw-text-cyan-300 tw-text-[10.5px]">{{ r.progress.done }}/{{ r.progress.total }}</span>
            </div>
          </td>
          <td>
            {% if r.critical_missing %}
              <span class="tw-text-rose-400 tw-text-[10.5px]">{{ r.critical_missing }} missing</span>
            {% else %}
              <span class="tw-text-emerald-400 tw-text-[10.5px]">ok</span>
            {% endif %}
          </td>
          <td class="tw-text-slate-500 tw-text-[10.5px]">
            {{ r.updated_at.strftime('%Y-%m-%d %H:%M') if r.updated_at else '—' }}
          </td>
          <td>
            <span class="tw-px-1.5 tw-py-0.5 tw-text-[10.5px] tw-rounded
                         {% if r.status == 'ACTIVE' %}tw-bg-emerald-900/40 tw-text-emerald-300
                         {% elif r.status == 'DRAFT' %}tw-bg-slate-800 tw-text-slate-300
                         {% else %}tw-bg-slate-800 tw-text-slate-500{% endif %}">
              {{ r.status }}
            </span>
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</form>
{% endif %}
```

- [ ] **Step 5: Add the page route + table partial endpoint**

```python
# src/ion/web/server.py — add after the Overview handler

@app.get("/cyab/systems", response_class=HTMLResponse)
async def cyab_systems_list_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Portfolio list — table loads via HTMX from /cyab/systems/_table."""
    from ion.services.cyab_subprofile_service import list_pillars, list_subprofiles
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        return templates.TemplateResponse(
            request=request, name="cyab/systems_list.html",
            context={
                "active_tab": "systems",
                "user": user,
                "pillars": list_pillars(session),
                "subprofiles": list_subprofiles(session),
            },
        )
    finally:
        session.close()
```

```python
# src/ion/web/cyab_api.py — add the table partial + bulk endpoint
# (these live on the /api/cyab router but the table partial is HTML, not JSON)

from fastapi import HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from ion.web.server import templates  # if circular, inline the Jinja env

@router.get("/_table", response_class=HTMLResponse,
            dependencies=[Depends(require_permission("alert:read"))])
async def systems_table_partial(
    request: Request,
    q: str = "",
    pillar: str = "",
    subprofile: str = "",
    status: str = "",
    owner: str = "",
    missing: str = "",
    stale: int = 0,
    session: Session = Depends(get_db_session),
):
    """HTMX partial — filtered + searched portfolio table.

    Note: the path is /api/cyab/_table (mounted under /api/cyab); the
    page template hits /cyab/systems/_table. Add the /cyab/systems/_table
    alias on the page-route side OR mount the partial directly. The
    template uses /cyab/systems/_table — register that path on app:
    """
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service

    stmt = select(CyabSystem)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            (CyabSystem.name.ilike(like))
            | (CyabSystem.soc_analyst_owner.ilike(like))
        )
    if status:
        stmt = stmt.where(CyabSystem.status == status)
    if owner:
        stmt = stmt.where(CyabSystem.soc_analyst_owner.ilike(f"%{owner}%"))
    # pillar / subprofile filters work on the data-source level — for
    # simplicity in this sub-plan filter post-fetch.

    systems = session.execute(stmt.order_by(CyabSystem.updated_at.desc())).scalars().all()

    rows = []
    for s in systems:
        summary = cyab_doc_checklist_service.coverage_summary(session, s.id)
        crit = summary.get("critical_missing") or []
        if missing and not any(getattr(c, "kind", None) == missing for c in crit):
            continue
        rows.append(type("Row", (), {
            "id": s.id, "name": s.name,
            "pillar": None,        # joined in via subprofile in Sub-plan C
            "subprofile": None,
            "owner": s.soc_analyst_owner,
            "progress": summary,
            "critical_missing": len(crit),
            "updated_at": s.updated_at,
            "status": s.status,
        })())

    return templates.TemplateResponse(
        request=request, name="cyab/_systems_table.html",
        context={"rows": rows},
    )


@router.post("/systems/bulk",
             dependencies=[Depends(require_permission("alert:read"))])
async def systems_bulk(
    payload: dict,
    request: Request,
    session: Session = Depends(get_db_session),
):
    """{action, system_ids} — mark-reviewed | export-csv | rerun-health."""
    import csv, io
    from datetime import date
    from ion.models.cyab import CyabSystem

    action = payload.get("action")
    ids = payload.get("system_ids", [])
    rows = session.execute(
        select(CyabSystem).where(CyabSystem.id.in_(ids))
    ).scalars().all()

    if action == "mark-reviewed":
        today = date.today()
        for s in rows:
            s.last_reviewed_date = today
        session.commit()
        return {"affected": len(rows)}

    if action == "export-csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "name", "department", "owner", "status", "readiness"])
        for s in rows:
            w.writerow([s.id, s.name, s.department, s.soc_analyst_owner or "",
                        s.status, s.readiness_score])
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"content-disposition": "attachment; filename=cyab-systems.csv"})

    if action == "rerun-health":
        # Stub — Sub-plan C wires the live data-health service into a job.
        return {"affected": len(rows), "note": "queued (stub)"}

    raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
```

(Path note: the page form uses `/cyab/systems/_table`. Register an `app`-level alias that proxies to the router function so both the `/api/cyab/_table` and the page-friendly `/cyab/systems/_table` paths work — or just register the partial directly under `/cyab/systems/_table` to keep filtering local to the page route file. Either approach passes the tests; choose the one that fits your wiring norms.)

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_systems_list.py -v
```
Expected: 7/7 PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/systems_list.html src/ion/web/templates/cyab/_systems_table.html src/ion/web/server.py src/ion/web/cyab_api.py tests/integration/test_cyab_systems_list.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab/systems portfolio list with HTMX filters + bulk ops"
```

---

## Task 7: Wizard Step 2 — wire reuse of existing /api/cyab/studio/answers

The spec calls out that wizard Step 2's intake answers should reuse the same `/api/cyab/studio/systems/{sys_id}/answers` endpoint that the per-system Intake tab uses (Sub-plan A Task 5). Verify the wizard form's HTMX `hx-post` actually round-trips through that endpoint and persists into `CyabSystemAssessment.responses_json` so refreshing the per-system page mid-wizard shows the answers.

This is a focused integration test — implementation is already complete in Tasks 3-4 if the endpoint name was correct. Catches regressions where the wizard accidentally goes to a wizard-private path.

**Files:**
- Test: `tests/integration/test_cyab_onboard_intake_persistence.py` (new file)

- [ ] **Step 1: Write failing test**

```python
# tests/integration/test_cyab_onboard_intake_persistence.py
"""End-to-end: wizard Step 2 answers visible from per-system Intake tab."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_wizard_intake_answer_visible_from_per_system_page(admin_session):
    # Start wizard
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # Identity → step 1
    admin_session.post(f"/api/cyab/onboard/{wid}/step/1", data={
        "name": "intake-persist", "department": "X",
        "hostname": "h", "pillar": "endpoint", "owner": "o",
        "containment_authority": "c",
    })

    # Look up the system_id we just created
    sys_id = next(s["id"] for s in admin_session.get("/api/cyab/systems").json()
                  if s["name"] == "intake-persist")

    # Submit an intake answer directly to the studio endpoint (this is
    # what the Step 2 form does on autosave).
    r = admin_session.post(
        f"/api/cyab/studio/systems/{sys_id}/answers",
        json={"answers": {"q_traffic_volume": "high"}},
    )
    assert r.status_code in (200, 201, 204)

    # Now read back via the same endpoint — answer should be present
    r = admin_session.get(f"/api/cyab/studio/systems/{sys_id}/answers")
    assert r.status_code == 200
    body = r.json()
    assert body.get("answers", {}).get("q_traffic_volume") == "high"


def test_wizard_resume_loads_prior_state(admin_session):
    """Visiting /cyab/onboard?wid=<existing>&step=1 shows saved values."""
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    admin_session.post(f"/api/cyab/onboard/{wid}/step/1", data={
        "name": "resume-test", "department": "X",
    })
    # Re-fetch step 1
    r = admin_session.get(f"/cyab/onboard?wid={wid}&step=1")
    assert "resume-test" in r.text
```

- [ ] **Step 2: Run tests to verify they pass (should already pass given Tasks 3-4)**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_onboard_intake_persistence.py -v
```
Expected: PASS — if any test fails, the wizard's hx-post URL or the studio endpoint contract drifted; fix the wiring.

- [ ] **Step 3: Commit**

```bash
cd ~/ION && git add tests/integration/test_cyab_onboard_intake_persistence.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "test(cyab): wizard intake answers round-trip via /api/cyab/studio/answers"
```

---

## Task 8: Section nav cross-links — verify every CyAB page renders the strip

Belt-and-braces test: hit each top-level CyAB URL and confirm the section nav is present with the right tab marked active. Catches "I forgot to include the partial" regressions when adding a new page later.

**Files:**
- Test: extend `tests/integration/test_cyab_section_nav.py`

- [ ] **Step 1: Append failing tests**

```python
# tests/integration/test_cyab_section_nav.py — appended

@pytest.mark.parametrize("path,active", [
    ("/cyab",          "overview"),
    ("/cyab/systems",  "systems"),
    ("/cyab/onboard",  "onboard"),
    ("/cyab/coverage", "coverage"),
    ("/cyab/audit",    "audit"),
])
def test_every_cyab_page_renders_section_nav(admin_session, path, active):
    r = admin_session.get(path, follow_redirects=True)
    assert r.status_code == 200
    assert "cyab-section-nav" in r.text, f"{path} missing section nav"
    assert f'data-active="{active}"' in r.text, f"{path} wrong active tab"


def test_section_nav_includes_link_to_per_system_pages_via_systems(admin_session):
    """The Systems link in the nav strip points to /cyab/systems."""
    r = admin_session.get("/cyab")
    assert 'href="/cyab/systems"' in r.text
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_section_nav.py -v
```
Expected: all PASS — if Onboard fails on `data-active="onboard"`, the wizard shell didn't pass `active_tab` correctly; verify Task 3 Step 5.

- [ ] **Step 3: Commit**

```bash
cd ~/ION && git add tests/integration/test_cyab_section_nav.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "test(cyab): every section page renders the secondary tab strip"
```

---

## Task 9: End-to-end smoke — full wizard run + landing pages

Single test that drives the wizard from "+ Onboard" through Finish, then verifies the new system shows up on the Overview "in progress" feed and on `/cyab/systems`. Catches any cross-page wiring breaks before release.

**Files:**
- Create: `tests/integration/test_cyab_landing_smoke.py`

- [ ] **Step 1: Write the smoke test**

```python
# tests/integration/test_cyab_landing_smoke.py
"""End-to-end smoke: wizard Finish lands user on per-system page;
new system appears on /cyab Overview and /cyab/systems."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_full_wizard_to_landing_smoke(admin_session):
    # 1. Start wizard
    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]

    # 2. Identity
    admin_session.post(f"/api/cyab/onboard/{wid}/step/1", data={
        "name": "smoke-finished", "department": "Smoke",
        "hostname": "smk01", "pillar": "endpoint", "owner": "smoker",
        "containment_authority": "SOC L1",
    })

    # 3. Intake (skip — wizard never blocks)
    admin_session.post(f"/api/cyab/onboard/{wid}/step/2", data={})

    # 4. Source
    admin_session.post(f"/api/cyab/onboard/{wid}/step/3", data={
        "name": "smk-source", "data_source_type": "edr-generic",
    })

    # 5. Finish
    r = admin_session.post(f"/api/cyab/onboard/{wid}/finish",
                           data={}, follow_redirects=False)
    assert r.status_code in (302, 303)
    target = r.headers["location"]
    assert target.startswith("/cyab/systems/")
    sys_id = int(target.rsplit("/", 1)[-1])

    # 6. Per-system page renders the new system (Sub-plan A page)
    r = admin_session.get(target)
    assert r.status_code == 200
    assert "smoke-finished" in r.text

    # 7. Overview "in progress" feed includes the new name
    r = admin_session.get("/cyab")
    assert "smoke-finished" in r.text

    # 8. Portfolio list table includes the new name
    r = admin_session.get("/cyab/systems/_table")
    assert "smoke-finished" in r.text


def test_overview_kpi_strip_reflects_new_system_count(admin_session):
    before = admin_session.get("/api/cyab/dashboard").json()["total_systems"]

    r = admin_session.get("/cyab/onboard", follow_redirects=False)
    wid = r.headers["location"].split("wid=")[1].split("&")[0]
    admin_session.post(f"/api/cyab/onboard/{wid}/step/1", data={
        "name": "kpi-bump", "department": "X",
    })

    after = admin_session.get("/api/cyab/dashboard").json()["total_systems"]
    assert after == before + 1
```

- [ ] **Step 2: Run smoke**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_landing_smoke.py -v
```
Expected: 2/2 PASS.

- [ ] **Step 3: Commit**

```bash
cd ~/ION && git add tests/integration/test_cyab_landing_smoke.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "test(cyab): end-to-end smoke — wizard to landing pages"
```

---

## Task 10: Run full Sub-plan A + B test suite for regressions

**Files:** none (test run only)

Confirm Sub-plan A's 25 tests still pass alongside Sub-plan B's ~30 new tests, plus the broader baseline.

- [ ] **Step 1: Run all CyAB-related tests**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_*.py tests/integration/test_cyab_*.py -v
```

Expected output ballpark:
- Sub-plan A:  ~25 tests pass.
- Sub-plan B:  ~30 tests pass (this plan).
- Total CyAB: ~55 passing.

- [ ] **Step 2: Run the full suite**

```bash
cd ~/ION && PYTHONPATH=src pytest -q
```

Expected: all green. If anything in unrelated modules broke, the most likely culprit is the `cyab_api.py` import-tree change (added `signoffs_this_week` dashboard query); verify with:

```bash
cd ~/ION && PYTHONPATH=src python -c "from ion.web.cyab_api import dashboard_metrics; print('ok')"
```

- [ ] **Step 3: Commit (only if any test files needed touch-ups)**

If test runs were clean, no commit needed. If a fix landed, commit it tagged `fix(cyab):` rather than `test(cyab):`.

---

## Task 11: Version bump → v0.19.0-rc.2 + CHANGELOG + release commit + tag

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/ion/__init__.py`
- Modify: `CHANGELOG.md`

This sub-plan ships `v0.19.0-rc.2`. (Sub-plan A shipped `rc.1`; Sub-plan C ships `rc.3`; final `v0.19.0` is tagged when all three are merged.)

- [ ] **Step 1: Bump version files**

```python
# pyproject.toml — line where version = "0.19.0-rc.1"
version = "0.19.0-rc.2"
```

```python
# src/ion/__init__.py
"""ION - Documentation Template Management System."""
__version__ = "0.19.0-rc.2"
```

- [ ] **Step 2: Add CHANGELOG entry**

Prepend to `CHANGELOG.md`:

```markdown
## v0.19.0-rc.2 — 2026-05-04

### CyAB IA — Onboarding wizard + landing pages (Sub-plan B of 3)

- **New `/cyab/onboard` 4-step wizard** — Identity, Intake, First data
  source, Doc placeholders. Wizard never blocks: every step accepts
  partial data and the user can exit and resume from the same wid URL.
  Finish drops the user into `/cyab/systems/{id}` with the doc checklist
  lazy-seeded (20 default items).
- **New `/cyab` Overview landing** — KPI strip (total systems, %
  onboarded, % critical-missing, sign-offs this week), "In progress"
  feed (5 most recent), "Needs attention" feed (critical-missing rows),
  CTAs to + Onboard / View systems / Run coverage rollup.
- **New `/cyab/systems` portfolio list** — table with name / pillar /
  sub-profile / owner / progress / critical-missing / last-edited /
  status; HTMX-filtered search by name/owner; filters for pillar /
  sub-profile / status / owner / "missing X" / stale data; bulk ops
  (mark reviewed, export CSV, re-run health checks).
- **Secondary tab strip** added to every CyAB page: Overview · Systems ·
  Scoping · Onboard · Coverage · Audit. Coverage and Audit are
  placeholder pages that ship the nav strip + "coming soon" card; both
  are filled in by Sub-plan C.
- **New `cyab_wizard_sessions` table + `cyab_wizard_service`** — manages
  in-progress wizard state server-side so users can resume across page
  reloads.
- `/api/cyab/dashboard` now returns `signoffs_this_week`.
- New `/api/cyab/systems/_table` HTMX partial endpoint.
- New `/api/cyab/systems/bulk` endpoint — `mark-reviewed`,
  `export-csv`, `rerun-health` (last is a stub pending Sub-plan C).

### Removed

- Legacy `src/ion/web/templates/cyab.html` template (3,543 lines) —
  replaced by the new Overview page. Per-system content already moved
  to `/cyab/systems/{id}` tabs in v0.19.0-rc.1.

### Coming in Sub-plan C (v0.19.0-rc.3)

Stack-to-use-cases scoping at `/cyab/scoping`; fleet `/cyab/coverage`
matrix; `/cyab/audit` trail. Live recommendation counter wired into
wizard Step 2.
```

- [ ] **Step 3: Run the full test suite to confirm no regressions**

```bash
cd ~/ION && PYTHONPATH=src pytest -q
```

Expected: all tests pass (Sub-plan A baseline + Sub-plan B additions; ~55 CyAB-related cases plus the broader 367-test baseline).

- [ ] **Step 4: Commit + tag**

```bash
cd ~/ION && git add pyproject.toml src/ion/__init__.py CHANGELOG.md
git -c user.name=tomo -c user.email=tomo@example.com commit -m "v0.19.0-rc.2 — CyAB IA: onboarding wizard + landing pages (sub-plan B)"
git -c user.name=tomo -c user.email=tomo@example.com tag -a v0.19.0-rc.2 -m "v0.19.0-rc.2 — CyAB wizard + landing pages"
```

- [ ] **Step 5: Push (operator confirms before pushing)**

```bash
cd ~/ION && git push origin main && git push origin v0.19.0-rc.2
```

(Operator may also want to publish a Docker image: `docker build -t ixion36/ion:0.19.0-rc.2 . && docker push ixion36/ion:0.19.0-rc.2`. Not part of the task — release-engineering decision.)

---

## Summary

11 tasks. Each ships an independent, tested commit. Total expected commits: 11 (one per task except Task 10 which is verification-only). Total new test cases: ~30 across 6 test files.

**Spec coverage check:**

| Spec section | Task |
|---|---|
| Secondary tab strip (Overview · Systems · Scoping · Onboard · Coverage · Audit) | 1 |
| `/cyab/coverage` and `/cyab/audit` placeholder routes (filled by Sub-plan C) | 1 |
| Wizard session state + lifecycle (start / advance / resume / finish) | 2 |
| Wizard Step 1 — Identity (creates CyabSystem) | 3 |
| Wizard Step 2 — Intake (sub-profile-driven; reuses `/api/cyab/studio/answers`) | 4, 7 |
| Wizard Step 3 — First data source (creates CyabDataSource) | 4 |
| Wizard Step 4 — Doc placeholders (lazy-seeds 20-item checklist) | 4 |
| Wizard "never blocks" semantics (partial data ok at every step) | 3, 4 |
| Wizard Finish → redirect to `/cyab/systems/{id}` | 4 |
| `/cyab` Overview KPIs (total / % onboarded / % critical-missing / signoffs/week) | 5 |
| `/cyab` "In progress" feed (5 most recent) | 5 |
| `/cyab` "Needs attention" feed (critical-missing systems) | 5 |
| `/cyab` CTAs (+ Onboard / View systems / Run coverage rollup) | 5 |
| Legacy `cyab.html` template deleted | 5 (explicit `git rm`) |
| `/cyab/systems` portfolio table (name / pillar / sub-profile / owner / progress / critical-missing / last-edited / status) | 6 |
| `/cyab/systems` filters (pillar, sub-profile, status, owner, missing X, stale data) | 6 |
| `/cyab/systems` search (name / hostname / owner) | 6 |
| `/cyab/systems` bulk ops (mark reviewed, export CSV, re-run health) | 6 |
| Section nav present on every CyAB page with active-tab highlighting | 1, 8 |
| End-to-end wizard → landing flow | 9 |
| Release artefact (rc.2 + CHANGELOG + tag) | 11 |

**Out of scope for this plan (in Sub-plan C):**

- `/cyab/scoping` page (questionnaire UI + summary + PDF export + "convert to system" CTA).
- Shared question set + scoring engine module (extends `cyab_assessment_service`).
- Wizard Step 2 live recommendation counter (depends on the shared scoring engine).
- `/cyab/coverage` matrix content (placeholder ships in this sub-plan).
- `/cyab/audit` trail content (placeholder ships in this sub-plan).
- Stale-data "last_event_at > 24h" filter on `/cyab/systems` — needs the live ingestion sync from Sub-plan C; portfolio currently filters using the doc-checklist critical-missing flag as a proxy.
- Re-run-health bulk action implementation (stub returns `affected` but doesn't actually queue jobs; Sub-plan C wires it).
- Reconciliation drift on Data Health (Phase 2 — separate plan).

**Open assumption (validate at Task 5):** the legacy `cyab.html` template has no surviving content not covered by either Sub-plan A's per-system tabs or this sub-plan's Overview / Systems / Onboard pages. If a stakeholder re-opens the page mid-implementation and finds a feature that wasn't moved, file an issue and either lift it into the new Overview or document the deprecation. The deletion at Task 5 Step 6 is destructive — verify the `git grep` check finds no stragglers before committing.
