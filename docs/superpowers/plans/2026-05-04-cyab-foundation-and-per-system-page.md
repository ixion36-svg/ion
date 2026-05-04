# CyAB IA — Foundation + Per-System Page (Sub-plan A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the new per-system page at `/cyab/systems/{id}` with sticky onboarding-progress header and 7 tabs (Overview, Intake, Sources, Data Health, Detection Use Cases, Audit Use Cases, Sign-off). Add the new Data Health backend service. Redirect `/cyab/studio` → new page. Foundation for sub-plans B (wizard + landing) and C (scoping + coverage + audit).

**Architecture:**
- New page route `/cyab/systems/{system_id}` rendering `templates/cyab/system_detail.html`.
- Each tab is a Jinja partial under `templates/cyab/tabs/`, swapped via HTMX (no full page reload between tabs).
- Sticky progress header is its own partial (`_progress_header.html`) included inside `system_detail.html`.
- New Data Health service `cyab_data_health_service.py` aggregates ingestion/mapping/coverage signals.
- Existing API routes (`/api/cyab/*` and `/api/cyab/studio/*`) are reused. One new API: `/api/cyab/systems/{sys_id}/data-health`.
- `/cyab/studio` becomes a 301 redirect to the new page.

**Tech Stack:** FastAPI · HTMX · Jinja2 · Tailwind · SQLAlchemy 2.x · pytest

**Spec source:** `docs/superpowers/specs/2026-05-04-cyab-ia-design.md` (commit `66a540f`).

**Section mapping resolution** (open question in spec, resolved here):

| Existing section in `cyab.html` | New tab |
|---|---|
| `section#demarcation` (System Source / SIEM) | **Sources** |
| `section#field-mapping` | **Sources** (sub-section under each data source) |
| `section#sal-tiers` (SAL-1/2/3 declarations) | **Sources** (declarative source attribute; Data Health checks adherence) |
| `section#governance` (sign-off duties / stakeholders) | **Sign-off** |

---

## File Structure

**New files (templates):**
- `src/ion/web/templates/cyab/system_detail.html` — page shell (header + tab nav + content slot)
- `src/ion/web/templates/cyab/_progress_header.html` — sticky progress bar partial
- `src/ion/web/templates/cyab/tabs/_overview.html` — checklist UI grouped by category
- `src/ion/web/templates/cyab/tabs/_intake.html` — sub-profile-driven questions (lifted from studio)
- `src/ion/web/templates/cyab/tabs/_sources.html` — data sources + demarcation + field mapping + SAL declarations
- `src/ion/web/templates/cyab/tabs/_data_health.html` — 3 panels (ingestion, field mapping, coverage)
- `src/ion/web/templates/cyab/tabs/_detection.html` — detection use case status grid
- `src/ion/web/templates/cyab/tabs/_audit_use_cases.html` — audit use case status grid
- `src/ion/web/templates/cyab/tabs/_signoff.html` — Onboarding Pack PDF + sign + governance

**New files (backend):**
- `src/ion/services/cyab_data_health_service.py` — ingestion freshness, field mapping completeness, coverage rollup wrapper

**New files (tests):**
- `tests/unit/test_cyab_data_health_service.py`
- `tests/integration/test_cyab_system_detail_page.py`
- `tests/integration/test_cyab_studio_redirect.py`

**Modified files:**
- `src/ion/web/server.py` — register new page route; redirect `/cyab/studio`
- `src/ion/web/cyab_api.py` — add `/api/cyab/systems/{sys_id}/data-health` endpoint
- `pyproject.toml`, `src/ion/__init__.py` — version bump (Task 14)
- `CHANGELOG.md` — release note

---

## Task 1: Page route + skeleton template

**Files:**
- Create: `src/ion/web/templates/cyab/system_detail.html`
- Modify: `src/ion/web/server.py` (after line 915 where `/cyab/studio` is registered)
- Test: `tests/integration/test_cyab_system_detail_page.py`

- [ ] **Step 1: Write the failing integration test**

```python
# tests/integration/test_cyab_system_detail_page.py
"""Integration tests for the new per-system CyAB page."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(temp_db, monkeypatch):
    """TestClient with the FastAPI app and a fresh DB."""
    monkeypatch.setattr(
        "ion.storage.database.get_engine", lambda *_a, **_k: temp_db
    )
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    """Logged-in admin session cookie."""
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code in (200, 401)  # 401 if admin user not seeded yet
    return client


@pytest.fixture
def seeded_system(temp_db):
    """Create a CyabSystem row to point the test at."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="prod-sso-test", department="Identity")
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_per_system_page_renders_with_system_name(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}")
    assert r.status_code == 200
    assert "prod-sso-test" in r.text
    assert "system-detail" in r.text  # page-level marker class


def test_per_system_page_404_for_unknown_id(admin_session):
    r = admin_session.get("/cyab/systems/999999")
    assert r.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py -v
```
Expected: 404 / template-not-found errors.

- [ ] **Step 3: Create the skeleton template**

```html
<!-- src/ion/web/templates/cyab/system_detail.html -->
{% extends "base.html" %}

{% block title %}{{ system.name }} — CyAB · ION{% endblock %}

{% block content %}
<div class="system-detail" data-system-id="{{ system.id }}">
  <nav class="breadcrumb tw-text-sm tw-text-slate-400 tw-mb-3">
    <a href="/cyab" class="hover:tw-text-white">CyAB</a>
    <span class="tw-mx-2">·</span>
    <a href="/cyab/systems" class="hover:tw-text-white">Systems</a>
    <span class="tw-mx-2">·</span>
    <span class="tw-text-white">{{ system.name }}</span>
  </nav>

  <header class="tw-flex tw-items-baseline tw-gap-4 tw-mb-4">
    <h1 class="tw-text-[28px] tw-font-semibold tw-text-white">{{ system.name }}</h1>
    {% if system.department %}<span class="tw-text-slate-400">{{ system.department }}</span>{% endif %}
  </header>

  {# Sticky progress header — implemented in Task 2 #}
  {# {% include "cyab/_progress_header.html" %} #}

  {# Tab nav + content slot — implemented in Task 3 #}
  <div class="tab-content tw-mt-6">
    <p class="tw-text-slate-400">Per-system page skeleton — tabs land in Task 3.</p>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 4: Add the page route to `server.py`**

Add after line 915 (the `/cyab/studio` page handler):

```python
# src/ion/web/server.py — add after the /cyab/studio handler
@app.get("/cyab/systems/{system_id}", response_class=HTMLResponse)
async def cyab_system_detail_page(
    system_id: int,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Per-system CyAB page (replaces /cyab/studio for a given system)."""
    from ion.models.cyab import CyabSystem
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    engine = get_engine(config.db_path)
    Session = get_session_factory(engine)
    session = Session()
    try:
        system = session.get(CyabSystem, system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")
        return templates.TemplateResponse(
            request=request,
            name="cyab/system_detail.html",
            context={"system": system, "user": user},
        )
    finally:
        session.close()
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py -v
```
Expected: both tests PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/system_detail.html src/ion/web/server.py tests/integration/test_cyab_system_detail_page.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): add per-system page skeleton at /cyab/systems/{id}"
```

---

## Task 2: Sticky progress header partial

**Files:**
- Create: `src/ion/web/templates/cyab/_progress_header.html`
- Modify: `src/ion/web/templates/cyab/system_detail.html` (uncomment include from Task 1)
- Modify: `src/ion/web/server.py` — extend page route to pass progress data
- Test: extend `tests/integration/test_cyab_system_detail_page.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/integration/test_cyab_system_detail_page.py`:

```python
def test_progress_header_shows_completion_count(admin_session, seeded_system):
    """Sticky header should show progress like '0 / 20' for a fresh system."""
    r = admin_session.get(f"/cyab/systems/{seeded_system}")
    assert r.status_code == 200
    # Default checklist is lazy-seeded with 20 items, all 'unknown'
    assert "0 / 20" in r.text or "0/20" in r.text
    assert "onboarding-progress" in r.text  # class on the partial


def test_progress_header_marks_critical_missing(admin_session, seeded_system):
    """Critical-missing pill appears when critical items aren't done."""
    r = admin_session.get(f"/cyab/systems/{seeded_system}")
    assert r.status_code == 200
    # Default checklist has 3 critical items: HLD, NETWORK_TOPOLOGY, OWNERS
    assert "critical missing" in r.text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py::test_progress_header_shows_completion_count -v
```
Expected: FAIL — "0 / 20" not in text.

- [ ] **Step 3: Create the progress header partial**

```html
<!-- src/ion/web/templates/cyab/_progress_header.html -->
<div class="onboarding-progress tw-sticky tw-top-0 tw-z-20 tw-bg-slate-900/95 tw-backdrop-blur tw-border-b tw-border-slate-800 tw-py-2 tw-px-4 tw-flex tw-items-center tw-gap-3 tw-text-[12.5px]">
  <span class="tw-text-slate-400 tw-uppercase tw-tracking-wider tw-text-[10px]">Onboarding</span>

  <div class="tw-flex tw-items-center tw-gap-2 tw-flex-1 tw-max-w-md">
    <div class="tw-h-1.5 tw-flex-1 tw-bg-slate-800 tw-rounded-full tw-overflow-hidden">
      <div class="tw-h-full tw-bg-gradient-to-r tw-from-cyan-400 tw-to-emerald-500"
           style="width: {{ progress.completion_pct }}%"></div>
    </div>
    <span class="tw-text-cyan-300 tw-font-medium">{{ progress.done }} / {{ progress.total }}</span>
  </div>

  {% if progress.critical_missing %}
    <span class="tw-text-rose-400 tw-bg-rose-950/40 tw-px-2 tw-py-0.5 tw-rounded">
      {{ progress.critical_missing|length }} critical missing
    </span>
  {% else %}
    <span class="tw-text-emerald-400 tw-text-[11px]">all critical items done</span>
  {% endif %}

  {% if system.updated_at %}
    <span class="tw-text-slate-500 tw-ml-auto tw-text-[11px]">
      last edited {{ system.updated_at.strftime('%Y-%m-%d %H:%M') }}
    </span>
  {% endif %}
</div>
```

- [ ] **Step 4: Wire progress data into the page route**

Modify the `cyab_system_detail_page` handler in `server.py` (added in Task 1):

```python
@app.get("/cyab/systems/{system_id}", response_class=HTMLResponse)
async def cyab_system_detail_page(
    system_id: int,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    engine = get_engine(config.db_path)
    Session = get_session_factory(engine)
    session = Session()
    try:
        system = session.get(CyabSystem, system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")

        # Lazy-seed checklist on first access (idempotent)
        cyab_doc_checklist_service.seed_for_system(session, system_id)
        progress = cyab_doc_checklist_service.coverage_summary(session, system_id)

        return templates.TemplateResponse(
            request=request,
            name="cyab/system_detail.html",
            context={"system": system, "user": user, "progress": progress},
        )
    finally:
        session.close()
```

- [ ] **Step 5: Uncomment the include in `system_detail.html`**

In `src/ion/web/templates/cyab/system_detail.html`, replace the commented include with:

```html
{% include "cyab/_progress_header.html" %}
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py -v
```
Expected: 4/4 PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/_progress_header.html src/ion/web/templates/cyab/system_detail.html src/ion/web/server.py tests/integration/test_cyab_system_detail_page.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): sticky onboarding-progress header on per-system page"
```

---

## Task 3: Tab navigation skeleton (HTMX swap)

**Files:**
- Modify: `src/ion/web/templates/cyab/system_detail.html` (add tab strip + HTMX target)
- Create: `src/ion/web/templates/cyab/tabs/_placeholder.html` (used by all tabs until Tasks 4-11 fill them)
- Modify: `src/ion/web/server.py` — add `/cyab/systems/{id}/tab/{name}` HTMX endpoint
- Test: extend the integration test file

- [ ] **Step 1: Write the failing test**

Append to `tests/integration/test_cyab_system_detail_page.py`:

```python
@pytest.mark.parametrize("tab", [
    "overview", "intake", "sources", "data-health",
    "detection", "audit-use-cases", "signoff",
])
def test_each_tab_endpoint_returns_partial(admin_session, seeded_system, tab):
    """HTMX tab endpoint returns the partial HTML (no full page chrome)."""
    r = admin_session.get(f"/cyab/systems/{seeded_system}/tab/{tab}")
    assert r.status_code == 200
    assert "<html" not in r.text  # partial, not full doc
    assert tab in r.text.lower() or "placeholder" in r.text.lower()


def test_unknown_tab_returns_404(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}/tab/bogus")
    assert r.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py -k tab -v
```
Expected: FAIL — endpoint not found.

- [ ] **Step 3: Add the placeholder partial**

```html
<!-- src/ion/web/templates/cyab/tabs/_placeholder.html -->
<div class="tab-placeholder tw-py-12 tw-text-center tw-text-slate-500">
  <p class="tw-text-[13px]">{{ tab_label }} tab — content lands in a later task.</p>
  <p class="tw-text-[11px] tw-mt-1 tw-text-slate-600">tab={{ tab_name }}</p>
</div>
```

- [ ] **Step 4: Add the tab strip to `system_detail.html`**

Replace the placeholder `<div class="tab-content">…</div>` block with:

```html
<nav class="tab-strip tw-flex tw-gap-1 tw-mt-4 tw-border-b tw-border-slate-800">
  {% set tabs = [
    ('overview', 'Overview'),
    ('intake', 'Intake'),
    ('sources', 'Sources'),
    ('data-health', 'Data Health'),
    ('detection', 'Detection Use Cases'),
    ('audit-use-cases', 'Audit Use Cases'),
    ('signoff', 'Sign-off'),
  ] %}
  {% for slug, label in tabs %}
    <button class="tab-btn tw-px-3 tw-py-2 tw-text-[12.5px] tw-text-slate-400 hover:tw-text-cyan-300 tw-border-b-2 tw-border-transparent {% if slug == 'overview' %}tw-text-cyan-300 tw-border-cyan-400{% endif %}"
            hx-get="/cyab/systems/{{ system.id }}/tab/{{ slug }}"
            hx-target="#tab-content"
            hx-swap="innerHTML"
            data-tab="{{ slug }}">
      {{ label }}
    </button>
  {% endfor %}
</nav>

<div id="tab-content" class="tw-mt-4"
     hx-get="/cyab/systems/{{ system.id }}/tab/overview"
     hx-trigger="load"
     hx-swap="innerHTML">
  <p class="tw-text-slate-500 tw-text-[12px]">Loading…</p>
</div>
```

- [ ] **Step 5: Add the HTMX tab endpoint to `server.py`**

```python
# src/ion/web/server.py — add after the /cyab/systems/{system_id} handler
_CYAB_TABS = {
    "overview": ("Overview", "cyab/tabs/_overview.html"),
    "intake": ("Intake", "cyab/tabs/_intake.html"),
    "sources": ("Sources", "cyab/tabs/_sources.html"),
    "data-health": ("Data Health", "cyab/tabs/_data_health.html"),
    "detection": ("Detection Use Cases", "cyab/tabs/_detection.html"),
    "audit-use-cases": ("Audit Use Cases", "cyab/tabs/_audit_use_cases.html"),
    "signoff": ("Sign-off", "cyab/tabs/_signoff.html"),
}


@app.get("/cyab/systems/{system_id}/tab/{tab_name}", response_class=HTMLResponse)
async def cyab_system_tab(
    system_id: int,
    tab_name: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """HTMX endpoint returning a single tab's content (no page chrome)."""
    if tab_name not in _CYAB_TABS:
        raise HTTPException(status_code=404, detail="Unknown tab")

    label, template_name = _CYAB_TABS[tab_name]

    from ion.models.cyab import CyabSystem
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config

    config = get_config()
    engine = get_engine(config.db_path)
    Session = get_session_factory(engine)
    session = Session()
    try:
        system = session.get(CyabSystem, system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")

        # Each tab will add its own context in later tasks. For now, fall back
        # to the placeholder template if the tab template doesn't exist yet.
        from jinja2 import TemplateNotFound
        try:
            return templates.TemplateResponse(
                request=request,
                name=template_name,
                context={"system": system, "user": user, "tab_name": tab_name, "tab_label": label},
            )
        except TemplateNotFound:
            return templates.TemplateResponse(
                request=request,
                name="cyab/tabs/_placeholder.html",
                context={"tab_name": tab_name, "tab_label": label},
            )
    finally:
        session.close()
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_system_detail_page.py -v
```
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/system_detail.html src/ion/web/templates/cyab/tabs/_placeholder.html src/ion/web/server.py tests/integration/test_cyab_system_detail_page.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): tab navigation scaffold with HTMX-swapped panels"
```

---

## Task 4: Overview tab — checklist UI

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_overview.html`
- Test: `tests/integration/test_cyab_overview_tab.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_overview_tab.py
"""Integration tests for the Overview tab (checklist view)."""

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
def seeded_system(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="prod-app-test")
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_overview_tab_shows_critical_first(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}/tab/overview")
    assert r.status_code == 200
    body = r.text.lower()
    # Critical items HLD, NETWORK_TOPOLOGY, OWNERS appear before non-critical
    crit_pos = body.find("critical")
    design_pos = body.find("design")
    assert crit_pos != -1 and crit_pos < design_pos


def test_overview_tab_groups_by_category(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}/tab/overview")
    body = r.text
    for cat in ("Critical", "Design", "Operational", "Security", "Compliance"):
        assert cat in body


def test_overview_lists_default_checklist_items(admin_session, seeded_system):
    r = admin_session.get(f"/cyab/systems/{seeded_system}/tab/overview")
    body = r.text
    for label in ("HLD", "LLD", "Network Topology", "Owners", "Runbook"):
        assert label in body
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_overview_tab.py -v
```
Expected: FAIL — placeholder served instead of real overview.

- [ ] **Step 3: Wire checklist data into the tab endpoint**

Modify `cyab_system_tab` in `server.py` to add overview-specific context. Replace the inner `try/except TemplateNotFound` block with:

```python
        ctx = {"system": system, "user": user, "tab_name": tab_name, "tab_label": label}
        if tab_name == "overview":
            from ion.services import cyab_doc_checklist_service
            ctx["checklist"] = cyab_doc_checklist_service.list_for_system(session, system_id)
            ctx["progress"] = cyab_doc_checklist_service.coverage_summary(session, system_id)

        from jinja2 import TemplateNotFound
        try:
            return templates.TemplateResponse(request=request, name=template_name, context=ctx)
        except TemplateNotFound:
            return templates.TemplateResponse(
                request=request,
                name="cyab/tabs/_placeholder.html",
                context={"tab_name": tab_name, "tab_label": label},
            )
```

- [ ] **Step 4: Create the Overview template**

```html
<!-- src/ion/web/templates/cyab/tabs/_overview.html -->
{# Overview tab — checklist grouped by category, critical first.
   Each item links to where to fix it (other tabs). #}

{% set critical_items = checklist | selectattr('is_critical', 'equalto', true) | list %}
{% set non_critical = checklist | rejectattr('is_critical', 'equalto', true) | list %}

{% macro item_row(item) %}
  {% set status_icon = {
    'done': '✓', 'in_progress': '◐', 'missing': '✗', 'na': '—', 'unknown': '○'
  }.get(item.status, '○') %}
  {% set status_color = {
    'done': 'emerald-400', 'in_progress': 'amber-400',
    'missing': 'rose-400', 'na': 'slate-500', 'unknown': 'slate-500'
  }.get(item.status, 'slate-500') %}
  <div class="checklist-item tw-flex tw-items-center tw-gap-3 tw-py-1.5 tw-px-2 hover:tw-bg-slate-800/40 tw-rounded">
    <span class="tw-text-{{ status_color }} tw-text-[14px] tw-w-4">{{ status_icon }}</span>
    <span class="tw-flex-1 tw-text-[13px] tw-text-slate-200">{{ item.label }}</span>
    {% if item.url %}
      <a href="{{ item.url }}" class="tw-text-cyan-400 tw-text-[11px] hover:tw-underline" target="_blank" rel="noopener">link</a>
    {% endif %}
    <span class="tw-text-slate-500 tw-text-[11px] tw-w-20 tw-text-right">{{ item.status }}</span>
  </div>
{% endmacro %}

{% if critical_items %}
<section class="tw-mb-6">
  <h3 class="tw-text-rose-400 tw-text-[11px] tw-uppercase tw-tracking-wider tw-mb-2">Critical (must complete to ship)</h3>
  <div class="tw-bg-slate-900/40 tw-border tw-border-rose-900/30 tw-rounded-md tw-p-2">
    {% for item in critical_items %}{{ item_row(item) }}{% endfor %}
  </div>
</section>
{% endif %}

{% set categories = ['design', 'operational', 'security', 'compliance'] %}
{% for cat in categories %}
  {% set rows = non_critical | selectattr('category', 'equalto', cat) | list %}
  {% if rows %}
    <section class="tw-mb-5">
      <h3 class="tw-text-slate-400 tw-text-[11px] tw-uppercase tw-tracking-wider tw-mb-2">
        {{ cat | capitalize }}
        ({{ rows | selectattr('status', 'equalto', 'done') | list | length }} / {{ rows | length }})
      </h3>
      <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded-md tw-p-2">
        {% for item in rows %}{{ item_row(item) }}{% endfor %}
      </div>
    </section>
  {% endif %}
{% endfor %}

{# "Add custom item" form — POSTs to existing /api/cyab/studio/systems/{id}/checklist #}
<section class="tw-mt-6 tw-pt-4 tw-border-t tw-border-slate-800">
  <details>
    <summary class="tw-text-cyan-400 tw-text-[12px] tw-cursor-pointer">+ Add custom checklist item</summary>
    <form hx-post="/api/cyab/studio/systems/{{ system.id }}/checklist"
          hx-target="#tab-content"
          hx-swap="innerHTML"
          class="tw-mt-3 tw-flex tw-gap-2 tw-items-center">
      <input name="label" placeholder="e.g. Quarterly access review" required
             class="tw-flex-1 tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
      <select name="category" class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
        <option value="design">Design</option>
        <option value="operational">Operational</option>
        <option value="security">Security</option>
        <option value="compliance">Compliance</option>
      </select>
      <button type="submit" class="tw-px-3 tw-py-1 tw-bg-cyan-700 tw-text-white tw-text-[12px] tw-rounded">Add</button>
    </form>
  </details>
</section>
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_overview_tab.py -v
```
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_overview.html src/ion/web/server.py tests/integration/test_cyab_overview_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Overview tab — checklist grouped by category, critical first"
```

---

## Task 5: Intake tab — lift from studio

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_intake.html`
- Test: extend overview test file with intake-specific tests

**Note:** the existing intake-question rendering lives in `src/ion/web/templates/cyab_studio.html` lines that render `data-intake-q-*` blocks driven by `/api/cyab/studio/systems/{sys_id}/answers` GET/POST. Lift the markup; the API endpoints stay unchanged.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_intake_tab.py
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
def seeded_system_with_subprofile(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    from ion.services.cyab_subprofile_service import seed_catalogue
    seed_catalogue()  # ensure pillars + subprofiles exist
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="prod-intake-test", subprofile_id=1)
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_intake_tab_renders_questions(admin_session, seeded_system_with_subprofile):
    r = admin_session.get(f"/cyab/systems/{seeded_system_with_subprofile}/tab/intake")
    assert r.status_code == 200
    assert "intake-question" in r.text or "data-intake-q" in r.text


def test_intake_tab_shows_progress_count(admin_session, seeded_system_with_subprofile):
    r = admin_session.get(f"/cyab/systems/{seeded_system_with_subprofile}/tab/intake")
    # Format like "0 / N answered"
    import re
    assert re.search(r"\d+\s*/\s*\d+\s+answered", r.text, re.IGNORECASE)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_intake_tab.py -v
```
Expected: FAIL.

- [ ] **Step 3: Wire intake context into the tab endpoint**

Extend the `if tab_name == "overview":` block in `server.py` (`cyab_system_tab`) to add intake handling:

```python
        if tab_name == "overview":
            from ion.services import cyab_doc_checklist_service
            ctx["checklist"] = cyab_doc_checklist_service.list_for_system(session, system_id)
            ctx["progress"] = cyab_doc_checklist_service.coverage_summary(session, system_id)
        elif tab_name == "intake":
            from ion.services.cyab_subprofile_service import (
                get_subprofile_full, system_coverage,
            )
            sub_id = system.subprofile_id
            ctx["subprofile"] = get_subprofile_full(session, sub_id) if sub_id else None
            ctx["coverage"] = system_coverage(session, system_id)
            # Existing answers — fetch via the same DB path used by /api/cyab/studio
            from ion.services.cyab_assessment_service import load_answers
            ctx["answers"] = load_answers(session, system_id) or {}
```

(If `load_answers` doesn't exist as a top-level helper, replicate the lookup pattern used in `cyab_studio_api.py:403` — it queries `CyabSystemAssessment.answers` JSON.)

- [ ] **Step 4: Create the Intake template (lifted from studio)**

```html
<!-- src/ion/web/templates/cyab/tabs/_intake.html -->
{% if not subprofile %}
  <div class="tw-py-6 tw-text-slate-400">
    <p>No sub-profile selected for this system. Choose one to load intake questions.</p>
    <p class="tw-text-[11px] tw-text-slate-500 tw-mt-2">Set <code>subprofile_id</code> via /api/cyab/systems/{{ system.id }}.</p>
  </div>
{% else %}
  {% set questions = subprofile.catalogue.intake_questions or [] %}
  {% set answered = answers | length %}
  {% set total = questions | length %}

  <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-4">
    <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Intake — {{ subprofile.name }}</h3>
    <span class="tw-text-cyan-300 tw-text-[12px]">{{ answered }} / {{ total }} answered</span>
  </header>

  <form hx-post="/api/cyab/studio/systems/{{ system.id }}/answers"
        hx-target="#tab-content" hx-swap="innerHTML"
        class="tw-space-y-4">
    {% for q in questions %}
      <div class="intake-question tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3"
           data-intake-q="{{ q.id }}">
        <label class="tw-block tw-text-slate-200 tw-text-[12.5px] tw-mb-2">{{ q.text }}</label>
        {% if q.type == 'choice' %}
          <select name="answers[{{ q.id }}]" class="tw-w-full tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
            <option value="">— select —</option>
            {% for opt in q.options %}
              <option value="{{ opt.value }}" {% if answers.get(q.id) == opt.value %}selected{% endif %}>{{ opt.label }}</option>
            {% endfor %}
          </select>
        {% else %}
          <input type="text" name="answers[{{ q.id }}]" value="{{ answers.get(q.id, '') }}"
                 class="tw-w-full tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
        {% endif %}
      </div>
    {% endfor %}
    <div class="tw-flex tw-justify-end">
      <button type="submit" class="tw-px-3 tw-py-1 tw-bg-cyan-700 tw-text-white tw-text-[12px] tw-rounded">Save</button>
    </div>
  </form>
{% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_intake_tab.py -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_intake.html src/ion/web/server.py tests/integration/test_cyab_intake_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Intake tab — sub-profile-driven questions, lifted from studio"
```

---

## Task 6: Sources tab (demarcation + field mapping + SAL)

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_sources.html`
- Test: `tests/integration/test_cyab_sources_tab.py`

**Note:** lifts three existing sections from `cyab.html`:
- `section#demarcation` (System Source / SIEM dropdowns)
- `section#field-mapping` (per-source field map editor)
- `section#sal-tiers` (Source Assurance Level declarations)

All three are per-source attributes; render once per data source row.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_sources_tab.py
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
def system_with_source(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem, CyabDataSource
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="prod-src-test")
    s.add(sys); s.flush()
    src = CyabDataSource(system_id=sys.id, name="winlog", data_source_type="windows-evtx")
    s.add(src); s.commit()
    yield sys.id, src.id
    s.close()


def test_sources_tab_lists_data_sources(admin_session, system_with_source):
    sys_id, _ = system_with_source
    r = admin_session.get(f"/cyab/systems/{sys_id}/tab/sources")
    assert r.status_code == 200
    assert "winlog" in r.text


def test_sources_tab_includes_demarcation_block(admin_session, system_with_source):
    sys_id, _ = system_with_source
    r = admin_session.get(f"/cyab/systems/{sys_id}/tab/sources")
    body = r.text.lower()
    assert "system source" in body
    assert "siem" in body or "data lake" in body


def test_sources_tab_includes_sal_section(admin_session, system_with_source):
    sys_id, _ = system_with_source
    r = admin_session.get(f"/cyab/systems/{sys_id}/tab/sources")
    body = r.text
    for tier in ("SAL-1", "SAL-2", "SAL-3"):
        assert tier in body


def test_sources_tab_includes_field_mapping_editor(admin_session, system_with_source):
    sys_id, _ = system_with_source
    r = admin_session.get(f"/cyab/systems/{sys_id}/tab/sources")
    assert "field-mapping" in r.text or "Field mapping" in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_sources_tab.py -v
```
Expected: FAIL.

- [ ] **Step 3: Wire sources context into the tab endpoint**

Add to the elif chain in `cyab_system_tab`:

```python
        elif tab_name == "sources":
            from sqlalchemy import select
            from ion.models.cyab import CyabDataSource
            ctx["sources"] = session.execute(
                select(CyabDataSource).where(CyabDataSource.system_id == system_id)
            ).scalars().all()
```

- [ ] **Step 4: Create the Sources template**

```html
<!-- src/ion/web/templates/cyab/tabs/_sources.html -->
<header class="tw-flex tw-items-baseline tw-justify-between tw-mb-4">
  <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Data Sources</h3>
  <button class="tw-px-2 tw-py-1 tw-bg-cyan-700 tw-text-white tw-text-[11.5px] tw-rounded"
          onclick="window.openDsPicker && openDsPicker()">+ Add source</button>
</header>

{% if not sources %}
  <p class="tw-text-slate-500 tw-text-[12px]">No data sources configured. Add one to start ingesting events.</p>
{% endif %}

{% for src in sources %}
<article class="data-source-row tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3 tw-mb-3" data-source-id="{{ src.id }}">
  <header class="tw-flex tw-items-center tw-justify-between tw-mb-2">
    <h4 class="tw-text-cyan-300 tw-font-mono tw-text-[13px]">{{ src.name }}</h4>
    <span class="tw-text-slate-500 tw-text-[11px]">{{ src.data_source_type or 'unknown type' }}</span>
  </header>

  {# === Demarcation: System Source / SIEM === #}
  <details open>
    <summary class="tw-text-slate-400 tw-text-[11px] tw-uppercase tw-tracking-wider tw-cursor-pointer">System Source / SIEM</summary>
    <div class="tw-grid tw-grid-cols-2 tw-gap-3 tw-mt-2 tw-text-[12px]">
      <label class="tw-flex tw-flex-col tw-gap-1">
        <span class="tw-text-slate-400">System Source</span>
        <input type="text" name="system_source" value="{{ src.system_source or '' }}"
               class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"
               hx-put="/api/cyab/sources/{{ src.id }}" hx-trigger="change" hx-include="closest article">
      </label>
      <label class="tw-flex tw-flex-col tw-gap-1">
        <span class="tw-text-slate-400">SIEM / Data Lake</span>
        <input type="text" name="siem" value="{{ src.siem or '' }}"
               class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"
               hx-put="/api/cyab/sources/{{ src.id }}" hx-trigger="change" hx-include="closest article">
      </label>
    </div>
  </details>

  {# === SAL declaration === #}
  <details class="tw-mt-2">
    <summary class="tw-text-slate-400 tw-text-[11px] tw-uppercase tw-tracking-wider tw-cursor-pointer">Source Assurance Level</summary>
    <div class="tw-flex tw-gap-2 tw-mt-2">
      {% for tier in ['SAL-1', 'SAL-2', 'SAL-3'] %}
        <label class="tw-flex tw-items-center tw-gap-1 tw-text-[12px]">
          <input type="radio" name="sal_tier" value="{{ tier }}" {% if src.sal_tier == tier %}checked{% endif %}
                 hx-put="/api/cyab/sources/{{ src.id }}" hx-trigger="change" hx-include="closest article">
          <span class="tw-text-slate-300">{{ tier }}</span>
        </label>
      {% endfor %}
    </div>
  </details>

  {# === Field mapping === #}
  <details class="tw-mt-2">
    <summary class="tw-text-slate-400 tw-text-[11px] tw-uppercase tw-tracking-wider tw-cursor-pointer">Field mapping</summary>
    <div class="tw-mt-2 field-mapping-editor" data-source-id="{{ src.id }}">
      {% set mapping = src.field_mapping or {} %}
      <table class="tw-w-full tw-text-[12px]">
        <thead><tr class="tw-text-slate-500 tw-text-[10px] tw-uppercase">
          <th class="tw-text-left tw-py-1">ECS field</th><th class="tw-text-left">Maps to (raw)</th>
        </tr></thead>
        <tbody>
          {% for ecs, raw in (mapping.items() if mapping else []) %}
            <tr><td class="tw-py-1 tw-text-slate-300">{{ ecs }}</td><td><input type="text" value="{{ raw }}" class="tw-w-full tw-px-1 tw-py-0.5 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"></td></tr>
          {% else %}
            <tr><td colspan="2" class="tw-text-slate-500 tw-py-2">No mapping defined.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </details>
</article>
{% endfor %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_sources_tab.py -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_sources.html src/ion/web/server.py tests/integration/test_cyab_sources_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Sources tab — data sources + demarcation + SAL + field mapping"
```

---

## Task 7: Data Health backend service

**Files:**
- Create: `src/ion/services/cyab_data_health_service.py`
- Test: `tests/unit/test_cyab_data_health_service.py`

- [ ] **Step 1: Write failing unit tests**

```python
# tests/unit/test_cyab_data_health_service.py
"""Unit tests for cyab_data_health_service."""

import pytest
from unittest.mock import MagicMock


def test_ingestion_freshness_returns_per_source_rows():
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    # 2 mocked data sources
    src1 = MagicMock(id=1, name="winlog", data_source_type="windows-evtx")
    src2 = MagicMock(id=2, name="proxy", data_source_type="generic-syslog")
    session.execute.return_value.scalars.return_value.all.return_value = [src1, src2]

    rows = svc.ingestion_freshness(session, system_id=42)
    assert len(rows) == 2
    assert all("source_name" in r and "last_event_at" in r and "sla_status" in r for r in rows)


def test_field_mapping_completeness_returns_zero_to_one():
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    src = MagicMock(id=1, data_source_type="windows-evtx", field_mapping={"host.name": "Computer"})
    session.execute.return_value.scalars.return_value.all.return_value = [src]

    rows = svc.field_mapping_completeness(session, system_id=42)
    assert len(rows) == 1
    assert 0.0 <= rows[0]["completeness"] <= 1.0
    assert "missing_fields" in rows[0]


def test_coverage_rollup_wraps_subprofile_service():
    from ion.services import cyab_data_health_service as svc
    session = MagicMock()
    out = svc.coverage_rollup(session, system_id=42)
    # Whatever shape system_coverage returns, we pass it through as a dict
    assert isinstance(out, dict)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_data_health_service.py -v
```
Expected: FAIL — module not found.

- [ ] **Step 3: Create the service**

```python
# src/ion/services/cyab_data_health_service.py
"""CyAB Data Health service.

Aggregates three signals per system for the Data Health tab:
  1. Ingestion freshness  — last event seen per data source, SLA pill
  2. Field mapping        — % of expected fields present in declared mapping
  3. Coverage rollup      — wraps cyab_subprofile_service.system_coverage()

Phase 2 will add a 4th panel (Reconciliation drift vs CMDB).
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource

# Per-source-type expected ECS fields. Drives "field mapping completeness".
# Conservative defaults; expand as new source types are added.
EXPECTED_FIELDS_BY_TYPE: Dict[str, List[str]] = {
    "windows-evtx":     ["@timestamp", "host.name", "event.code", "user.name"],
    "generic-syslog":   ["@timestamp", "host.name", "message"],
    "linux-auditd":     ["@timestamp", "host.name", "user.name", "process.name"],
    "aws-cloudtrail":   ["@timestamp", "user.name", "event.action", "source.ip"],
    "office365":        ["@timestamp", "user.name", "event.action", "source.ip"],
    "okta":             ["@timestamp", "user.name", "event.action", "source.ip"],
    "azure-ad":         ["@timestamp", "user.name", "event.action", "source.ip"],
    "edr-generic":      ["@timestamp", "host.name", "process.name", "user.name"],
}

# SLA: how stale a source can get before the freshness pill turns amber/red.
DEFAULT_SLA_AMBER_SECONDS = 60 * 60        # 1 hour
DEFAULT_SLA_RED_SECONDS   = 60 * 60 * 24   # 24 hours


def _sla_status(last_event_at: Optional[datetime]) -> str:
    """Map last-event timestamp to a status pill: 'fresh' | 'amber' | 'red' | 'unknown'."""
    if last_event_at is None:
        return "unknown"
    age = (datetime.now(timezone.utc) - last_event_at).total_seconds()
    if age < DEFAULT_SLA_AMBER_SECONDS:
        return "fresh"
    if age < DEFAULT_SLA_RED_SECONDS:
        return "amber"
    return "red"


def ingestion_freshness(session: Session, system_id: int) -> List[Dict[str, Any]]:
    """Return per-source rows: {source_id, source_name, last_event_at, sla_status}.

    Phase-1 implementation reads `last_event_at` from CyabDataSource (populated
    by a future background sync; defaults to None for now → 'unknown' pill).
    Phase-2 may query Elasticsearch directly per source.
    """
    sources = session.execute(
        select(CyabDataSource).where(CyabDataSource.system_id == system_id)
    ).scalars().all()

    rows: List[Dict[str, Any]] = []
    for src in sources:
        last = getattr(src, "last_event_at", None)
        rows.append({
            "source_id":     src.id,
            "source_name":   src.name,
            "data_source_type": src.data_source_type,
            "last_event_at": last,
            "sla_status":    _sla_status(last),
        })
    return rows


def field_mapping_completeness(session: Session, system_id: int) -> List[Dict[str, Any]]:
    """Per-source rows: {source_id, source_name, completeness (0..1), missing_fields, expected_fields}."""
    sources = session.execute(
        select(CyabDataSource).where(CyabDataSource.system_id == system_id)
    ).scalars().all()

    rows: List[Dict[str, Any]] = []
    for src in sources:
        expected = EXPECTED_FIELDS_BY_TYPE.get(src.data_source_type or "", [])
        mapping  = src.field_mapping or {}
        if not expected:
            rows.append({
                "source_id": src.id, "source_name": src.name,
                "completeness": None, "missing_fields": [], "expected_fields": [],
                "note": "No expected-field profile for source type.",
            })
            continue
        missing = [f for f in expected if f not in mapping]
        completeness = (len(expected) - len(missing)) / len(expected)
        rows.append({
            "source_id":      src.id,
            "source_name":    src.name,
            "completeness":   completeness,
            "missing_fields": missing,
            "expected_fields": expected,
        })
    return rows


def coverage_rollup(session: Session, system_id: int) -> Dict[str, Any]:
    """Wraps cyab_subprofile_service.system_coverage() for the Data Health panel."""
    from ion.services.cyab_subprofile_service import system_coverage
    return system_coverage(session, system_id)


def reconciliation_panel(session: Session, system_id: int) -> Dict[str, Any]:
    """Phase 2 stub. Returns a 'coming soon' marker for the UI to show greyed-out."""
    return {
        "available": False,
        "reason":    "Reconciliation requires CMDB integration (Phase 2).",
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_data_health_service.py -v
```
Expected: PASS (2 of 3; the wrapper test will only pass if `system_coverage` is mocked too — fix by patching it):

If `test_coverage_rollup_wraps_subprofile_service` fails because `system_coverage` calls real DB code, patch it inside the test:

```python
def test_coverage_rollup_wraps_subprofile_service(monkeypatch):
    from ion.services import cyab_data_health_service as svc
    monkeypatch.setattr(
        "ion.services.cyab_subprofile_service.system_coverage",
        lambda s, sid: {"intake_pct": 0.5, "detection_pct": 0.0, "audit_pct": 0.0},
    )
    out = svc.coverage_rollup(MagicMock(), system_id=42)
    assert out["intake_pct"] == 0.5
```

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/services/cyab_data_health_service.py tests/unit/test_cyab_data_health_service.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Data Health service (ingestion freshness, field mapping, coverage rollup)"
```

---

## Task 8: Data Health API + tab template

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_data_health.html`
- Modify: `src/ion/web/cyab_api.py` — add `/systems/{sys_id}/data-health` endpoint
- Modify: `src/ion/web/server.py` — wire context for `data-health` tab
- Test: `tests/integration/test_cyab_data_health_tab.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_data_health_tab.py
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
def system_id(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="dh-test"); s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_data_health_api_returns_three_panels(admin_session, system_id):
    r = admin_session.get(f"/api/cyab/systems/{system_id}/data-health")
    assert r.status_code == 200
    data = r.json()
    assert "ingestion_freshness" in data
    assert "field_mapping_completeness" in data
    assert "coverage_rollup" in data
    assert data.get("reconciliation", {}).get("available") is False


def test_data_health_tab_renders_three_panels(admin_session, system_id):
    r = admin_session.get(f"/cyab/systems/{system_id}/tab/data-health")
    assert r.status_code == 200
    body = r.text.lower()
    assert "ingestion" in body
    assert "field mapping" in body
    assert "coverage" in body
    assert "reconciliation" in body  # phase-2 stub also visible (greyed)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_data_health_tab.py -v
```
Expected: FAIL.

- [ ] **Step 3: Add the API endpoint**

In `src/ion/web/cyab_api.py`, add after the `/systems/{system_id}` GET handler:

```python
@router.get("/systems/{system_id}/data-health", dependencies=[Depends(require_permission("alert:read"))])
async def get_data_health(system_id: int, session: Session = Depends(get_db_session)):
    """Aggregate Data Health signals for a system."""
    from ion.services import cyab_data_health_service as dh
    return {
        "system_id":                  system_id,
        "ingestion_freshness":        dh.ingestion_freshness(session, system_id),
        "field_mapping_completeness": dh.field_mapping_completeness(session, system_id),
        "coverage_rollup":            dh.coverage_rollup(session, system_id),
        "reconciliation":             dh.reconciliation_panel(session, system_id),
    }
```

- [ ] **Step 4: Wire context in `cyab_system_tab` for the data-health tab**

```python
        elif tab_name == "data-health":
            from ion.services import cyab_data_health_service as dh
            ctx["ingestion"] = dh.ingestion_freshness(session, system_id)
            ctx["mapping"]   = dh.field_mapping_completeness(session, system_id)
            ctx["coverage"]  = dh.coverage_rollup(session, system_id)
            ctx["reconciliation"] = dh.reconciliation_panel(session, system_id)
```

- [ ] **Step 5: Create the Data Health template**

```html
<!-- src/ion/web/templates/cyab/tabs/_data_health.html -->
<header class="tw-mb-4">
  <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Data Health</h3>
  <p class="tw-text-slate-500 tw-text-[11px]">Live signals about the data feeding this system. Phase-1: ingestion freshness, field mapping, coverage. Phase-2: reconciliation.</p>
</header>

<div class="tw-grid tw-grid-cols-2 tw-gap-3">

  {# Panel 1: Ingestion freshness #}
  <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
    <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Ingestion freshness</h4>
    {% if not ingestion %}
      <p class="tw-text-slate-500 tw-text-[11px]">No data sources configured.</p>
    {% else %}
      <table class="tw-w-full tw-text-[12px]">
        <tbody>
          {% for r in ingestion %}
            {% set color = {'fresh':'emerald-400','amber':'amber-400','red':'rose-400','unknown':'slate-500'}[r.sla_status] %}
            <tr>
              <td class="tw-py-1"><span class="tw-text-{{ color }}">●</span> {{ r.source_name }}</td>
              <td class="tw-text-slate-500 tw-text-[11px] tw-py-1 tw-text-right">
                {{ r.last_event_at.strftime('%Y-%m-%d %H:%M') if r.last_event_at else 'no events seen' }}
              </td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% endif %}
  </section>

  {# Panel 2: Field mapping completeness #}
  <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
    <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Field mapping</h4>
    {% if not mapping %}
      <p class="tw-text-slate-500 tw-text-[11px]">No data sources configured.</p>
    {% else %}
      {% for r in mapping %}
        <div class="tw-flex tw-items-center tw-gap-2 tw-py-1 tw-text-[12px]">
          <span class="tw-flex-1 tw-text-slate-300">{{ r.source_name }}</span>
          {% if r.completeness is none %}
            <span class="tw-text-slate-500 tw-text-[11px]">no profile</span>
          {% else %}
            {% set pct = (r.completeness * 100) | round(0) | int %}
            <div class="tw-h-1 tw-w-20 tw-bg-slate-800 tw-rounded">
              <div class="tw-h-full tw-bg-cyan-400 tw-rounded" style="width: {{ pct }}%"></div>
            </div>
            <span class="tw-text-cyan-300 tw-text-[11px]">{{ pct }}%</span>
          {% endif %}
        </div>
        {% if r.missing_fields %}
          <p class="tw-text-rose-400 tw-text-[10px] tw-pl-2 tw-pb-1">missing: {{ r.missing_fields | join(', ') }}</p>
        {% endif %}
      {% endfor %}
    {% endif %}
  </section>

  {# Panel 3: Coverage rollup #}
  <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
    <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Coverage rollup</h4>
    <div class="tw-space-y-2 tw-text-[12px]">
      {% for k, label in [('intake_pct','Intake'),('detection_pct','Detection'),('audit_pct','Audit')] %}
        {% set pct = (coverage.get(k, 0) * 100) | round(0) | int if coverage.get(k) is not none else 0 %}
        <div class="tw-flex tw-items-center tw-gap-2">
          <span class="tw-flex-1 tw-text-slate-300">{{ label }}</span>
          <div class="tw-h-1 tw-w-20 tw-bg-slate-800 tw-rounded">
            <div class="tw-h-full tw-bg-emerald-400 tw-rounded" style="width: {{ pct }}%"></div>
          </div>
          <span class="tw-text-emerald-300 tw-text-[11px]">{{ pct }}%</span>
        </div>
      {% endfor %}
    </div>
  </section>

  {# Panel 4: Reconciliation (Phase 2 stub) #}
  <section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3 tw-opacity-50">
    <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Reconciliation</h4>
    <p class="tw-text-slate-500 tw-text-[11px]">{{ reconciliation.reason }}</p>
  </section>

</div>
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_data_health_tab.py -v
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_data_health.html src/ion/web/cyab_api.py src/ion/web/server.py tests/integration/test_cyab_data_health_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Data Health tab + API endpoint (3 panels live, reconciliation stub)"
```

---

## Task 9: Detection Use Cases tab

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_detection.html`
- Test: `tests/integration/test_cyab_detection_tab.py`

**Note:** lifts the use-case-status grid from `cyab_studio.html`. The existing API at `/api/cyab/studio/data-sources/{ds_id}/use-case-status` is reused unchanged.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_detection_tab.py
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
def system_with_subprofile(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    from ion.services.cyab_subprofile_service import seed_catalogue
    seed_catalogue()
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="det-test", subprofile_id=1)
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_detection_tab_lists_use_cases(admin_session, system_with_subprofile):
    r = admin_session.get(f"/cyab/systems/{system_with_subprofile}/tab/detection")
    assert r.status_code == 200
    # Sub-profile catalogue contains detection use cases
    assert "use-case" in r.text or "Use case" in r.text or "detection" in r.text.lower()


def test_detection_tab_shows_status_chips(admin_session, system_with_subprofile):
    r = admin_session.get(f"/cyab/systems/{system_with_subprofile}/tab/detection")
    body = r.text.lower()
    # Statuses: shipped / partial / gap / n/a
    assert any(s in body for s in ("shipped", "partial", "gap", "n/a"))
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_detection_tab.py -v
```
Expected: FAIL.

- [ ] **Step 3: Wire detection context into `cyab_system_tab`**

```python
        elif tab_name in ("detection", "audit-use-cases"):
            from ion.services.cyab_subprofile_service import get_subprofile_full
            sub = get_subprofile_full(session, system.subprofile_id) if system.subprofile_id else None
            # Use cases from catalogue, filtered by tab
            cat = sub.catalogue if sub else {}
            key = "detection_use_cases" if tab_name == "detection" else "audit_use_cases"
            ctx["use_cases"] = cat.get(key, []) if cat else []
            ctx["subprofile"] = sub
            # Per-source status (existing endpoint returns these)
            from sqlalchemy import select
            from ion.models.cyab import CyabDataSource
            ctx["sources"] = session.execute(
                select(CyabDataSource).where(CyabDataSource.system_id == system_id)
            ).scalars().all()
```

- [ ] **Step 4: Create the Detection template**

```html
<!-- src/ion/web/templates/cyab/tabs/_detection.html -->
{% if not subprofile %}
  <p class="tw-text-slate-500 tw-text-[12px]">No sub-profile selected. Detection use cases come from the sub-profile catalogue.</p>
{% elif not use_cases %}
  <p class="tw-text-slate-500 tw-text-[12px]">No detection use cases defined for {{ subprofile.name }}.</p>
{% else %}
  <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-3">
    <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Detection Use Cases</h3>
    <span class="tw-text-slate-500 tw-text-[11px]">{{ use_cases | length }} use cases · {{ sources | length }} sources</span>
  </header>

  <div class="tw-space-y-2">
    {% for uc in use_cases %}
      <article class="use-case-row tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3" data-uc-id="{{ uc.id }}">
        <header class="tw-flex tw-items-center tw-gap-3">
          <h4 class="tw-flex-1 tw-text-cyan-300 tw-text-[13px]">{{ uc.title }}</h4>
          {% for src in sources %}
            <button class="cs-uc-status status-chip tw-px-2 tw-py-0.5 tw-rounded tw-text-[10.5px] tw-font-mono tw-bg-slate-800 tw-text-slate-300"
                    data-source-id="{{ src.id }}" data-uc-id="{{ uc.id }}"
                    title="Cycle status for {{ src.name }}">
              {{ src.name }}
            </button>
          {% endfor %}
          <button class="tw-px-2 tw-py-0.5 tw-bg-cyan-700 tw-text-white tw-text-[10.5px] tw-rounded"
                  hx-post="/api/cyab/studio/use-cases/{{ uc.id }}/tide-stub"
                  hx-target="closest article"
                  hx-swap="afterend">
            + TIDE
          </button>
        </header>
        {% if uc.description %}
          <p class="tw-text-slate-500 tw-text-[11px] tw-mt-1">{{ uc.description }}</p>
        {% endif %}
      </article>
    {% endfor %}
  </div>

  {# Re-use the existing studio JS for status-chip cycling.
     The studio template loads /static/js/cyab_studio.js — that script
     finds .cs-uc-status buttons and POSTs to use-case-status. #}
  <script src="/static/js/cyab_studio.js" defer></script>
{% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_detection_tab.py -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_detection.html src/ion/web/server.py tests/integration/test_cyab_detection_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Detection Use Cases tab — sub-profile catalogue with per-source status"
```

---

## Task 10: Audit Use Cases tab

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_audit_use_cases.html`
- Test: `tests/integration/test_cyab_audit_uc_tab.py`

**Note:** identical shape to Detection (Task 9). Context already wired in Task 9's `if tab_name in ("detection", "audit-use-cases"):` branch.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_audit_uc_tab.py
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
def system_with_subprofile(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    from ion.services.cyab_subprofile_service import seed_catalogue
    seed_catalogue()
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="aud-test", subprofile_id=1)
    s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_audit_uc_tab_returns_partial(admin_session, system_with_subprofile):
    r = admin_session.get(f"/cyab/systems/{system_with_subprofile}/tab/audit-use-cases")
    assert r.status_code == 200
    assert "<html" not in r.text


def test_audit_uc_tab_distinct_from_detection(admin_session, system_with_subprofile):
    r1 = admin_session.get(f"/cyab/systems/{system_with_subprofile}/tab/detection")
    r2 = admin_session.get(f"/cyab/systems/{system_with_subprofile}/tab/audit-use-cases")
    # If the catalogue has separate detection vs audit lists, content should differ
    # (at minimum the section heading does).
    assert "Audit Use Cases" in r2.text
    assert "Audit Use Cases" not in r1.text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_uc_tab.py -v
```

- [ ] **Step 3: Create the template (same shape, different heading)**

```html
<!-- src/ion/web/templates/cyab/tabs/_audit_use_cases.html -->
{% if not subprofile %}
  <p class="tw-text-slate-500 tw-text-[12px]">No sub-profile selected. Audit use cases come from the sub-profile catalogue.</p>
{% elif not use_cases %}
  <p class="tw-text-slate-500 tw-text-[12px]">No audit use cases defined for {{ subprofile.name }}.</p>
{% else %}
  <header class="tw-flex tw-items-baseline tw-justify-between tw-mb-3">
    <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Audit Use Cases</h3>
    <span class="tw-text-slate-500 tw-text-[11px]">{{ use_cases | length }} use cases · {{ sources | length }} sources</span>
  </header>

  <div class="tw-space-y-2">
    {% for uc in use_cases %}
      <article class="use-case-row tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3" data-uc-id="{{ uc.id }}">
        <header class="tw-flex tw-items-center tw-gap-3">
          <h4 class="tw-flex-1 tw-text-amber-300 tw-text-[13px]">{{ uc.title }}</h4>
          {% for src in sources %}
            <button class="cs-uc-status status-chip tw-px-2 tw-py-0.5 tw-rounded tw-text-[10.5px] tw-font-mono tw-bg-slate-800 tw-text-slate-300"
                    data-source-id="{{ src.id }}" data-uc-id="{{ uc.id }}"
                    title="Cycle status for {{ src.name }}">
              {{ src.name }}
            </button>
          {% endfor %}
        </header>
        {% if uc.description %}
          <p class="tw-text-slate-500 tw-text-[11px] tw-mt-1">{{ uc.description }}</p>
        {% endif %}
      </article>
    {% endfor %}
  </div>
  <script src="/static/js/cyab_studio.js" defer></script>
{% endif %}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_uc_tab.py -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_audit_use_cases.html tests/integration/test_cyab_audit_uc_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Audit Use Cases tab"
```

---

## Task 11: Sign-off tab (with governance + de-dupe)

**Files:**
- Create: `src/ion/web/templates/cyab/tabs/_signoff.html`
- Test: `tests/integration/test_cyab_signoff_tab.py`

**Note:** lifts both `section#sign-off` and `section#governance` from `cyab.html`, plus the sign-off panel from `cyab_studio.html`. Replaces all three with a single tab. Existing API endpoints used: `GET /api/cyab/studio/systems/{sys_id}/onboarding-pack` (PDF), `POST /api/cyab/studio/systems/{sys_id}/onboarding-pack/sign`.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_signoff_tab.py
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
def system_id(temp_db):
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="signoff-test", containment_authority="SOC Lead"); s.add(sys); s.commit()
    yield sys.id
    s.close()


def test_signoff_tab_renders(admin_session, system_id):
    r = admin_session.get(f"/cyab/systems/{system_id}/tab/signoff")
    assert r.status_code == 200
    body = r.text.lower()
    assert "sign-off" in body or "sign off" in body


def test_signoff_tab_includes_containment_authority(admin_session, system_id):
    r = admin_session.get(f"/cyab/systems/{system_id}/tab/signoff")
    assert "SOC Lead" in r.text


def test_signoff_tab_links_onboarding_pack_pdf(admin_session, system_id):
    r = admin_session.get(f"/cyab/systems/{system_id}/tab/signoff")
    assert f"/api/cyab/studio/systems/{system_id}/onboarding-pack" in r.text
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_signoff_tab.py -v
```

- [ ] **Step 3: Wire signoff context**

```python
        elif tab_name == "signoff":
            from ion.services import cyab_doc_checklist_service
            ctx["progress"] = cyab_doc_checklist_service.coverage_summary(session, system_id)
            # Existing snapshot/sign-off history (CyabSnapshot rows tagged 'signoff')
            from sqlalchemy import select
            from ion.models.cyab import CyabSnapshot
            ctx["signoffs"] = session.execute(
                select(CyabSnapshot)
                .where(CyabSnapshot.system_id == system_id, CyabSnapshot.kind == "signoff")
                .order_by(CyabSnapshot.created_at.desc())
                .limit(10)
            ).scalars().all()
```

- [ ] **Step 4: Create the Sign-off template**

```html
<!-- src/ion/web/templates/cyab/tabs/_signoff.html -->
<header class="tw-mb-4">
  <h3 class="tw-text-white tw-text-[14px] tw-font-semibold">Sign-off</h3>
  <p class="tw-text-slate-500 tw-text-[11px]">Final approval for this system to enter operational status.</p>
</header>

{# === Governance: containment authority === #}
<section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3 tw-mb-4">
  <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Governance</h4>
  <div class="tw-grid tw-grid-cols-2 tw-gap-3 tw-text-[12px]">
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400">Containment authority</span>
      <input type="text" name="containment_authority" value="{{ system.containment_authority or '' }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"
             hx-put="/api/cyab/systems/{{ system.id }}" hx-trigger="change">
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400">Owner</span>
      <input type="text" name="owner" value="{{ system.owner or '' }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded"
             hx-put="/api/cyab/systems/{{ system.id }}" hx-trigger="change">
    </label>
  </div>
</section>

{# === Onboarding Pack preview & sign === #}
<section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3 tw-mb-4">
  <header class="tw-flex tw-items-center tw-justify-between tw-mb-2">
    <h4 class="tw-text-slate-300 tw-text-[12px]">Onboarding Pack</h4>
    <a href="/api/cyab/studio/systems/{{ system.id }}/onboarding-pack" target="_blank"
       class="tw-text-cyan-400 tw-text-[11.5px] hover:tw-underline">Open PDF →</a>
  </header>

  <div class="tw-text-[12px] tw-text-slate-400 tw-mb-3">
    Onboarding progress: <span class="tw-text-cyan-300">{{ progress.done }} / {{ progress.total }}</span>
    {% if progress.critical_missing %}
      · <span class="tw-text-rose-400">{{ progress.critical_missing | length }} critical items still missing</span>
    {% endif %}
  </div>

  <form hx-post="/api/cyab/studio/systems/{{ system.id }}/onboarding-pack/sign"
        hx-target="#tab-content" hx-swap="innerHTML"
        class="tw-flex tw-items-center tw-gap-2">
    <input name="signed_by" placeholder="Your name" required
           class="tw-flex-1 tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
    <button type="submit"
            class="tw-px-3 tw-py-1 tw-bg-emerald-700 tw-text-white tw-text-[12px] tw-rounded">
      Sign Onboarding Pack
    </button>
  </form>
</section>

{# === Prior sign-offs === #}
<section class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
  <h4 class="tw-text-slate-300 tw-text-[12px] tw-mb-2">Prior sign-offs</h4>
  {% if not signoffs %}
    <p class="tw-text-slate-500 tw-text-[11px]">No sign-offs yet.</p>
  {% else %}
    <ul class="tw-text-[12px] tw-space-y-1">
      {% for so in signoffs %}
        <li class="tw-flex tw-justify-between tw-text-slate-300">
          <span>{{ so.signed_by or 'unknown' }}</span>
          <span class="tw-text-slate-500 tw-text-[11px]">{{ so.created_at.strftime('%Y-%m-%d %H:%M') }}</span>
        </li>
      {% endfor %}
    </ul>
  {% endif %}
</section>
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_signoff_tab.py -v
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/tabs/_signoff.html src/ion/web/server.py tests/integration/test_cyab_signoff_tab.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): Sign-off tab — governance + Onboarding Pack + signoff history (de-duped)"
```

---

## Task 12: /cyab/studio → 301 redirect

**Files:**
- Modify: `src/ion/web/server.py` — replace the `/cyab/studio` page handler with a redirect
- Test: `tests/integration/test_cyab_studio_redirect.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_studio_redirect.py
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


def test_studio_without_system_redirects_to_systems_list(admin_session):
    r = admin_session.get("/cyab/studio", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] in ("/cyab/systems", "/cyab")


def test_studio_with_system_redirects_to_per_system_page(admin_session):
    r = admin_session.get("/cyab/studio?system=123", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "/cyab/systems/123"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_studio_redirect.py -v
```
Expected: FAIL — currently returns 200 (renders studio template).

- [ ] **Step 3: Replace the studio page handler with a redirect**

In `src/ion/web/server.py` find the existing handler at line ~915:

```python
@app.get("/cyab/studio", response_class=HTMLResponse)
async def cyab_studio_page(...):
    return templates.TemplateResponse(...)
```

Replace with:

```python
from fastapi.responses import RedirectResponse

@app.get("/cyab/studio")
async def cyab_studio_redirect(system: int | None = None):
    """301 redirect — /cyab/studio is replaced by /cyab/systems/{id}.

    Kept for one minor version (v0.19.x). Drop in v0.20.0.
    """
    target = f"/cyab/systems/{system}" if system else "/cyab/systems"
    return RedirectResponse(url=target, status_code=301)
```

(Note: `/cyab/systems` doesn't exist yet — comes in Sub-plan B. The redirect target is forward-compatible; in the meantime visiting `/cyab/studio` without a system param will 404 until B ships. That's acceptable since the user is presumably bookmarking specific systems.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_studio_redirect.py -v
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/web/server.py tests/integration/test_cyab_studio_redirect.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "refactor(cyab): /cyab/studio 301 redirects to /cyab/systems/{id} (deprecated)"
```

---

## Task 13: Full per-system page smoke test

**Files:**
- Create: `tests/integration/test_cyab_per_system_smoke.py`

End-to-end test that exercises all 7 tabs against a fully-seeded system to catch any cross-tab regressions before release.

- [ ] **Step 1: Write the smoke test**

```python
# tests/integration/test_cyab_per_system_smoke.py
"""End-to-end smoke test covering the per-system page across all 7 tabs."""

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
def fully_seeded_system(temp_db):
    """A system with sub-profile, data sources, intake answers, and a checklist item done."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem, CyabDataSource
    from ion.services.cyab_subprofile_service import seed_catalogue
    from ion.services.cyab_doc_checklist_service import seed_for_system, update_item, list_for_system
    seed_catalogue()
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(
        name="prod-smoke", department="Identity", subprofile_id=1,
        owner="Alice", containment_authority="SOC Lead",
    )
    s.add(sys); s.flush()
    s.add(CyabDataSource(system_id=sys.id, name="winlog", data_source_type="windows-evtx",
                         field_mapping={"@timestamp": "ts", "host.name": "host"}))
    s.commit()
    seed_for_system(s, sys.id)
    items = list_for_system(s, sys.id)
    if items:
        update_item(s, items[0]["id"], status="done")
    yield sys.id
    s.close()


def test_full_page_loads(admin_session, fully_seeded_system):
    r = admin_session.get(f"/cyab/systems/{fully_seeded_system}")
    assert r.status_code == 200
    assert "prod-smoke" in r.text
    assert "onboarding-progress" in r.text


@pytest.mark.parametrize("tab", [
    "overview", "intake", "sources", "data-health",
    "detection", "audit-use-cases", "signoff",
])
def test_each_tab_loads_for_seeded_system(admin_session, fully_seeded_system, tab):
    r = admin_session.get(f"/cyab/systems/{fully_seeded_system}/tab/{tab}")
    assert r.status_code == 200, f"Tab {tab} returned {r.status_code}"
    assert len(r.text) > 100, f"Tab {tab} returned suspiciously short content"
```

- [ ] **Step 2: Run smoke test**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_per_system_smoke.py -v
```
Expected: PASS (8 cases: 1 page + 7 tabs).

- [ ] **Step 3: Commit**

```bash
cd ~/ION && git add tests/integration/test_cyab_per_system_smoke.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "test(cyab): end-to-end smoke covering per-system page + all 7 tabs"
```

---

## Task 14: Version bump + CHANGELOG + release commit

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/ion/__init__.py`
- Modify: `CHANGELOG.md`

This sub-plan ships a `v0.19.0-rc.1` (release candidate). Sub-plans B and C ship `rc.2` and `rc.3`; final `v0.19.0` is tagged when all three are merged.

- [ ] **Step 1: Bump version files**

```python
# pyproject.toml — line where version = "0.18.1"
version = "0.19.0-rc.1"
```

```python
# src/ion/__init__.py
"""ION - Documentation Template Management System."""
__version__ = "0.19.0-rc.1"
```

- [ ] **Step 2: Add CHANGELOG entry**

Prepend to `CHANGELOG.md`:

```markdown
## v0.19.0-rc.1 — 2026-05-04

### CyAB IA — Foundation + per-system page (Sub-plan A of 3)

- New per-system page at `/cyab/systems/{id}` with sticky onboarding-progress
  header and 7 tabs: Overview, Intake, Sources, Data Health, Detection Use
  Cases, Audit Use Cases, Sign-off.
- New `cyab_data_health_service` aggregates ingestion freshness, field
  mapping completeness, and coverage rollup. Reconciliation panel stubbed
  for Phase 2 (needs CMDB).
- `/cyab/studio` 301 redirects to `/cyab/systems/{id}` (deprecated; drop in
  v0.20.0).
- Section consolidation: `demarcation`, `field-mapping`, `sal-tiers` from
  the legacy `/cyab` page now live in the **Sources** tab. `governance`
  consolidated into the **Sign-off** tab (was previously duplicated).

### Coming in Sub-plan B (v0.19.0-rc.2)
Onboarding wizard at `/cyab/onboard`; portfolio list at `/cyab/systems`;
new `/cyab` Overview landing page.

### Coming in Sub-plan C (v0.19.0-rc.3)
Stack-to-use-cases scoping at `/cyab/scoping`; fleet `/cyab/coverage`
matrix; `/cyab/audit` trail.
```

- [ ] **Step 3: Run the full test suite to confirm no regressions**

```bash
cd ~/ION && PYTHONPATH=src pytest -q
```
Expected: all tests pass (367 baseline + ~25 new from this sub-plan).

- [ ] **Step 4: Commit + tag**

```bash
cd ~/ION && git add pyproject.toml src/ion/__init__.py CHANGELOG.md
git -c user.name=tomo -c user.email=tomo@example.com commit -m "v0.19.0-rc.1 — CyAB IA: foundation + per-system page (sub-plan A)"
git -c user.name=tomo -c user.email=tomo@example.com tag -a v0.19.0-rc.1 -m "v0.19.0-rc.1 — CyAB foundation"
```

- [ ] **Step 5: Push (operator confirms before pushing)**

```bash
cd ~/ION && git push origin main && git push origin v0.19.0-rc.1
```

(Operator may also want to publish a Docker image: `docker build -t ixion36/ion:0.19.0-rc.1 . && docker push ixion36/ion:0.19.0-rc.1`. Not part of the task — release-engineering decision.)

---

## Summary

14 tasks. Each ships an independent, tested commit. Total expected commits: 14 (one per task). Total new test cases: ~25 across 8 test files.

**Spec coverage check:**

| Spec section | Task |
|---|---|
| Per-system page exists at `/cyab/systems/{id}` | 1 |
| Sticky onboarding-progress header | 2 |
| 7 tabs in declared order | 3 (scaffold) + 4-11 (content) |
| Overview = checklist (critical first, grouped) | 4 |
| Intake — sub-profile-driven questions | 5 |
| Sources — data sources + demarcation + SAL + field mapping | 6 |
| Data Health — 3 panels (ingestion + mapping + coverage) | 7-8 |
| Reconciliation Phase-2 stub | 7 (`reconciliation_panel`) + 8 (greyed UI) |
| Detection Use Cases tab | 9 |
| Audit Use Cases tab | 10 |
| Sign-off tab (Onboarding Pack PDF + sign + governance) | 11 |
| `/cyab/studio` → 301 redirect | 12 |
| Section mapping resolved (demarcation/field-mapping/sal-tiers/governance) | embedded in Tasks 6 & 11 |
| End-to-end smoke | 13 |
| Release artefact | 14 |

**Out of scope for this plan (in B or C):**

- New `/cyab/onboard` wizard (Sub-plan B)
- New `/cyab` Overview landing page (Sub-plan B)
- New `/cyab/systems` portfolio list (Sub-plan B)
- `/cyab/scoping` stack-to-use-cases tool (Sub-plan C)
- `/cyab/coverage` fleet matrix (Sub-plan C)
- `/cyab/audit` trail page (Sub-plan C)
- Reconciliation drift live data (Phase 2 — separate plan)
- Per-system Recommendations tab (Phase 2)

**Open assumption (validate at Task 1):** the existing `/cyab` page (`cyab_page` handler in `server.py`) is **not modified by this plan**. It continues to render the legacy `cyab.html` template. Sub-plan B will replace it with the new Overview design. If the legacy page surfacing the same controls (now also in the per-system page) becomes a problem during testing, file an issue and we'll address in B.
