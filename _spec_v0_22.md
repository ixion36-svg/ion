# ION v0.22.0 Architecture Spec

**Status:** Sealed — all blocking open questions resolved 2026-05-07. Ready for implementation.
**Date:** 2026-05-07
**Base version:** v0.21.0 (commit 8819108)
**Stack constraint:** FastAPI + Jinja2 server-rendered HTML + Tailwind CSS. No SPA, no React.

---

## 1. Goals and Non-Goals

### Goals

- **Feature A — MITRE coverage heatmap:** a single page that diffs the CyAB catalogue's per-technique declared coverage against actual technique occurrence in alert triage records and both Workbench pin tables, exposing blind spots and coverage claims that have never been exercised in real cases.
- **Feature B — Timeline annotations:** free-text analyst annotations attached to specific points on the AlertCase and ForensicCase timelines, with a clear mutability posture and an explicit decision on ledger integration.
- Symmetric treatment of both case types (AlertCase and ForensicCase) throughout, maintaining the parity established at v0.20.1.
- All new mutation paths satisfy the TOCTOU rule: ownership/auth checks run inside the service before any commit.

### Non-Goals

- Live MITRE STIX feed or any network fetch of ATT&CK data. Technique metadata stays bundled-snapshot only (air-gap constraint).
- A full ATT&CK matrix navigator (the existing `/api/mitre-navigator/layer` export already covers that use case via TIDE).
- Machine-learning or AI-driven coverage gap recommendations in this version.
- Per-annotation reactions, threading, or mentions.
- Backfilling `mitre_techniques` onto historical `AlertTriage` rows that were created before MITRE tagging was available.

---

## 2. Real-Code Findings

### 2.1 Alert-to-case link table

There is no separate junction table. The link is a direct nullable FK column:

- `src/ion/models/alert_triage.py` line 167-169: `AlertTriage.case_id: Optional[int]` FK to `alert_cases.id`.
- `AlertCase.triage_entries` is the back-populated relationship (line 121-123).
- `AlertCase.source_alert_ids` (line 95) is a JSON list that snapshots the originating ES alert IDs at case creation; this is denormalized metadata, not the live join surface. The live join is `AlertTriage.case_id`.

Heatmap query path for alert-side technique data: join `alert_cases` → `alert_triage` on `alert_triage.case_id = alert_cases.id`, then read `alert_triage.mitre_techniques` (JSON list column, line 173).

### 2.2 MITRE technique field names — consistency audit

| Location | Column / field | Type | Notes |
|---|---|---|---|
| `alert_triage.mitre_techniques` | `mitre_techniques` | `JSON` (Python `list`) | Free list of technique IDs, e.g. `["T1078", "T1059.001"]`. Nullable; many rows will be `NULL`. |
| `case_evidence_pins.mitre_techniques` | `mitre_techniques` | `JSON` (Python `list`) | Same shape. Set at pin-create time or via PATCH. AlertCase Workbench. `src/ion/models/case_evidence.py` line 108. |
| `forensic_case_pins.mitre_techniques` | `mitre_techniques` | `JSON` (Python `list`) | Same shape. ForensicCase Workbench. `src/ion/models/forensic_workbench.py` line 72. |
| `cyab_subprofile_catalogue.py` (JSON blob in `cyab_subprofiles.catalogue_json`) | `detection_use_cases[].mitre_ids` | `list[str]` | Field is named `mitre_ids`, not `mitre_techniques`. Confirmed in `_detection.html` (line 5) and via grep (103 occurrences of `mitre_ids` in the catalogue file). |

**Key finding:** the CyAB catalogue uses `mitre_ids` (plural, inside JSON blob) while all three operational tables use `mitre_techniques` (JSON column). The heatmap service layer must normalize to a common key; the spec uses `technique_id` as the canonical internal name within the new service.

### 2.3 CyAB per-technique coverage state — what exists

The existing `system_coverage()` service (`src/ion/services/cyab_subprofile_service.py` lines 309-384) computes per-sub-profile detection use case shipped percentages, but **it does not expose individual technique IDs**. It aggregates to `{shipped_count, total, pct}` per sub-profile, not per technique.

The `/api/cyab/systems/{sys_id}/coverage` route (line 3839) returns this rollup. There is no existing query that extracts the flat list `[(technique_id, shipped_status)]` from the catalogue for a given system or fleet-wide. That query must be added.

The catalogue blob shape, confirmed in `cyab_subprofile_catalogue.py`:

```json
{
  "detection_use_cases": [
    {
      "id": "uc_kerberoasting",
      "mitre_ids": ["T1558.003"],
      "title": "...",
      ...
    }
  ]
}
```

The `use_case_status` on `cyab_data_sources` is a JSON object keyed by `use_case_id → "shipped"|"partial"|"gap"|"n/a"`. This is the canonical "declared coverage" signal. A technique is considered "catalogued as covered" when at least one detection use case whose `mitre_ids` list contains that technique has `use_case_status = "shipped"` on any data source in the fleet.

### 2.4 Existing `/cyab/coverage` page

`src/ion/web/templates/cyab/coverage.html` and `_coverage_matrix.html` exist and render the fleet health matrix (7 dimensions: ingestion, fields, intake, detections, audit, checklist, sign-off). This is **system-level** health, not technique-level. The new heatmap is a different concept and warrants a distinct page rather than a tab on the existing coverage page.

### 2.5 ForensicCase timeline — existing structure

`src/ion/models/forensics.py` line 546-589: `ForensicTimelineEntry` exists with columns `(id, forensic_case_id, user_id, content, entry_type, timestamp, metadata_json)`. The `entry_type` is a free string defaulting to `"note"`. This is a mutable table (no sha256 chain, no ledger coupling). It is the pre-Workbench note surface for ForensicCase.

**AlertCase has no equivalent timeline table.** AlertCase uses the `Note` model (`alert_triage.py` line 214) via a polymorphic `entity_type/entity_id` join. The `Note` table is also mutable.

This asymmetry is significant for Feature B design (see section 4).

### 2.6 Router prefixes

From `server.py`:

- `cyab_router` mounted at `/api/cyab` (line 288). New routes in `cyab_api.py` must use relative paths: `@router.get("/attack-heatmap")` becomes `/api/cyab/attack-heatmap`.
- `workbench_router` mounted at `/api` with its own `/alert-cases` prefix inside the router (line 309). New AlertCase annotation endpoints go in `workbench_api.py` as `/{case_id}/annotations`.
- `forensic_workbench_router` mounted at `/api/forensics` (line 284). New ForensicCase annotation endpoints go in `forensic_workbench_api.py` as `/cases/{case_id}/annotations`.
- Page routes (non-`/api` GET handlers that return HTML) for CyAB live in `cyab_api.py` with their own prefix-free paths; confirm against the server's page route registrations before adding.

### 2.7 Advisory lock namespace inventory

Currently used namespaces (from memory and code grep):
- `CEVL` (0x4345564C) — AlertCase Workbench ledger
- `FCWL` (0x4643574C) — ForensicCase Workbench ledger
- Background task locks 1001–1017

New namespaces needed for v0.22.0:
- No new advisory lock namespaces needed for Feature A (read-only service).
- Feature B annotation writes are serialized via the **existing** per-case CEVL/FCWL locks if annotations write to the ledger, or need no advisory lock at all if they are a freestanding mutable table (see section 4 for the decision).

---

## 3. Feature A — MITRE Coverage Heatmap

### 3.1 Concept

The page answers: "For every MITRE ATT&CK technique the CyAB catalogue claims to detect, how often does it actually appear in real AlertCase triage records and Workbench pins?" One cell = one technique. Color encodes the relationship between declared coverage and observed occurrence.

Three source signals per technique:
1. **Catalogue declared** — the CyAB catalogue says this technique is covered (shipped use case).
2. **Alert observed** — at least one `AlertTriage.mitre_techniques` entry for this technique, linked to any AlertCase.
3. **Pin observed** — at least one `CaseEvidencePin.mitre_techniques` or `ForensicCasePin.mitre_techniques` entry.

Cell states:
- `covered_exercised` — catalogued as shipped AND seen in at least one case/pin. Green.
- `covered_not_exercised` — catalogued as shipped but ZERO case observations. Amber. This is the primary risk signal.
- `not_covered_seen` — NOT in catalogue (no shipped use case) but appears in real cases/pins. Red. Indicates an undetected threat pattern the catalogue does not address.
- `not_covered_not_seen` — absent from catalogue, absent from cases. Gray. Low signal.

### 3.2 New service: `ion/services/mitre_heatmap_service.py`

```
src/ion/services/mitre_heatmap_service.py
```

No new Alembic migration needed for the service itself — it queries existing tables.

**Public interface:**

```python
def get_heatmap(session: Session) -> dict:
    """
    Returns:
    {
      "generated_at": "ISO-8601",
      "technique_count": int,
      "cells": [
        {
          "technique_id": "T1558.003",
          "technique_label": "Kerberoasting",        # from bundled snapshot
          "tactic_ids": ["TA0006"],                   # from bundled snapshot
          "catalogue_state": "shipped"|"partial"|"gap"|"n/a"|"absent",
          "alert_case_count": int,    # distinct alert_cases where technique seen
          "pin_count": int,           # sum of case_evidence_pins + forensic_case_pins
          "cell_state": "covered_exercised"|"covered_not_exercised"|
                        "not_covered_seen"|"not_covered_not_seen",
        }
      ],
      "summary": {
        "covered_exercised": int,
        "covered_not_exercised": int,
        "not_covered_seen": int,
      }
    }
    """
```

**Query 1 — catalogue declared techniques (fleet-wide):**

```sql
-- Pseudo-SQL; implemented in Python iterating cyab_subprofiles
-- For each subprofile: parse catalogue_json, walk detection_use_cases[].mitre_ids
-- For each technique in mitre_ids: determine best status across all
-- cyab_data_sources that reference this subprofile_id.
-- "best status" = max(rank) where rank: shipped=3, partial=2, n/a=1, gap=0.
```

Reuse `_aggregate_uc_status()` from `cyab_subprofile_service.py` (line 387). The new service imports it directly. The result is a dict `{technique_id: "shipped"|"partial"|"gap"|"n/a"}` for every technique that appears in any detection use case.

**Query 2 — alert-side technique observations:**

```sql
SELECT
    unnested.technique_id,
    COUNT(DISTINCT at.case_id)          AS alert_case_count
FROM alert_triage AS at
     CROSS JOIN LATERAL json_array_elements_text(at.mitre_techniques) AS unnested(technique_id)
WHERE at.case_id IS NOT NULL
  AND at.mitre_techniques IS NOT NULL
GROUP BY unnested.technique_id;
```

SQLAlchemy equivalent uses `func.json_array_elements_text` (Postgres) with a compatibility shim for SQLite (which does not support lateral joins; fall back to Python-side unnesting when `session.bind.dialect.name == "sqlite"`).

**Query 3 — pin observations (both case types):**

```sql
-- AlertCase pins
SELECT
    unnested.technique_id,
    COUNT(DISTINCT cep.alert_case_id)   AS case_count
FROM case_evidence_pins AS cep
     CROSS JOIN LATERAL json_array_elements_text(cep.mitre_techniques) AS unnested(technique_id)
WHERE cep.mitre_techniques IS NOT NULL
  AND cep.finding_status != 'dismissed'
GROUP BY unnested.technique_id

UNION ALL

-- ForensicCase pins
SELECT
    unnested.technique_id,
    COUNT(DISTINCT fcp.forensic_case_id) AS case_count
FROM forensic_case_pins AS fcp
     CROSS JOIN LATERAL json_array_elements_text(fcp.mitre_techniques) AS unnested(technique_id)
WHERE fcp.mitre_techniques IS NOT NULL
  AND fcp.finding_status != 'dismissed'
GROUP BY unnested.technique_id;
```

Sum both counts per technique_id in Python.

**Technique label + tactic metadata:** loaded from a bundled snapshot file (`src/ion/data/attack_techniques.json`), consistent with the air-gap constraint. Format:

```json
[
  {"id": "T1558.003", "name": "Kerberoasting", "tactic_ids": ["TA0006"], "is_subtechnique": true, "parent_id": "T1558"},
  ...
]
```

This file already exists in some form for the TIDE navigator export; confirm at `src/ion/data/` or equivalent path and reuse. If not present, it must be created as part of v0.22.0 from a bundled copy of ATT&CK Enterprise v15 (the same version TIDE uses). The file is generated offline, committed to the repo, never fetched at runtime.

**Sub-technique rollup rule:** `T1558.003` counts toward both `T1558.003` and its parent `T1558`. The heatmap defaults to showing sub-techniques expanded. A query param `?rollup=parent` collapses sub-techniques to the parent row, taking the max cell_state across children. The URL encodes this on page load so the filter form can GET-submit without JS state.

**Edge cases:**

- Technique in catalogue but `mitre_ids` list is empty `[]` — skip, it contributes no heatmap cells.
- No CyAB data sources configured (`use_case_status` is NULL on all rows) — `catalogue_state` = `absent` for all techniques; all cells are either `not_covered_seen` or `not_covered_not_seen`.
- Pin with `mitre_techniques = null` — excluded by `WHERE ... IS NOT NULL`.
- Dismissed pins — excluded by `finding_status != 'dismissed'`.
- Technique appears in real cases but is not in the bundled snapshot (unknown/custom technique IDs) — include in results with `technique_label = technique_id` and `tactic_ids = []`.

### 3.3 New route

Add to `src/ion/web/cyab_api.py` (prefix `/api/cyab`):

```python
@router.get(
    "/attack-heatmap",
    dependencies=[Depends(require_permission("alert:read"))],
)
def get_attack_heatmap(session: Session = Depends(get_db_session)):
    from ion.services.mitre_heatmap_service import get_heatmap
    return get_heatmap(session)
```

Add a page route (HTML response) also in `cyab_api.py`:

```python
@router.get("/page/attack-heatmap", response_class=HTMLResponse)
async def page_attack_heatmap(
    request: Request,
    rollup: str = "subtechnique",
    tactic: str = "",
    state: str = "",
    ...
):
```

Wait — confirm server.py page route registration pattern before landing. The existing CyAB page routes (`/cyab/systems`, `/cyab/coverage`, etc.) are registered in `server.py` NOT in `cyab_api.py`. Check:
<br>
From `server.py` grep output, line 288: `app.include_router(cyab_router, prefix="/api/cyab")`. Page routes in `cyab_api.py` under this prefix would land at `/api/cyab/...` not `/cyab/...`. The existing page routes must be registered separately in `server.py` (as direct `@app.get("/cyab/...")` routes) or the router uses a second include with an empty/different prefix.

**Decision for v0.22.0:** the heatmap page route is `/cyab/attack-heatmap` (no `/api` prefix). Register it in `server.py` as a direct `@app.get` handler (matching the pattern used by other `/cyab/*` pages) or via a dedicated page router. The API data endpoint stays at `/api/cyab/attack-heatmap`.

### 3.4 IA placement

`/cyab/attack-heatmap` — nested under the CyAB section. Add to `cyab/_section_nav.html` alongside Coverage, Audit Feed, and Systems. Nav label: "ATT&CK Heatmap".

This avoids adding a new top-level nav item (the heatmap is a CyAB deliverable, not a standalone SOC tool) and is immediately findable by users already working in CyAB.

### 3.5 Template and render approach

File: `src/ion/web/templates/cyab/attack_heatmap.html`

Extends `base.html`. No SPA. Full server-render on each GET. Filters (tactic, cell_state, rollup) are `<form method="get">` parameters.

**Grid structure:** CSS grid, one cell per technique. Tailwind `grid grid-cols-[repeat(auto-fill,minmax(64px,1fr))]` with each cell being a colored square pill.

Cell markup (one per technique):
```html
<a href="/cyab/systems?technique={{ cell.technique_id }}"
   title="{{ cell.technique_id }} · {{ cell.technique_label }}"
   class="hm-cell {{ cell_class }} text-[9px] font-mono p-1 rounded text-center leading-tight block">
  {{ cell.technique_id }}
</a>
```

Where `cell_class` maps cell_state to Tailwind:
- `covered_exercised` → `bg-emerald-700/80 text-emerald-200`
- `covered_not_exercised` → `bg-amber-700/80 text-amber-200`
- `not_covered_seen` → `bg-rose-700/80 text-rose-200`
- `not_covered_not_seen` → `bg-slate-800 text-slate-600`

The cells are grouped by tactic row. Each tactic is a `<section>` with a heading. Tactic headings come from the bundled snapshot. The page uses a plain HTML table-within-sections structure, not SVG, to keep it accessible and screen-reader friendly, and to work without JS.

**Performance:** the heatmap query is read-only and expected to be fast (< 200 ms) on typical deployments with < 500 CyAB technique mappings and < 10 000 alert triage rows. No caching layer needed for v0.22.0. Add a `Cache-Control: no-cache` header on the API response so browser doesn't stale-serve during a rebuild cycle.

### 3.6 Technique filtering for per-system drilldown (future)

The API accepts an optional `?system_id=N` filter to scope the catalogue declared state to a single system's data sources. The page does not expose this filter in v0.22.0 (the filter form will be extended in a future version), but the service must accept it as an optional parameter now to avoid a breaking change.

---

## 4. Feature B — Timeline Annotations

### 4.1 Problem statement

Both AlertCase and ForensicCase need a way for analysts to attach timestamped free-text notes to specific points in the case timeline — "at T+2h we observed DNS beaconing resume after containment" — distinct from general case notes (which are unanchored in time) and from Workbench pins (which are evidence items, not narrative context).

### 4.2 Mutability decision

**Decision: annotations are a freestanding mutable surface, NOT written to the tamper-evident ledger.**

Justification:

1. **Purpose separation.** The ledger is a forensic chain-of-custody record whose invariant is append-only immutability. Annotations are analytical narrative — they may need correction as an investigation unfolds ("I was wrong about the 14:35 event, it was benign"). Forcing analysts to emit a new ledger row for every typo fix pollutes the chain with noise.
2. **The ledger's integrity guarantee is load-bearing only when the subject is evidence.** The pin/ledger combination covers evidence items: their existence, status, and dismissal. An annotation saying "this timeline point looks suspicious" is not evidence — it is an interpretation. Interpretations belong in the mutable note surface.
3. **Precedent in the existing codebase.** `Note` (AlertCase) and `ForensicTimelineEntry` (ForensicCase) are already mutable tables. Annotations extend the same pattern to a time-anchored variant.
4. **Edit and delete ARE permitted**, but soft-delete only (a `deleted_at` timestamp). Hard-delete is disallowed for the same reason pins are not hard-deleted: if a dispute arises, the existence of a now-deleted annotation may be forensically relevant. The soft-delete pattern means the row persists; `deleted_at IS NOT NULL` filters it from normal display.

**However:** a single ledger row IS written when an annotation is first created, recording the annotation's `id`, `case_id`, and `created_by_id`. This is a lightweight audit trail that the annotation existed (not its content). It provides accountability without encoding the mutable content into the hash chain.

The ledger entry payload for an annotation create is:

```json
{
  "annotation_id": 42,
  "timeline_ts":   "2026-05-07T14:35:00Z",
  "actor_id":      7
}
```

Note: the annotation text itself is NOT in the ledger payload. This preserves the separation of concerns — if the annotation is later edited, the ledger entry is not invalidated. The ledger proves the annotation exists at a point in time; the `case_annotations` table holds the current (possibly edited) content.

Edit and delete events do NOT write additional ledger rows. This is a conscious choice: once we accept that the ledger does not record content, it also should not record content changes. If full audit of edits is needed, that is a separate `annotation_edits` history table (not in v0.22.0 scope — see Open Questions).

### 4.3 Schema

Two new tables, one per case type.

#### `alert_case_annotations`

```sql
CREATE TABLE alert_case_annotations (
    id              SERIAL PRIMARY KEY,
    alert_case_id   INTEGER NOT NULL REFERENCES alert_cases(id) ON DELETE CASCADE,
    created_by_id   INTEGER NOT NULL REFERENCES users(id),
    timeline_ts     TIMESTAMP NOT NULL,   -- the point in time being annotated
    body            TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT now(),
    updated_at      TIMESTAMP NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMP,            -- soft-delete; NULL = active
    CONSTRAINT ck_aca_body_not_empty CHECK (length(body) > 0)
);

CREATE INDEX ix_aca_case ON alert_case_annotations(alert_case_id);
CREATE INDEX ix_aca_created_by ON alert_case_annotations(created_by_id);
CREATE INDEX ix_aca_timeline_ts ON alert_case_annotations(alert_case_id, timeline_ts);
```

#### `forensic_case_annotations`

```sql
CREATE TABLE forensic_case_annotations (
    id               SERIAL PRIMARY KEY,
    forensic_case_id INTEGER NOT NULL REFERENCES forensic_cases(id) ON DELETE CASCADE,
    created_by_id    INTEGER NOT NULL REFERENCES users(id),
    timeline_ts      TIMESTAMP NOT NULL,
    body             TEXT NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT now(),
    updated_at       TIMESTAMP NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMP,
    CONSTRAINT ck_fca_body_not_empty CHECK (length(body) > 0)
);

CREATE INDEX ix_fca_case ON forensic_case_annotations(forensic_case_id);
CREATE INDEX ix_fca_created_by ON forensic_case_annotations(created_by_id);
CREATE INDEX ix_fca_timeline_ts ON forensic_case_annotations(forensic_case_id, timeline_ts);
```

SQLAlchemy models: `AlertCaseAnnotation` in `src/ion/models/alert_triage.py` (logical home, same file as `AlertCase`), `ForensicCaseAnnotation` in `src/ion/models/forensics.py`.

Do not add a `body_length` column — the CHECK constraint enforces non-empty; the API layer enforces max length (2000 chars) in the Pydantic schema.

### 4.4 Ledger integration — implementation detail

When `annotation_service.create(session, case_id, body, timeline_ts, actor_id)` is called:

1. Validate inputs (ownership, body non-empty, timeline_ts is a valid datetime).
2. Insert the `alert_case_annotations` row, flush (don't commit yet).
3. Call `case_ledger_service.append(session, case_id, action="annotation_created", actor_id=actor_id, payload={"annotation_id": new_row.id, "timeline_ts": timeline_ts.isoformat(), "actor_id": actor_id})` — this uses the existing CEVL advisory lock.
4. `session.commit()` once. Both rows land atomically.

ForensicCase mirrors this with `forensic_ledger_service.append()` (FCWL namespace).

The annotation services are named:
- `src/ion/services/annotation_service.py` — AlertCase annotations
- `src/ion/services/forensic_annotation_service.py` — ForensicCase annotations

Each has the methods: `create`, `list_active`, `update`, `soft_delete`. Update and soft_delete do NOT call the ledger service.

TOCTOU rule: `update` and `soft_delete` must verify `annotation.alert_case_id == url_case_id` BEFORE any mutation, raising a service-level `AnnotationError` (maps to 404) if mismatch.

### 4.5 Permissions

Reuse existing gates — no new permissions:

| Operation | Permission required |
|---|---|
| List annotations on AlertCase | `case:read` |
| Create annotation on AlertCase | `case:update` |
| Edit/delete own annotation on AlertCase | `case:update` |
| Edit/delete any annotation on AlertCase | `case:close` (supervisor-level) |
| All ForensicCase equivalents | `forensic:update` / `forensic:create` |

"Own annotation" means `annotation.created_by_id == current_user.id`. The service must check this before allowing an edit; a user with only `case:update` can only edit their own annotations. A user with `case:close` can edit any annotation on the case.

### 4.6 API endpoints

**AlertCase annotations** — added to `src/ion/web/workbench_api.py` (prefix `/api/alert-cases` from the router's own prefix):

```
GET    /{case_id}/annotations          — list active annotations, sorted by timeline_ts asc
POST   /{case_id}/annotations          — create annotation
PATCH  /{case_id}/annotations/{ann_id} — edit body and/or timeline_ts
DELETE /{case_id}/annotations/{ann_id} — soft-delete
```

**ForensicCase annotations** — added to `src/ion/web/forensic_workbench_api.py` (mounted at `/api/forensics`):

```
GET    /cases/{case_id}/annotations
POST   /cases/{case_id}/annotations
PATCH  /cases/{case_id}/annotations/{ann_id}
DELETE /cases/{case_id}/annotations/{ann_id}
```

Pydantic schemas:

```python
class AnnotationCreate(BaseModel):
    timeline_ts: datetime
    body: str = Field(..., min_length=1, max_length=2000)

class AnnotationUpdate(BaseModel):
    timeline_ts: Optional[datetime] = None
    body: Optional[str] = Field(None, min_length=1, max_length=2000)
```

Response shape (both case types):

```json
{
  "id": 42,
  "case_id": 7,
  "timeline_ts": "2026-05-07T14:35:00",
  "body": "DNS beaconing resumed after containment.",
  "created_by_id": 3,
  "created_by_username": "analyst1",
  "created_at": "2026-05-07T16:10:00",
  "updated_at": "2026-05-07T16:10:00"
}
```

`deleted_at` is never returned to the caller (soft-deleted rows are excluded by the list query).

### 4.7 UI surface

**Scope decision (sealed):** annotations render **only inside the Workbench panel** for v0.22.0 — no unified case-timeline view is built in this version. Operator chose this over a unified timeline to keep v0.22.0 scope tight; a unified timeline can land in a later version if it earns its place.

**AlertCase:** Workbench panel in `src/ion/web/templates/cases.html` (the `renderPanelContent` function). Annotations appear as a dedicated section below the Workbench pins list — collapsible, sorted by `timeline_ts` descending. Visually distinct from pins via a left-border accent color (indigo) so the analyst can scan the Workbench and instantly see narrative vs. evidence.

**ForensicCase:** ForensicCase Workbench panel in `src/ion/web/templates/forensic_case_detail.html` (or wherever the existing `forensic_case_pins` list renders). Same dedicated-section pattern. Does NOT interleave with `ForensicTimelineEntry` items in v0.22.0 — those remain the existing timeline section, separate from annotations.

**Create interaction:** "Add annotation" button inside the annotations section. Click expands an inline form (not a modal) with a datetime picker (`<input type="datetime-local">`) and a textarea. POST to the API endpoint, response either reloads the page or swaps the annotations section partial (HTMX-style if wiring is already in place).

**Edit/delete:** inline pencil and trash icons on each annotation card, visible only to the annotation's author or users with `case:close`. Edit click replaces the card content with the inline form; delete click confirms then POSTs delete and removes the card. Same pattern as existing note edit on cases.

---

## 5. Migration Plan

### 5.1 Alembic revisions

Two revisions, applied in order:

**Revision 1: `v022_feature_b_annotations`**

```
Creates: alert_case_annotations, forensic_case_annotations
No backfill needed — both tables start empty.
Rollback: DROP TABLE alert_case_annotations; DROP TABLE forensic_case_annotations;
```

No existing data is touched. The only risk is a long table-create on a very large Postgres instance, which is negligible for new empty tables.

**Revision 2: not needed — Feature A is purely additive code + bundled JSON**

`src/ion/data/attack_techniques.json` does NOT currently exist (verified — `src/ion/data/` holds `cyab_scoping_questions.json`, KB articles, `pii_fields.yaml`, `skills/`, but no ATT&CK snapshot). v0.22.0 must ship the file. Generation pattern follows the KEV bundled-snapshot precedent (per `project_ion_kev_design.md`):

1. **One-time generation script** (committed to repo at `scripts/generate_attack_techniques_json.py` or equivalent) — pulls the ATT&CK Enterprise v15.1 STIX bundle from MITRE's GitHub once during dev, extracts `(technique_id, name, tactic_ids, is_subtechnique, parent_technique_id)`, writes the JSON.
2. **Committed JSON** at `src/ion/data/attack_techniques.json` — air-gap deployments consume this file directly, never the live STIX feed.
3. **Refresh cadence** — re-run the generation script at every ION minor-version bump as part of release ritual (same ritual as KEV refresh).
4. **Dockerfile** — already copies `src/ion/data/` into `/app/src/ion/data/`, no Dockerfile change required.

No Alembic revision is needed for Feature A — the heatmap queries existing tables exclusively and the JSON is filesystem-resident.

### 5.2 Data backfill

None required for either feature. Historical alert triage rows with `mitre_techniques = NULL` will appear as zero-observation on the heatmap; this is correct and expected. Analysts can backfill technique tags on open cases manually via the existing PATCH endpoint on AlertTriage.

### 5.3 Rollback safety

Feature A is additive read-only. Rolling back the deployment means removing the new route and template — no data to reverse.

Feature B: if a rollback occurs after annotations have been created, the `alert_case_annotations` and `forensic_case_annotations` tables will have rows but the application code will not reference them. Run the Alembic downgrade to drop the tables. The ledger rows written by annotation creation (in `case_evidence_ledger` / `forensic_case_ledger`) will remain. These are phantom entries referencing annotation IDs that no longer exist in the dropped tables. On re-upgrade, annotation IDs restart at 1 and could collide with the phantom ledger payload `annotation_id` values. Mitigation: on re-upgrade after rollback, run a manual SQL to clear phantom ledger rows where `action = 'annotation_created'` before recreating the annotation tables. Document in the RUNBOOK.

### 5.4 Version-bump checklist (release ritual)

Past releases have rotted version strings in less-obvious files. v0.22.0 must bump every location listed below, *and* this checklist becomes the canonical reference for every future release.

**Verified rot as of 2026-05-07** (will be cleaned up in the v0.22.0 bump commit):

| File | Line | Current value | Comment |
|---|---|---|---|
| `src/ion/__init__.py` | 3 | `__version__ = "0.19.19"` | **Load-bearing** — feeds `{{ ion_version }}` into every Jinja template. UI has been showing 0.19.19 for 13 releases. |
| `README.md` | 3 | `version-0.9.98-blue` badge | Public-facing; rotted by ~12 minor versions. |
| `Dockerfile` | 42 | `org.opencontainers.image.version="0.11.6"` | OCI label; rotted by ~10 minor versions. |
| `.env.deploy` | 6, 11 | `0.11.21` (comment + live `ION_VERSION`) | Deployment default; rotted by ~10 minor versions. |

**Live (currently correct) version locations — must still bump in v0.22.0:**

| File | Line | Pattern |
|---|---|---|
| `pyproject.toml` | 7 | `version = "0.22.0"` |
| `docker-compose.yml` | 101, 260 | `image: ixion36/ion:${ION_VERSION:-0.22.0}` (two services) |
| `CHANGELOG.md` | top | new `## v0.22.0 — <release-date>` entry above v0.21.0 |
| `SECURITY_ASSESSMENT.md` | severity table, "Application Version" header | add v0.22.0 column + Net-New Surfaces section |

**Bump-commit content:**

A single commit `chore(release): v0.22.0 — version bumps + CHANGELOG + SECURITY_ASSESSMENT delta`, applied at the very end of the release ritual *after* feature commits land. The commit touches all eight files above.

**Sanity check (must run after bump commit, must return zero hits):**

```bash
# In the ixion repo root, exclude historical changelog references:
grep -RnE "0\.19\.19|0\.11\.6|0\.9\.98|0\.11\.21" \
  --exclude-dir=.git \
  --exclude=CHANGELOG.md \
  --exclude=SECURITY_ASSESSMENT.md \
  --exclude=_spec_v0_22.md \
  | grep -v "^Binary file"
# expected: empty output

# v0.21.0 references should remain only as historical annotations in code comments
# and changelog entries — must NOT appear in pyproject.toml, docker-compose.yml,
# src/ion/__init__.py, Dockerfile, README.md, or .env.deploy.
grep -nE "version *= *\"0\.21\.0\"|ION_VERSION:-0\.21\.0|__version__ *= *\"0\.21\.0\"|\"0\.21\.0\"|=0\.21\.0\\b|version-0\.21\.0" \
  pyproject.toml docker-compose.yml src/ion/__init__.py Dockerfile README.md .env.deploy
# expected: empty output
```

**Per-release reminder:** add this checklist as a heading in `RUNBOOK.md` ("Release ritual — version bump") so future versions don't rot.

---

## 6. Smoke Test Plan

All tests use the existing HTTP API smoke-test framework (real Postgres, not SQLite-only). File locations follow the existing pattern in `tests/`.

### 6.1 Feature A — MITRE heatmap (new file: `tests/test_mitre_heatmap.py`)

| # | Test | Assertion |
|---|---|---|
| 1 | GET `/api/cyab/attack-heatmap` unauthenticated | 401 |
| 2 | GET `/api/cyab/attack-heatmap` with `alert:read` permission | 200, `cells` is a list, `summary` has required keys |
| 3 | No MITRE-tagged alerts in DB | `alert_case_count = 0` for all cells, no 500 |
| 4 | Seed one AlertTriage with `mitre_techniques=["T1558.003"]` linked to a case; seed CyAB catalogue with `T1558.003` as shipped | cell for T1558.003 has `cell_state="covered_exercised"`, `alert_case_count=1` |
| 5 | Seed one CaseEvidencePin with `mitre_techniques=["T1078"]`; T1078 NOT in catalogue | cell for T1078 has `cell_state="not_covered_seen"`, `pin_count >= 1` |
| 6 | Catalogue has T1046 as shipped; no alert/pin observations | cell for T1046 has `cell_state="covered_not_exercised"` |
| 7 | ForensicCasePin with `mitre_techniques=["T1003.001"]` is counted | `pin_count >= 1` for T1003.001 |
| 8 | Dismissed pin NOT counted | create pin, dismiss it, verify `pin_count` does not include it |

### 6.2 Feature B — Annotations (append to `tests/test_forensics_workbench.py` for ForensicCase; new file `tests/test_alert_case_annotations.py` for AlertCase)

| # | Test | Assertion |
|---|---|---|
| 1 | POST annotation with valid body and timeline_ts | 201, annotation id returned |
| 2 | GET annotations list | returns created annotation, `deleted_at` absent from payload |
| 3 | PATCH annotation body | 200, updated body returned |
| 4 | DELETE annotation | 200; subsequent GET list does not include it |
| 5 | POST annotation writes a ledger row with `action="annotation_created"` | GET `/ledger` shows the row; verify payload contains `annotation_id` |
| 6 | Cross-case annotation PATCH rejected | create annotation on case A, PATCH via case B's URL → 404, annotation unchanged |
| 7 | Cross-case annotation DELETE rejected | same pattern → 404, annotation not soft-deleted |
| 8 | POST annotation with empty body | 422 |
| 9 | POST annotation with body > 2000 chars | 422 |
| 10 | Edit another user's annotation without `case:close` | 403 |
| 11 | Ledger chain still valid after annotation create | GET `/ledger/verify` returns `is_valid=true` |

---

## 7. Open Questions

### Resolved 2026-05-07

1. **Bundled ATT&CK snapshot file** — RESOLVED. `src/ion/data/attack_techniques.json` does NOT exist; v0.22.0 ships generation script + committed JSON for ATT&CK Enterprise v15.1. See §5.1 Revision 2.
2. **Annotation edit audit trail** — RESOLVED. No `annotation_edits` history table in v0.22.0. Single `annotation_created` ledger row records existence + actor; subsequent edits/deletes do not write ledger rows. If a future compliance ask requires edit audit, add it then — current threat model does not require it.
3. **AlertCase unified timeline view** — RESOLVED. Annotations render in the Workbench panel only. No unified timeline view is built in v0.22.0. See §4.7.

### Still open — recommend defaults, confirm before implementation

4. **Heatmap page auth level:** The heatmap queries `alert_triage.mitre_techniques` which may leak information about real alert activity. The spec gates it behind `alert:read`. Confirm this is the appropriate minimum permission level for this environment.

5. **SQLite lateral join compatibility:** The heatmap service includes a SQLite fallback for the lateral-join technique unnesting. Is SQLite still used in development (confirmed yes from architecture notes) and do the v0.22.0 smoke tests run against Postgres or SQLite? If smoke tests run only against SQLite, the Postgres LATERAL query path is untested until deployment. Recommend running smoke tests against Postgres (which the test harness already supports) and documenting the SQLite fallback as dev-only.

6. **Annotation `timeline_ts` timezone:** Should `timeline_ts` be stored as UTC always (with client submitting UTC) or should the API accept timezone-aware ISO-8601 and normalize to UTC on write? The existing `CaseEvidenceLedger.timestamp` uses `DateTime` without timezone. For consistency, store as UTC naive (matching ledger convention). Confirm this does not conflict with any frontend display requirements.

---

## 8. Risk Register

### Risk 1: Heatmap query performance on large alert_triage tables

**Description:** The `json_array_elements_text(mitre_techniques)` lateral unnesting query runs against the full `alert_triage` table (potentially tens of thousands of rows). In Postgres, lateral unnesting is efficient but unindexed on the JSON content. At 50,000 alert rows, the unnest + group-by may take 2-5 seconds.

**Likelihood:** Medium (grows with usage).

**Mitigation:** Add a partial index `CREATE INDEX ix_at_mitre_notnull ON alert_triage(id) WHERE mitre_techniques IS NOT NULL` to narrow the scan to rows that actually have technique data (likely a small fraction). Alternatively, pre-compute the heatmap as a background task (lock ID 1018, 15-minute interval) and cache the result in a `heatmap_snapshot` table or Redis. For v0.22.0, implement the partial index only. Background compute is the v0.22.1 tuning path if response time is unacceptable in production.

### Risk 2: Annotation ledger phantom rows after rollback-then-re-upgrade

**Description:** If Feature B is deployed, annotations are created, then a rollback drops the annotation tables, then re-upgrade recreates them, the ledger contains phantom rows with `action="annotation_created"` referencing annotation IDs that no longer exist. On chain verification, these rows are structurally valid (the hash chain is intact) but the payload references non-existent entities. This could confuse auditors.

**Likelihood:** Low (rollbacks are rare; rollback-then-re-upgrade is even rarer).

**Mitigation:** Document the manual cleanup step in `docs/RUNBOOK.md` under "Rolling back v0.22.0". Add a `ledger_verify_strict` endpoint flag (future) that can report orphaned payload references. For v0.22.0, the RUNBOOK entry is sufficient.

### Risk 3: MITRE technique ID format inconsistency between sources

**Description:** The CyAB catalogue uses `"T1558.003"` (period-separated sub-technique notation). `AlertTriage.mitre_techniques` is populated by ES alert metadata and possibly by Bob's LLM output, both of which may use different formats (`"t1558.003"` lowercase, `"T1558"` parent-only when sub-technique is not known, `"1558.003"` without the T prefix). The heatmap will fail to match if normalization is not applied.

**Likelihood:** High (LLM outputs are inconsistent; ES alert metadata varies by rule source).

**Mitigation:** The heatmap service's normalization step converts all technique IDs to uppercase with the `T` prefix before any comparisons: `tid.strip().upper().lstrip("T").replace(".", ".") → "T" + cleaned`. Apply this to both the catalogue side and the observation side. Add a unit test asserting that `"t1558.003"`, `"T1558.003"`, and `"1558.003"` all normalize to `"T1558.003"`. This test runs in the SQLite-compatible unit test suite (no DB required).
