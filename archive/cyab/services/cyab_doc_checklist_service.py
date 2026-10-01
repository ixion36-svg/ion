"""CyAB Documentation Checklist service (v0.18.0).

Manages the per-system documentation checklist (HLD, LLD, network
topology, etc.). The default catalogue lives in this module — adding /
removing a default item is a code change. Per-system rows are
lazy-seeded on first access so existing systems get the checklist
without a backfill migration.

Three "critical" items (HLD, NETWORK_TOPOLOGY, OWNERS) drive the soft
sign-off gate on the Onboarding Pack — analyst sees a warning if any
critical item is not Done; can override with a one-click acceptance.

Status semantics:
    done           document exists, link captured
    in_progress    being authored / reviewed
    missing        gap, no document yet
    na             not applicable to this system (e.g. DR/BCP for a
                   stateless dev tool)
    unknown        not yet investigated — initial state for new rows

Categories group items in the UI:
    design         architecture & design (HLD, LLD, topology, ...)
    operational    runbooks, ownership, recovery
    security       threat model, risk, RBAC
    compliance     classification, IR plan, change mgmt
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from ion.models.cyab_doc_checklist import (
    ALL_CATEGORIES,
    ALL_STATUSES,
    CATEGORY_COMPLIANCE,
    CATEGORY_DESIGN,
    CATEGORY_OPERATIONAL,
    CATEGORY_SECURITY,
    STATUS_DONE,
    STATUS_NA,
    STATUS_UNKNOWN,
    CyabDocChecklistItem,
)

logger = logging.getLogger(__name__)


# ── Default catalogue ────────────────────────────────────────────────────
#
# The 20-item starter list. Adding a new entry here ALSO seeds it for
# every existing system the next time their checklist is fetched (the
# lazy-seed step skips kinds that already exist on the system, so this
# is idempotent and safe).
_DEFAULT_CHECKLIST: List[Dict[str, Any]] = [
    # ── Architecture & Design ──
    {"kind": "HLD",                "label": "High-Level Design",                       "category": CATEGORY_DESIGN,      "is_critical": True},
    {"kind": "LLD",                "label": "Low-Level Design",                        "category": CATEGORY_DESIGN,      "is_critical": False},
    {"kind": "NETWORK_TOPOLOGY",   "label": "Network Topology Diagram",                "category": CATEGORY_DESIGN,      "is_critical": True},
    {"kind": "DATA_FLOW",          "label": "Data Flow Diagram",                       "category": CATEGORY_DESIGN,      "is_critical": False},
    {"kind": "LOGGING_ARCH",       "label": "Logging & Telemetry Architecture",        "category": CATEGORY_DESIGN,      "is_critical": False},

    # ── Operational ──
    {"kind": "RUNBOOK",            "label": "Runbook / Operational SOP",               "category": CATEGORY_OPERATIONAL, "is_critical": False},
    {"kind": "CMDB",               "label": "Asset Inventory / CMDB Entry",            "category": CATEGORY_OPERATIONAL, "is_critical": False},
    {"kind": "OWNERS",             "label": "Owners & Escalation Matrix",              "category": CATEGORY_OPERATIONAL, "is_critical": True},
    {"kind": "BACKUP",             "label": "Backup & Recovery Plan",                  "category": CATEGORY_OPERATIONAL, "is_critical": False},
    {"kind": "DR_BCP",             "label": "Disaster Recovery / Business Continuity", "category": CATEGORY_OPERATIONAL, "is_critical": False},
    {"kind": "DECOMMISSIONING",    "label": "Decommissioning Plan",                    "category": CATEGORY_OPERATIONAL, "is_critical": False},

    # ── Security & Risk ──
    {"kind": "THREAT_MODEL",       "label": "Threat Model",                            "category": CATEGORY_SECURITY,    "is_critical": False},
    {"kind": "RISK_ASSESSMENT",    "label": "Risk Assessment",                         "category": CATEGORY_SECURITY,    "is_critical": False},
    {"kind": "VULN_REPORT",        "label": "Vulnerability Assessment / Pentest",      "category": CATEGORY_SECURITY,    "is_critical": False},
    {"kind": "AUTH_RBAC",          "label": "Authentication & Access Control (RBAC)",  "category": CATEGORY_SECURITY,    "is_critical": False},

    # ── Compliance ──
    {"kind": "DATA_CLASSIFICATION","label": "Data Classification",                     "category": CATEGORY_COMPLIANCE,  "is_critical": False},
    {"kind": "COMPLIANCE_MAPPING", "label": "Compliance / Controls Mapping",           "category": CATEGORY_COMPLIANCE,  "is_critical": False},
    {"kind": "IR_PLAN",            "label": "Incident Response Plan (system-specific)","category": CATEGORY_COMPLIANCE,  "is_critical": False},
    {"kind": "CHANGE_MGMT",        "label": "Change Management Process",               "category": CATEGORY_COMPLIANCE,  "is_critical": False},
    {"kind": "VENDOR_DOCS",        "label": "Vendor / License Documentation",          "category": CATEGORY_COMPLIANCE,  "is_critical": False},
]


# Stable category ordering for UI rendering — mirrors the catalogue order.
_CATEGORY_ORDER = [CATEGORY_DESIGN, CATEGORY_OPERATIONAL, CATEGORY_SECURITY, CATEGORY_COMPLIANCE]
_CATEGORY_INDEX = {c: i for i, c in enumerate(_CATEGORY_ORDER)}


# ── Lazy seed / list ─────────────────────────────────────────────────────


def seed_for_system(session: Session, system_id: int) -> int:
    """Insert default rows for ``system_id`` that don't already exist.

    Idempotent: re-running picks up newly-added defaults without
    touching existing rows. Returns the number of rows inserted.
    """
    existing_kinds = {
        k for (k,) in session.query(CyabDocChecklistItem.kind)
        .filter(CyabDocChecklistItem.system_id == system_id)
    }
    inserted = 0
    for spec in _DEFAULT_CHECKLIST:
        if spec["kind"] in existing_kinds:
            continue
        session.add(CyabDocChecklistItem(
            system_id=system_id,
            kind=spec["kind"],
            label=spec["label"],
            category=spec["category"],
            is_critical=bool(spec.get("is_critical", False)),
            is_custom=False,
            status=STATUS_UNKNOWN,
        ))
        inserted += 1
    if inserted:
        session.commit()
    return inserted


def list_for_system(session: Session, system_id: int) -> List[Dict[str, Any]]:
    """Return all checklist items for a system, sorted by category then
    label. Triggers a one-shot lazy seed if the system has no rows yet.
    """
    seed_for_system(session, system_id)
    rows = (
        session.query(CyabDocChecklistItem)
        .filter(CyabDocChecklistItem.system_id == system_id)
        .all()
    )
    rows.sort(key=lambda r: (
        _CATEGORY_INDEX.get(r.category, 99),
        0 if r.is_critical else 1,
        r.label.lower(),
    ))
    return [r.to_dict() for r in rows]


# ── Mutations ────────────────────────────────────────────────────────────


def update_item(
    session: Session,
    item_id: int,
    *,
    status: Optional[str] = None,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    label: Optional[str] = None,
    is_critical: Optional[bool] = None,
    user_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Update one checklist row. Returns the updated row dict, or None
    if the item doesn't exist. Callers should validate ``status``
    against ``ALL_STATUSES`` before calling.
    """
    row = session.get(CyabDocChecklistItem, item_id)
    if row is None:
        return None
    if status is not None:
        if status not in ALL_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")
        row.status = status
    if url is not None:
        row.url = url.strip() or None
    if notes is not None:
        row.notes = notes.strip() or None
    # Default rows: label + is_critical are not editable (catalogue-managed).
    # Custom rows: both editable.
    if row.is_custom:
        if label is not None and label.strip():
            row.label = label.strip()
        if is_critical is not None:
            row.is_critical = bool(is_critical)
    if user_id is not None:
        row.updated_by_id = user_id
    session.commit()
    return row.to_dict()


def add_custom_item(
    session: Session,
    system_id: int,
    *,
    kind: str,
    label: str,
    category: str = CATEGORY_DESIGN,
    is_critical: bool = False,
    status: str = STATUS_UNKNOWN,
    url: Optional[str] = None,
    notes: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a custom (operator-added) checklist row beyond the
    default catalogue. ``kind`` must be unique per system.
    """
    if not kind or not kind.strip():
        raise ValueError("kind is required")
    if not label or not label.strip():
        raise ValueError("label is required")
    if category not in ALL_CATEGORIES:
        raise ValueError(f"Invalid category: {category!r}")
    if status not in ALL_STATUSES:
        raise ValueError(f"Invalid status: {status!r}")
    # Sanity: don't shadow a default kind with is_custom=True.
    existing = (
        session.query(CyabDocChecklistItem)
        .filter_by(system_id=system_id, kind=kind.strip())
        .first()
    )
    if existing:
        raise ValueError(f"kind {kind!r} already exists on system {system_id}")
    row = CyabDocChecklistItem(
        system_id=system_id,
        kind=kind.strip(),
        label=label.strip(),
        category=category,
        is_critical=bool(is_critical),
        is_custom=True,
        status=status,
        url=(url or "").strip() or None,
        notes=(notes or "").strip() or None,
        updated_by_id=user_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.to_dict()


def delete_custom_item(session: Session, item_id: int) -> bool:
    """Remove a custom row. Default-catalogue rows cannot be deleted —
    returns False for those (callers should surface a 400). Returns True
    on successful delete, False if not found OR not custom.
    """
    row = session.get(CyabDocChecklistItem, item_id)
    if row is None or not row.is_custom:
        return False
    session.delete(row)
    session.commit()
    return True


# ── Coverage rollup ──────────────────────────────────────────────────────


def coverage_summary(session: Session, system_id: int) -> Dict[str, Any]:
    """Counts used by the dashboard / Studio header / sign-off gate.

    Critical-missing means status != done AND status != na (so an
    explicit N/A doesn't drag down the gate). The Pack export uses
    ``critical_missing`` as the soft-gate input.
    """
    seed_for_system(session, system_id)
    rows = (
        session.query(CyabDocChecklistItem)
        .filter(CyabDocChecklistItem.system_id == system_id)
        .all()
    )
    total = len(rows)
    by_status: Dict[str, int] = {s: 0 for s in ALL_STATUSES}
    critical_total = 0
    critical_done = 0
    critical_missing_kinds: List[str] = []
    for r in rows:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        if r.is_critical:
            critical_total += 1
            if r.status == STATUS_DONE:
                critical_done += 1
            elif r.status != STATUS_NA:
                critical_missing_kinds.append(r.kind)
    return {
        "total":            total,
        "by_status":        by_status,
        "done":             by_status.get(STATUS_DONE, 0),
        "critical_total":   critical_total,
        "critical_done":    critical_done,
        "critical_missing": critical_missing_kinds,
        "completion_pct":   round(by_status.get(STATUS_DONE, 0) * 100 / total) if total else 0,
    }


def default_catalogue_view() -> List[Dict[str, Any]]:
    """Read-only view of the default catalogue (for UI 'reset to default')."""
    return [dict(spec) for spec in _DEFAULT_CHECKLIST]
