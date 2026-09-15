"""DE content-pack export / import — Phase 4 of the Detection Engineering module.

A **content pack** is a portable bundle of *reusable* DE content — system quirks
and detection proposals — so a curated baseline can move between air-gapped ION
deployments. It carries content only, never local identity or decisions.

Import safety is the whole point (mirrors the anti-abuse posture of the models):

* Every quirk is re-created through ``de_quirk_service.raise_quirk`` → lands
  ``pending`` with the importer as ``raised_by`` and **no verifier**, so
  separation-of-duties still requires a different person to verify before it has
  any effect. Wildcard / global scopes are rejected by that same path.
* Every proposal is re-created through ``de_proposal_service.create_proposal`` →
  lands ``draft`` with no decision/outcome, so an "applied" verdict can never be
  imported; the local analyst must decide.
* Duplicates (same content signature) are skipped, so re-import is safe.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from ion.models.detection_proposal import DetectionProposal, DetectionProposalStatus
from ion.models.system_quirk import SystemQuirk, SystemQuirkStatus
from ion.services import de_proposal_service, de_quirk_service

logger = logging.getLogger(__name__)

PACK_SCHEMA = 1


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _quirk_sig(title: str, scopes: Dict[str, Any]) -> str:
    import json
    norm = {k: sorted(str(x).lower() for x in (scopes.get(k) or [])) for k in
            ("scope_rules", "scope_hosts", "scope_users", "scope_ips")}
    norm["scope_observables"] = sorted(
        f"{(o or {}).get('type','')}:{(o or {}).get('value','')}".lower()
        for o in (scopes.get("scope_observables") or [])
    )
    return (title or "").strip().lower() + "|" + json.dumps(norm, sort_keys=True)


def _proposal_sig(title: str, rule_name: str, change: str) -> str:
    return "|".join([
        (title or "").strip().lower(),
        (rule_name or "").strip().lower(),
        (change or "").strip().lower(),
    ])


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #

def export_pack(session: Session) -> Dict[str, Any]:
    """Serialise shareable quirks + proposals into a versioned content pack.

    Reverted quirks and rejected/duplicate proposals are omitted — a pack ships
    live content, not the local rejection history.
    """
    import ion as _ion

    quirks: List[Dict[str, Any]] = []
    q_rows = (
        session.query(SystemQuirk)
        .filter(SystemQuirk.status != SystemQuirkStatus.REVERTED)
        .all()
    )
    for q in q_rows:
        quirks.append({
            "title": q.title,
            "scope_rules": q.scope_rules or [],
            "scope_hosts": q.scope_hosts or [],
            "scope_users": q.scope_users or [],
            "scope_ips": q.scope_ips or [],
            "scope_observables": q.scope_observables or [],
            "annotation": q.annotation,
            "priority_nudge": q.priority_nudge,
            "justification": q.justification,
            "review_date": q.review_date.isoformat() if q.review_date else None,
            "source_status": q.status,  # provenance only; import lands pending
        })

    proposals: List[Dict[str, Any]] = []
    p_rows = (
        session.query(DetectionProposal)
        .filter(DetectionProposal.status.in_(
            [DetectionProposalStatus.DRAFT, DetectionProposalStatus.APPLIED]))
        .all()
    )
    for p in p_rows:
        proposals.append({
            "rule_name": p.rule_name,
            "change_type": p.change_type,
            "title": p.title,
            "suggested_change": p.suggested_change,
            "rationale": p.rationale,
            "scope": p.scope,
            "expected_fp_reduction": p.expected_fp_reduction,
            "expected_hours_reclaimed": p.expected_hours_reclaimed,
            "campaign_snapshot": p.campaign_snapshot,
            "mitre_techniques": p.mitre_techniques or [],
            "source_status": p.status,  # provenance only; import lands draft
        })

    return {
        "pack_schema": PACK_SCHEMA,
        "ion_version": getattr(_ion, "__version__", "unknown"),
        "exported_at": _now().isoformat(),
        "quirks": quirks,
        "proposals": proposals,
    }


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

def import_pack(session: Session, pack: Dict[str, Any], user_id: int) -> Dict[str, Any]:
    """Import a content pack. Quirks land pending, proposals land draft.

    Returns a summary of created / skipped / errored items. Raises ValueError
    only on a structurally invalid pack (bad schema); per-item failures are
    caught and reported so one bad row never aborts the whole import.
    """
    if not isinstance(pack, dict):
        raise ValueError("pack must be a JSON object")
    schema = pack.get("pack_schema")
    if schema != PACK_SCHEMA:
        raise ValueError(f"unsupported pack_schema {schema!r} (expected {PACK_SCHEMA})")

    summary = {
        "quirks_created": 0, "quirks_skipped": 0,
        "proposals_created": 0, "proposals_skipped": 0,
        "errors": [],
    }

    # Existing signatures, so re-import is idempotent.
    existing_q = {
        _quirk_sig(q.title, {
            "scope_rules": q.scope_rules, "scope_hosts": q.scope_hosts,
            "scope_users": q.scope_users, "scope_ips": q.scope_ips,
            "scope_observables": q.scope_observables,
        })
        for q in session.query(SystemQuirk).all()
    }
    existing_p = {
        _proposal_sig(p.title, p.rule_name, p.suggested_change)
        for p in session.query(DetectionProposal).all()
    }

    for raw in pack.get("quirks") or []:
        try:
            sig = _quirk_sig(raw.get("title", ""), raw)
            if sig in existing_q:
                summary["quirks_skipped"] += 1
                continue
            # review_date must be in the future for raise_quirk; a stale pack's
            # date is refreshed so the import is not rejected outright.
            rd = raw.get("review_date")
            payload = dict(raw)
            payload.pop("source_status", None)
            if not rd or _parse_past(rd):
                payload["review_date"] = (_now() + timedelta(days=90)).isoformat()
            de_quirk_service.raise_quirk(session, payload, user_id)
            existing_q.add(sig)
            summary["quirks_created"] += 1
        except Exception as exc:  # ValueError from validation, etc.
            summary["errors"].append(f"quirk '{raw.get('title', '?')}': {exc}")

    for raw in pack.get("proposals") or []:
        try:
            sig = _proposal_sig(
                raw.get("title", ""), raw.get("rule_name", ""),
                raw.get("suggested_change", ""),
            )
            if sig in existing_p:
                summary["proposals_skipped"] += 1
                continue
            payload = dict(raw)
            payload.pop("source_status", None)
            de_proposal_service.create_proposal(session, payload, user_id)
            existing_p.add(sig)
            summary["proposals_created"] += 1
        except Exception as exc:
            summary["errors"].append(f"proposal '{raw.get('title', '?')}': {exc}")

    logger.info(
        "DE content-pack import by user %s: quirks +%d/skip %d, proposals +%d/skip %d, %d error(s)",
        user_id, summary["quirks_created"], summary["quirks_skipped"],
        summary["proposals_created"], summary["proposals_skipped"], len(summary["errors"]),
    )
    return summary


def _parse_past(iso: str) -> bool:
    """True if an ISO date is missing/invalid or already in the past."""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt <= _now()
    except (ValueError, AttributeError):
        return True
