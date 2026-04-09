"""Adversary Emulation Plans service.

CRUD over plans + steps, plus a verification helper that queries Elasticsearch
to check whether expected detections fired after a step was executed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.emulation import (
    EmulationPlan,
    EmulationPlanStatus,
    EmulationStep,
    StepResult,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CRUD — plans
# ---------------------------------------------------------------------------

def list_plans(session: Session, status: Optional[str] = None) -> List[dict]:
    stmt = select(EmulationPlan).order_by(EmulationPlan.updated_at.desc())
    if status:
        stmt = stmt.where(EmulationPlan.status == status)
    rows = session.execute(stmt).scalars().all()
    return [r.to_dict(include_steps=False) for r in rows]


def get_plan(session: Session, plan_id: int) -> Optional[EmulationPlan]:
    return session.get(EmulationPlan, plan_id)


def create_plan(
    session: Session,
    *,
    name: str,
    description: Optional[str],
    actor_name: Optional[str],
    actor_id: Optional[str],
    target_systems: Optional[list],
    tags: Optional[list],
    created_by_id: Optional[int],
) -> EmulationPlan:
    p = EmulationPlan(
        name=name.strip(),
        description=description,
        actor_name=actor_name,
        actor_id=actor_id,
        target_systems=target_systems or [],
        tags=tags or [],
        status=EmulationPlanStatus.DRAFT.value,
        created_by_id=created_by_id,
    )
    session.add(p)
    session.commit()
    session.refresh(p)
    return p


def update_plan(session: Session, plan_id: int, **fields) -> Optional[EmulationPlan]:
    p = session.get(EmulationPlan, plan_id)
    if not p:
        return None
    allowed = {"name", "description", "actor_name", "actor_id", "status", "target_systems", "tags"}
    for k, v in fields.items():
        if k in allowed:
            setattr(p, k, v)
    if fields.get("status") == EmulationPlanStatus.RUNNING.value and not p.started_at:
        p.started_at = datetime.utcnow()
    if fields.get("status") == EmulationPlanStatus.COMPLETED.value and not p.completed_at:
        p.completed_at = datetime.utcnow()
    session.commit()
    session.refresh(p)
    return p


def delete_plan(session: Session, plan_id: int) -> bool:
    p = session.get(EmulationPlan, plan_id)
    if not p:
        return False
    session.delete(p)
    session.commit()
    return True


# ---------------------------------------------------------------------------
# CRUD — steps
# ---------------------------------------------------------------------------

def add_step(
    session: Session,
    plan_id: int,
    *,
    title: str,
    description: Optional[str] = None,
    mitre_techniques: Optional[list] = None,
    procedure: Optional[str] = None,
    expected_rules: Optional[list] = None,
) -> EmulationStep:
    plan = session.get(EmulationPlan, plan_id)
    if not plan:
        raise ValueError("Plan not found")
    next_idx = len(plan.steps or [])
    step = EmulationStep(
        plan_id=plan_id,
        order_index=next_idx,
        title=title.strip(),
        description=description,
        mitre_techniques=mitre_techniques or [],
        procedure=procedure,
        expected_rules=expected_rules or [],
    )
    session.add(step)
    session.commit()
    session.refresh(step)
    return step


def update_step(session: Session, step_id: int, **fields) -> Optional[EmulationStep]:
    s = session.get(EmulationStep, step_id)
    if not s:
        return None
    allowed = {
        "title", "description", "mitre_techniques", "procedure",
        "expected_rules", "result", "notes", "order_index",
    }
    for k, v in fields.items():
        if k in allowed:
            setattr(s, k, v)
    session.commit()
    session.refresh(s)
    return s


def delete_step(session: Session, step_id: int) -> bool:
    s = session.get(EmulationStep, step_id)
    if not s:
        return False
    session.delete(s)
    session.commit()
    return True


def mark_executed(session: Session, step_id: int) -> Optional[EmulationStep]:
    s = session.get(EmulationStep, step_id)
    if not s:
        return None
    s.executed_at = datetime.utcnow()
    if s.result == StepResult.PENDING.value:
        s.result = StepResult.PENDING.value  # awaiting verification
    session.commit()
    session.refresh(s)
    return s


# ---------------------------------------------------------------------------
# Verification — query ES for matching alerts
# ---------------------------------------------------------------------------

async def verify_step(session: Session, step_id: int, lookback_hours: int = 4) -> dict:
    """Query Elasticsearch for alerts that match this step's MITRE techniques
    and were ingested in the last ``lookback_hours``. Updates the step result.
    """
    from ion.services.elasticsearch_service import ElasticsearchService

    s = session.get(EmulationStep, step_id)
    if not s:
        raise ValueError("Step not found")

    techniques = s.mitre_techniques or []
    if not techniques:
        return {"step_id": step_id, "result": s.result, "error": "Step has no MITRE techniques set"}

    es = ElasticsearchService()
    if not es.is_configured:
        return {"step_id": step_id, "result": s.result, "error": "Elasticsearch not configured"}

    # Build a should clause matching any of the techniques (parent + sub)
    should = []
    for t in techniques:
        tid = (t or "").strip().upper()
        if not tid:
            continue
        if not tid.startswith("T"):
            tid = "T" + tid
        should.append({"term": {"threat.technique.id": tid}})
        # Match sub-techniques if parent given
        if "." not in tid:
            should.append({"prefix": {"threat.technique.id": tid + "."}})

    if not should:
        return {"step_id": step_id, "result": s.result, "error": "No usable MITRE technique IDs"}

    body = {
        "size": 20,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{int(lookback_hours)}h"}}},
                ],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "_source": ["kibana.alert.rule.name", "rule.name", "@timestamp"],
    }

    try:
        result = await es._request(
            "POST",
            "/.alerts-security.alerts-*,alerts-*/_search",
            json=body,
        )
    except Exception as e:
        return {"step_id": step_id, "result": s.result, "error": type(e).__name__}

    hits = (result.get("hits") or {}).get("hits") or []
    total_obj = (result.get("hits") or {}).get("total") or {}
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else (total_obj or 0)

    rule_names = []
    seen = set()
    for h in hits:
        src = h.get("_source") or {}
        name = (
            ((src.get("kibana") or {}).get("alert") or {}).get("rule", {}).get("name")
            or ((src.get("rule") or {})).get("name")
            or src.get("rule_name")
        )
        if name and name not in seen:
            seen.add(name)
            rule_names.append(name)

    s.matched_alert_count = total
    s.matched_rule_names = rule_names
    s.verified_at = datetime.utcnow()

    # Decide pass/fail. Without expected_rules, any hit = pass.
    expected = s.expected_rules or []
    if total == 0:
        s.result = StepResult.FAILED.value
    elif expected:
        expected_lc = {e.lower() for e in expected}
        matched_expected = sum(
            1 for n in rule_names if n.lower() in expected_lc
            or any(e.lower() in n.lower() for e in expected_lc)
        )
        if matched_expected == 0:
            s.result = StepResult.FAILED.value
        elif matched_expected < len(expected):
            s.result = StepResult.PARTIAL.value
        else:
            s.result = StepResult.PASSED.value
    else:
        s.result = StepResult.PASSED.value

    session.commit()
    session.refresh(s)
    return {
        "step_id": step_id,
        "result": s.result,
        "matched_alert_count": s.matched_alert_count,
        "matched_rule_names": s.matched_rule_names,
        "verified_at": s.verified_at.isoformat() if s.verified_at else None,
    }
