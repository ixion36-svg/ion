"""SOC Maturity Assessment service.

SOC-CMM inspired questionnaire across 5 domains. Each domain has 5 questions
scored 1-5. The overall maturity level maps to the SOC-CMM scale:

  1 = Initial    — Ad-hoc, reactive, undocumented
  2 = Managed    — Some processes documented, inconsistent
  3 = Defined    — Standardised, documented, repeatable
  4 = Measured   — Metrics-driven, continuously monitored
  5 = Optimising — Continuous improvement, automation, proactive
"""

from __future__ import annotations

import logging
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.maturity import MaturityAssessment

logger = logging.getLogger(__name__)


# =========================================================================
# Questionnaire definition
# =========================================================================

DOMAINS = [
    {
        "id": "business",
        "name": "Business",
        "description": "Governance, alignment, compliance, and executive support.",
        "icon": "briefcase",
        "ion_pages": ["/compliance", "/executive-report"],
        "questions": [
            {"id": "b1", "text": "Is there a formal SOC charter defining mission, scope, and authority?", "guidance": "Level 3+ requires a signed charter reviewed annually."},
            {"id": "b2", "text": "Are SOC services documented in a service catalogue?", "guidance": "List all services: monitoring, IR, threat hunting, forensics, vulnerability management."},
            {"id": "b3", "text": "Does the SOC have a RACI matrix for key processes?", "guidance": "Who is Responsible/Accountable/Consulted/Informed for triage, IR, escalation, reporting."},
            {"id": "b4", "text": "Is compliance posture tracked against at least one framework?", "guidance": "ION tracks NIST CSF, 800-53, ISO 27001, PCI DSS, CIS Controls at /compliance."},
            {"id": "b5", "text": "Does the SOC produce regular executive reports with actionable metrics?", "guidance": "ION generates executive reports at /executive-report with MTTR, FP rate, case volume."},
        ],
    },
    {
        "id": "people",
        "name": "People",
        "description": "Staffing, skills, training, retention, and team health.",
        "icon": "users",
        "ion_pages": ["/training", "/oncall", "/shift-handover"],
        "questions": [
            {"id": "p1", "text": "Are analyst roles formally defined with competency requirements (L1/L2/L3)?", "guidance": "ION has analyst/senior/principal/lead/forensic/engineering roles with distinct permissions."},
            {"id": "p2", "text": "Is there a skills assessment and career development framework?", "guidance": "ION tracks skills via /training with SFIA/UKCSC/MOD frameworks."},
            {"id": "p3", "text": "Is on-call cover documented with defined escalation paths?", "guidance": "ION manages on-call rosters at /oncall with escalation policies."},
            {"id": "p4", "text": "Is there a formal shift handover process?", "guidance": "ION provides structured shift handover at /shift-handover."},
            {"id": "p5", "text": "Do analysts have annual training plans with certification targets?", "guidance": "Level 4+ requires tracked training hours and certification attainment."},
        ],
    },
    {
        "id": "process",
        "name": "Process",
        "description": "Procedures, runbooks, playbooks, incident response, and change management.",
        "icon": "clipboard",
        "ion_pages": ["/playbooks", "/pir", "/cases"],
        "questions": [
            {"id": "r1", "text": "Is there a documented alert triage SOP that all analysts follow?", "guidance": "Step-by-step: receive → classify → assign → investigate → escalate → close."},
            {"id": "r2", "text": "Is there a formal Incident Response Plan covering the full IR lifecycle?", "guidance": "Detect → Contain → Eradicate → Recover → Lessons Learned (NIST 800-61)."},
            {"id": "r3", "text": "Does the SOC maintain a playbook library covering common alert types?", "guidance": "ION has 25 playbooks at /playbooks. Level 3+ requires 15+ covering top alert categories."},
            {"id": "r4", "text": "Are post-incident reviews (PIRs) conducted and action items tracked?", "guidance": "ION tracks PIRs at /pir with action items, owners, and due dates."},
            {"id": "r5", "text": "Is there a change management process for detection rule changes?", "guidance": "ION tracks changes via the change log. Level 4+ requires approval workflows."},
        ],
    },
    {
        "id": "technology",
        "name": "Technology",
        "description": "Tooling, integration, detection coverage, and log source health.",
        "icon": "cpu",
        "ion_pages": ["/detection-engineering", "/log-sources", "/integrations"],
        "questions": [
            {"id": "t1", "text": "Is there a detection rule catalogue with MITRE ATT&CK mapping?", "guidance": "ION shows TIDE rules with MITRE mapping at /detection-engineering."},
            {"id": "t2", "text": "Is log source health actively monitored for ingestion gaps?", "guidance": "ION monitors log source health at /log-sources with expected cadence checks."},
            {"id": "t3", "text": "Is detection coverage measured and gaps identified?", "guidance": "ION shows MITRE coverage, D3FEND, and gap analysis in Detection Engineering."},
            {"id": "t4", "text": "Are integrations between SOC tools tested and monitored?", "guidance": "ION shows integration health at /integrations with connection testing."},
            {"id": "t5", "text": "Is there an assurance baseline defining expected detections per system?", "guidance": "ION's CyAB page at /cyab defines per-system use case baselines from TIDE."},
        ],
    },
    {
        "id": "services",
        "name": "Services",
        "description": "Monitoring, detection, response, threat intel, and continuous improvement.",
        "icon": "shield",
        "ion_pages": ["/analyst", "/threat-intel", "/canaries", "/briefing"],
        "questions": [
            {"id": "s1", "text": "Is 24/7 monitoring coverage in place (or clearly defined business-hours coverage)?", "guidance": "Level 3+ requires documented coverage hours with after-hours escalation."},
            {"id": "s2", "text": "Is threat intelligence consumed, processed, and actioned?", "guidance": "ION integrates with OpenCTI for threat intel at /threat-intel."},
            {"id": "s3", "text": "Are adversary emulation exercises (purple team) conducted regularly?", "guidance": "ION tracks emulation plans in Detection Engineering → Emulation tab."},
            {"id": "s4", "text": "Is there a vulnerability management process linked to detection?", "guidance": "ION's /vulnerabilities page (in DE) links CVEs to TIDE detection coverage."},
            {"id": "s5", "text": "Does the SOC have a continuous improvement backlog driven by PIR actions?", "guidance": "ION's PIR action backlog at /pir/backlog tracks improvement items across the org."},
        ],
    },
]

MATURITY_LEVELS = {
    1: {"name": "Initial", "description": "Ad-hoc and reactive. No formal processes. Hero-dependent."},
    2: {"name": "Managed", "description": "Some processes documented. Inconsistent execution. Reactive with some proactive elements."},
    3: {"name": "Defined", "description": "Standardised, documented, repeatable processes. Consistent execution across the team."},
    4: {"name": "Measured", "description": "Metrics-driven operations. KPIs tracked and acted on. Continuous monitoring of SOC performance."},
    5: {"name": "Optimising", "description": "Continuous improvement culture. Automation where possible. Proactive threat hunting and innovation."},
}


# =========================================================================
# CRUD
# =========================================================================

def get_questionnaire() -> dict:
    """Return the full questionnaire structure for the UI."""
    return {
        "domains": DOMAINS,
        "maturity_levels": MATURITY_LEVELS,
        "total_questions": sum(len(d["questions"]) for d in DOMAINS),
    }


def submit_assessment(
    session: Session,
    *,
    title: str,
    responses: dict,
    notes: Optional[str],
    created_by_id: Optional[int],
) -> MaturityAssessment:
    """Score and save a completed assessment."""
    scores = {}
    total = 0
    count = 0

    for domain in DOMAINS:
        domain_responses = responses.get(domain["id"], {})
        domain_total = 0
        domain_count = 0
        for q in domain["questions"]:
            answer = domain_responses.get(q["id"], {})
            score = int(answer.get("score", 1)) if isinstance(answer, dict) else int(answer or 1)
            domain_total += max(1, min(5, score))
            domain_count += 1
        domain_avg = round(domain_total / domain_count) if domain_count else 1
        scores[domain["id"]] = {
            "score": domain_avg,
            "total": domain_total,
            "max": domain_count * 5,
            "pct": round(domain_total / (domain_count * 5) * 100) if domain_count else 0,
        }
        total += domain_total
        count += domain_count

    overall = round(total / count) if count else 1
    level_info = MATURITY_LEVELS.get(overall, MATURITY_LEVELS[1])

    assessment = MaturityAssessment(
        title=title or f"SOC Maturity Assessment",
        scores=scores,
        responses=responses,
        overall_score=overall,
        overall_level=level_info["name"],
        notes=notes,
        created_by_id=created_by_id,
    )
    session.add(assessment)
    session.commit()
    session.refresh(assessment)
    return assessment


def list_assessments(session: Session) -> list[dict]:
    rows = session.execute(
        select(MaturityAssessment).order_by(MaturityAssessment.created_at.desc())
    ).scalars().all()
    return [r.to_dict() for r in rows]


def get_assessment(session: Session, assessment_id: int) -> Optional[dict]:
    a = session.get(MaturityAssessment, assessment_id)
    return a.to_dict() if a else None


def delete_assessment(session: Session, assessment_id: int) -> bool:
    a = session.get(MaturityAssessment, assessment_id)
    if not a:
        return False
    session.delete(a)
    session.commit()
    return True
