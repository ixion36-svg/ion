"""SOC roles & daily duties reference page (``/soc-roles``).

Extracted from ``course_api`` when the courseware cluster was archived: the
page is part of the skills surface ION keeps, but it lived in the course
module because each role declares the ``CourseLevel`` its training path
starts at and the route joins that to the published-course catalogue.

The catalogue join is retained as-is. ``Course`` and ``course_enrolments``
remain live because the workforce onboarding journey resolves COURSE
requirements from them. With the courseware pages archived the links the
join produces have no page to land on, so whether this page keeps a
training-path section at all is an open product decision.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_page_auth
from ion.models.course import Course
from ion.models.user import User
from ion.web.api import get_db_session
from ion.web.templating import make_templates

logger = logging.getLogger(__name__)
router = APIRouter(tags=["soc-roles"])
_templates = make_templates()


# SOC roles & daily duties reference page (/soc-roles).
#
# Static first-party training content rendered fully server-side (the hover
# expansion is pure CSS — no JS on the page). Each role declares the
# CourseLevel its training path starts at; the route joins that to the live
# published-course catalogue so the card links to real courses. URL is
# /soc-roles (NOT /roles — that path is reserved for the planned RBAC admin
# surface and sits confusingly close to the existing /api/roles).
_SOC_ROLES: list = [
    {
        "color": "cyan", "tier": "Tier 1 · Triage", "name": "L1 Triage Analyst",
        "oneliner": "First eyes on every alert — triage, enrich, disposition or escalate.",
        "mission": "Nothing sits unseen: fast triage with context that travels.",
        "level": "L1",
        "day": [("08:00", "Shift handover review"), ("08:30", "Queue triage block"),
                ("11:00", "Daily standup"), ("14:00", "Learning block (L1 path)"),
                ("15:30", "Final sweep + handover notes")],
        "duties": [("Queue ownership", "every alert gets eyes and a disposition inside SLA"),
                   ("Enrichment discipline", "IOCs enriched before escalation"),
                   ("Escalation quality", "L2 never re-does the basics")],
        "good": "Queue at zero twice a shift; escalations accepted without rework.",
        "apps": ["Alerts", "Cases", "Threat Intel"],
    },
    {
        "color": "green", "tier": "Tier 2 · Investigation", "name": "L2 Investigation Analyst",
        "oneliner": "Owns escalated cases end-to-end — deep-dive, correlate, conclude.",
        "mission": "Every case ends in a conclusion a reviewer can follow from the evidence.",
        "level": "L2",
        "day": [("08:00", "Case review & prioritisation"), ("09:00", "Investigation block (PCAP, process trees)"),
                ("11:00", "Standup + L1 escalation surgery"), ("14:30", "Evidence documentation"),
                ("15:30", "Mentoring an L1 escalation")],
        "duties": [("Case ownership", "defensible conclusions, documented evidence"),
                   ("Correlation", "spot the campaign behind the alerts"),
                   ("Feedback upstream", "findings become tuning proposals")],
        "good": "Zero cases re-opened for missing rationale; one tuning proposal a week.",
        "apps": ["Cases", "Workbench", "PCAP"],
    },
    {
        "color": "amber", "tier": "Tier 3 · Response", "name": "L3 / Incident Lead",
        "oneliner": "Runs the response when it's real — containment calls, coordination.",
        "mission": "One voice, clear comms, decisions logged — and every incident teaches.",
        "level": "L3",
        "day": [("08:30", "Open-incident review"), ("09:30", "Response lead / case-quality review"),
                ("11:00", "Daily standup"), ("13:00", "IR playbook upkeep"),
                ("15:00", "Tabletop / exercise prep")],
        "duties": [("Incident command", "stakeholder comms, resource calls"),
                   ("Containment authority", "isolation and blocking decisions, audited"),
                   ("Post-incident learning", "playbook + detection changes every time")],
        "good": "Time-to-containment inside target; every incident yields an improvement.",
        "apps": ["Forensics", "Playbooks", "Cases"],
    },
    {
        "color": "violet", "tier": "Engineering", "name": "Detection Engineer",
        "oneliner": "Owns the rule estate — coverage, quality, and the tuning loop.",
        "mission": "Know what you can't see; make every rule earn its place.",
        "level": "L3",
        "day": [("08:30", "Detection health dashboard"), ("09:30", "Rule development / testing"),
                ("11:00", "Daily standup"), ("13:00", "False-positive deep dives"),
                ("15:00", "Change requests (CAB)")],
        "duties": [("Coverage", "MITRE gap analysis drives the backlog"),
                   ("Quality loop", "floor tuning proposals reviewed weekly"),
                   ("Safe change", "tested, documented, reversible")],
        "good": "Agreement rates trending up; no silent dead rules; coverage map current.",
        "apps": ["Detection Health", "Discover"],
    },
    {
        "color": "steel", "tier": "Engineering", "name": "Security Platform Engineer",
        "oneliner": "Keeps the stack itself healthy — ingest, sensors, storage, upgrades.",
        "mission": "The SOC never goes blind: pipelines full, sensors green, storage ahead of demand.",
        "level": "L3",
        "day": [("08:00", "Stack health sweep (ingest lag, disk, cluster state)"),
                ("09:30", "Engineering block: upgrades, new log-source onboarding"),
                ("11:00", "Daily standup"), ("13:00", "Integration health + cert/key rotation"),
                ("15:00", "Capacity review & change prep (CAB)")],
        "duties": [("Pipeline integrity", "every log source flowing, lag alarmed, gaps investigated"),
                   ("Sensor estate", "collectors and taps patched, monitored, spares ready"),
                   ("Boring upgrades", "tested in staging, rollback rehearsed, zero surprise")],
        "good": "Zero unnoticed ingest gaps; upgrades land without analyst-visible downtime.",
        "apps": ["Integrations", "Audit Logs", "Reports"],
    },
    {
        "color": "lime", "tier": "Engineering", "name": "Automation Engineer (SOAR)",
        "oneliner": "Turns repeated analyst work into tested automation — playbooks as code.",
        "mission": "If the floor does it three times, it's a candidate; if it's automated, it's tested.",
        "level": "L3",
        "day": [("08:30", "Automation health review (failed runs, stuck jobs)"),
                ("09:30", "Build block: new playbook automation"),
                ("11:00", "Daily standup"), ("13:00", "Shadow an analyst — hunt for friction"),
                ("15:00", "Test, document, CAB submission")],
        "duties": [("Toil hunting", "measure the floor's repeated work, automate the worst first"),
                   ("Fail safe", "every automation has a manual fallback and a named owner"),
                   ("AI guardrails", "assistive automation stays advisory and audited")],
        "good": "Analyst minutes saved measured monthly; zero silent automation failures.",
        "apps": ["Playbooks", "Service Desk", "Change Requests"],
    },
    {
        "color": "rose", "tier": "Engineering", "name": "Network Security Engineer",
        "oneliner": "Owns visibility at the wire — taps, spans, sensor placement, segmentation.",
        "mission": "Every segment that matters is on a tap; every capture complete and clocked right.",
        "level": "L2",
        "day": [("08:30", "Capture health check (drops, clock skew, disk)"),
                ("09:30", "Field block: tap/SPAN changes, sensor placement"),
                ("11:00", "Daily standup"), ("13:00", "Segmentation review with architecture"),
                ("15:00", "Coverage map upkeep")],
        "duties": [("Coverage honesty", "the network map shows what is actually captured, not hoped"),
                   ("Capture quality", "packet drops and clock skew treated as incidents"),
                   ("Segmentation partner", "firewall and VLAN changes reviewed for visibility impact")],
        "good": "No blind segments discovered mid-incident; capture loss under 0.1%.",
        "apps": ["Network Map", "Arkime", "PCAP"],
    },
    {
        "color": "coral", "tier": "Specialist", "name": "Threat Hunter",
        "oneliner": "Assumes the alert never fired — hypothesis-driven sweeps.",
        "mission": "Every hunt starts falsifiable and ends recorded — found or clean.",
        "level": "L2",
        "day": [("08:30", "Intel review, pick hypothesis"), ("09:30", "Hunt block: query, pivot, carve"),
                ("11:00", "Daily standup"), ("13:00", "Hunt block: widen or kill"),
                ("15:00", "Write-up & detection handoff")],
        "duties": [("Hypothesis discipline", "stated and falsifiable, always"),
                   ("Detection handoff", "findings become rules"),
                   ("Negative results count", "a clean sweep is recorded coverage")],
        "good": "Every hunt logged with outcome; a detection candidate per week of hunting.",
        "apps": ["Discover", "Network Map", "Arkime"],
    },
    {
        "color": "pink", "tier": "Specialist", "name": "Threat Intel Analyst",
        "oneliner": "Curates what the SOC watches for — actors, campaigns, IOCs.",
        "mission": "Signal over noise: small, current, justified watchlists.",
        "level": "L2",
        "day": [("08:00", "Overnight intel review"), ("09:00", "Morning floor briefing"),
                ("10:00", "Watchlist & IOC curation"), ("13:00", "Report production"),
                ("15:00", "Hunt liaison")],
        "duties": [("Signal over noise", "watchlists stay small and current"),
                   ("Context delivery", "intel arrives attached to its alerts"),
                   ("Lifecycle honesty", "stale IOCs retire")],
        "good": "Watchlist hit-rate stays meaningful; the floor can name this week's threats.",
        "apps": ["Threat Intel", "Observables"],
    },
    {
        "color": "teal", "tier": "Specialist", "name": "DFIR Specialist",
        "oneliner": "Evidence handling done properly — imaging, custody, timelines.",
        "mission": "The chain never breaks; a second examiner reaches the same findings.",
        "level": "L3",
        "day": [("08:30", "Forensic case review"), ("09:30", "Lab block: imaging, memory"),
                ("11:00", "Daily standup"), ("13:00", "Timeline reconstruction"),
                ("15:30", "Custody log + same-day notes")],
        "duties": [("Custody first", "logged before touched, every item"),
                   ("Repeatability", "findings reproducible from the evidence"),
                   ("Same-day notes", "written fresh, defensible later")],
        "good": "Zero custody gaps; imaging backlog under 48 hours.",
        "apps": ["Forensics", "Workbench"],
    },
    {
        "color": "ice", "tier": "Leadership", "name": "SOC Manager",
        "oneliner": "Keeps the floor running — coverage, metrics, escalation, growth.",
        "mission": "Green SLAs without heroics; every analyst has a live growth path.",
        "level": "L4",
        "day": [("08:00", "Floor check & staffing"), ("11:00", "Daily standup (chair)"),
                ("11:30", "Wallboard / SLA review"), ("13:00", "1:1s & training reviews"),
                ("15:00", "Stakeholders & CAB")],
        "duties": [("Coverage", "shifts staffed for capabilities, not headcount"),
                   ("Escalation clarity", "everyone knows when to wake whom"),
                   ("Growth", "training paths live for every seat")],
        "good": "Zero single-person capability dependencies; SLAs green without heroics.",
        "apps": ["Team Day", "Skills", "Reports"],
    },
]


@router.get("/soc-roles", response_class=HTMLResponse)
def soc_roles_page(
    request: Request,
    _user: User = Depends(require_page_auth),
    session: Session = Depends(get_db_session),
):
    """SOC roles & daily duties — training-section reference page.

    Joins each role's declared CourseLevel to the live published-course
    catalogue so the expanded card links to the actual training path.
    Best-effort: with no published courses (fresh install) the cards fall
    back to a link to the /courses catalogue.
    """
    courses_by_level: dict = {}
    try:
        rows = (
            session.query(Course)
            .filter(Course.published.is_(True))
            .order_by(Course.order_in_level.asc(), Course.id.asc())
            .all()
        )
        for c in rows:
            # SQLEnum(native_enum=False) reads back as the enum member —
            # normalise to the plain value ("L1") the role dicts declare.
            lvl = c.level.value if hasattr(c.level, "value") else str(c.level)
            courses_by_level.setdefault(lvl, []).append(
                {"title": c.title, "slug": c.slug}
            )
    except Exception as exc:  # noqa: BLE001 — page must render without the catalogue
        logger.warning("soc-roles: course-catalogue lookup failed: %s", exc)
        courses_by_level = {}
    return _templates.TemplateResponse(
        request=request,
        name="soc_roles.html",
        context={"roles": _SOC_ROLES, "courses_by_level": courses_by_level},
    )
