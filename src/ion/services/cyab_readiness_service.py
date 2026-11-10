"""Where a CyAB system stands: its stage, readiness and next action.

Onboarding runs in dependency order. Intake questions come from the
sub-profiles of a system's data sources, and use cases from the same
sub-profiles, so sources come before intake and use cases. Documents and
sign-off follow.

    profile -> sources -> intake -> use_cases -> docs -> signoff

A system's stage is the first step not yet complete. With every step
complete it is "signed", or "review_due" once its review date passes.
Readiness is the mean completion of the six steps. Nothing here is stored:
`compute_many` reads a page of systems in a fixed number of queries, so the
figures cannot drift from the rows they describe.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.cyab import CyabDataSource, CyabSystem, CyabSystemAssessment
from ion.models.cyab_assurance import SIGNOFF_ROLES, CyabChecklistException, CyabSignoff
from ion.models.cyab_doc_checklist import STATUS_DONE, STATUS_NA, CyabDocChecklistItem
from ion.models.cyab_subprofile import CyabSubProfile
from ion.services import cyab_assessment_service, cyab_sal
from ion.services.cyab_doc_checklist_service import _DEFAULT_CHECKLIST

STEPS: Tuple[str, ...] = ("profile", "sources", "intake", "use_cases", "docs", "signoff")
STAGES: Tuple[str, ...] = STEPS + ("signed", "review_due", "retired")
STAGE_LABELS: Dict[str, str] = {
    "profile": "Profile",
    "sources": "Sources",
    "intake": "Intake",
    "use_cases": "Use cases",
    "docs": "Docs",
    "signoff": "Sign-off",
    "signed": "Signed",
    "review_due": "Review due",
    "retired": "Retired",
}

# Tab of the system page where each stage's work is done.
STAGE_TAB: Dict[str, str] = {
    "profile": "profile",
    "sources": "sources",
    "intake": "profile",
    "use_cases": "use-cases",
    "docs": "signoff",
    "signoff": "signoff",
    "signed": "summary",
    "review_due": "signoff",
    "retired": "summary",
}

PROFILE_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("department_lead", "department lead"),
    ("soc_analyst_owner", "SOC owner"),
    ("data_classification", "data classification"),
)

_DEFAULT_LABELS = {spec["kind"]: spec["label"] for spec in _DEFAULT_CHECKLIST}
_DEFAULT_CRITICAL = {spec["kind"] for spec in _DEFAULT_CHECKLIST if spec.get("is_critical")}


@dataclass(frozen=True)
class Step:
    key: str
    done: int
    total: int

    @property
    def complete(self) -> bool:
        return self.done >= self.total

    @property
    def pct(self) -> int:
        return round(self.done * 100 / self.total) if self.total else 100

    @property
    def label(self) -> str:
        return STAGE_LABELS[self.key]


@dataclass(frozen=True)
class Readiness:
    system_id: int
    stage: str
    pct: int
    steps: Tuple[Step, ...]
    next_action: str
    sal: str
    missing_docs: Tuple[str, ...]
    signed_roles: Tuple[str, ...]
    next_review: Optional[date]
    use_cases_shipped: int
    use_cases_total: int
    subprofile_ids: Tuple[str, ...]

    @property
    def stage_label(self) -> str:
        return STAGE_LABELS[self.stage]

    @property
    def tab(self) -> str:
        return STAGE_TAB[self.stage]

    @property
    def needs_attention(self) -> bool:
        return self.stage == "review_due" or bool(self.missing_docs and self.stage in ("docs", "signoff"))


def _catalogue(row: Optional[CyabSubProfile]) -> dict:
    if row is None or not row.catalogue_json:
        return {}
    try:
        cat = json.loads(row.catalogue_json)
    except (json.JSONDecodeError, TypeError):
        return {}
    return cat if isinstance(cat, dict) else {}


def parse_uc_status(raw: Optional[str]) -> Dict[str, str]:
    """A data source's stored use-case statuses. Pre-JSON free text reads as none."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {k: v for k, v in parsed.items() if v in ("shipped", "partial", "gap", "n/a")}


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def _next_action(stage: str, system: CyabSystem, steps: Dict[str, Step],
                 missing_profile: List[str], source_count: int,
                 missing_docs: List[str], signed: set, today: date) -> str:
    if stage == "profile":
        return "Add " + ", ".join(missing_profile)
    if stage == "sources":
        if source_count == 0:
            return "Add a data source"
        untagged = steps["sources"].total - steps["sources"].done
        return f"Choose a sub-profile for {_plural(untagged, 'source')}"
    if stage == "intake":
        left = steps["intake"].total - steps["intake"].done
        return f"Answer {_plural(left, 'intake question')}"
    if stage == "use_cases":
        left = steps["use_cases"].total - steps["use_cases"].done
        return f"Set status on {_plural(left, 'use case')}"
    if stage == "docs":
        if len(missing_docs) == 1:
            return f"Attach {missing_docs[0]}"
        return f"Close {_plural(len(missing_docs), 'required document')}"
    if stage == "signoff":
        roles = [r for r in SIGNOFF_ROLES if r not in signed]
        who = " and ".join("department" if r == "department" else "SOC" for r in roles)
        return f"Sign off as {who}"
    if stage == "review_due":
        days = (today - system.next_review_date).days if system.next_review_date else 0
        return f"Review overdue by {_plural(days, 'day')}"
    if stage == "signed":
        if system.next_review_date:
            return f"Review in {_plural((system.next_review_date - today).days, 'day')}"
        return "Set a review date"
    return "Retired"


def compute_many(session: Session, systems: Sequence[CyabSystem],
                 today: Optional[date] = None) -> Dict[int, Readiness]:
    today = today or date.today()
    ids = [s.id for s in systems]
    if not ids:
        return {}

    sources_by_sys: Dict[int, List[CyabDataSource]] = {i: [] for i in ids}
    for ds in session.scalars(select(CyabDataSource).where(CyabDataSource.system_id.in_(ids))):
        sources_by_sys[ds.system_id].append(ds)

    # Intake answers as load_answers reads them: the latest submitted row,
    # with the autosave row merged over it.
    marker = cyab_assessment_service._STUDIO_NOTES_MARKER
    latest_ids = select(func.max(CyabSystemAssessment.id)).where(
        CyabSystemAssessment.system_id.in_(ids),
        CyabSystemAssessment.notes.is_distinct_from(marker),
    ).group_by(CyabSystemAssessment.system_id)
    answer_rows = list(session.scalars(select(CyabSystemAssessment).where(CyabSystemAssessment.id.in_(latest_ids))))
    answer_rows += list(session.scalars(select(CyabSystemAssessment).where(
        CyabSystemAssessment.system_id.in_(ids), CyabSystemAssessment.notes == marker,
    ).order_by(CyabSystemAssessment.id)))
    answers_by_sys: Dict[int, dict] = {}
    for a in answer_rows:
        try:
            parsed = json.loads(a.responses_json or "{}")
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict):
            answers_by_sys.setdefault(a.system_id, {}).update(parsed)

    sub_ids = {ds.subprofile_id for rows in sources_by_sys.values() for ds in rows if ds.subprofile_id}
    catalogues: Dict[str, dict] = {}
    if sub_ids:
        for row in session.scalars(select(CyabSubProfile).where(CyabSubProfile.id.in_(sub_ids))):
            catalogues[row.id] = _catalogue(row)

    items_by_sys: Dict[int, List[CyabDocChecklistItem]] = {i: [] for i in ids}
    for item in session.scalars(select(CyabDocChecklistItem).where(CyabDocChecklistItem.system_id.in_(ids))):
        items_by_sys[item.system_id].append(item)

    excepted_items = set(session.scalars(
        select(CyabChecklistException.item_id).where(
            CyabChecklistException.system_id.in_(ids),
            CyabChecklistException.revoked_at.is_(None),
            CyabChecklistException.until >= today,
        )
    ))

    signed_by_sys: Dict[int, set] = {i: set() for i in ids}
    for sid, role in session.execute(
        select(CyabSignoff.system_id, CyabSignoff.role).where(CyabSignoff.system_id.in_(ids)).distinct()
    ):
        signed_by_sys[sid].add(role)

    out: Dict[int, Readiness] = {}
    for system in systems:
        out[system.id] = _one(
            system,
            sources_by_sys[system.id],
            answers_by_sys.get(system.id, {}),
            catalogues,
            items_by_sys[system.id],
            excepted_items,
            signed_by_sys[system.id],
            today,
        )
    return out


def compute(session: Session, system: CyabSystem, today: Optional[date] = None) -> Readiness:
    return compute_many(session, [system], today)[system.id]


def _one(system: CyabSystem, sources: List[CyabDataSource], answers: dict,
         catalogues: Dict[str, dict], items: List[CyabDocChecklistItem],
         excepted_items: set, signed: set, today: date) -> Readiness:
    sal = cyab_sal.normalise(system.sal_tier)

    missing_profile = [label for attr, label in PROFILE_FIELDS if not (getattr(system, attr) or "").strip()]
    profile = Step("profile", len(PROFILE_FIELDS) - len(missing_profile), len(PROFILE_FIELDS))

    tagged = [ds for ds in sources if ds.subprofile_id]
    sources_step = Step("sources", len(tagged), max(len(sources), 1))

    sub_ids = list(dict.fromkeys(ds.subprofile_id for ds in tagged))
    questions = [q["key"] for sid in sub_ids for q in catalogues.get(sid, {}).get("intake_questions") or []]
    questions = list(dict.fromkeys(questions))
    answered = sum(1 for k in questions if answers.get(k) not in (None, "", []))
    if questions:
        intake = Step("intake", answered, len(questions))
    else:
        intake = Step("intake", int(sources_step.complete), 1)

    reviewed = shipped = uc_total = 0
    for sid in sub_ids:
        cat = catalogues.get(sid, {})
        uc_ids = [u["id"] for u in (cat.get("detection_use_cases") or []) + (cat.get("audit_use_cases") or [])]
        statuses = [parse_uc_status(ds.use_case_status) for ds in tagged if ds.subprofile_id == sid]
        for uc in uc_ids:
            uc_total += 1
            seen = {s[uc] for s in statuses if uc in s}
            if seen:
                reviewed += 1
            if "shipped" in seen:
                shipped += 1
    if uc_total:
        use_cases = Step("use_cases", reviewed, uc_total)
    else:
        use_cases = Step("use_cases", int(sources_step.complete), 1)

    required = cyab_sal.required_kinds(sal)
    missing_docs: List[str] = []
    if items:
        required_items = [i for i in items if cyab_sal.is_required(i.kind, i.is_critical, sal)]
        for i in required_items:
            if i.status not in (STATUS_DONE, STATUS_NA) and i.id not in excepted_items:
                missing_docs.append(i.label)
        docs = Step("docs", len(required_items) - len(missing_docs), len(required_items))
    else:
        kinds = sorted(required | _DEFAULT_CRITICAL)
        missing_docs = [_DEFAULT_LABELS.get(k, k) for k in kinds]
        docs = Step("docs", 0, len(kinds))

    signed = set(signed)
    if system.sign_dept_name and system.sign_dept_date:
        signed.add("department")
    if system.sign_soc_name and system.sign_soc_date:
        signed.add("soc")
    signoff = Step("signoff", sum(1 for r in SIGNOFF_ROLES if r in signed), len(SIGNOFF_ROLES))

    steps = (profile, sources_step, intake, use_cases, docs, signoff)
    by_key = {s.key: s for s in steps}
    if (system.status or "").upper() == "RETIRED":
        stage = "retired"
    else:
        stage = next((s.key for s in steps if not s.complete), "")
        if not stage:
            overdue = system.next_review_date is not None and system.next_review_date < today
            stage = "review_due" if overdue else "signed"

    pct = round(sum(min(s.done, s.total) / s.total for s in steps) * 100 / len(steps))
    return Readiness(
        system_id=system.id,
        stage=stage,
        pct=pct,
        steps=steps,
        next_action=_next_action(stage, system, by_key, missing_profile, len(sources),
                                 missing_docs, signed, today),
        sal=sal,
        missing_docs=tuple(missing_docs),
        signed_roles=tuple(r for r in SIGNOFF_ROLES if r in signed),
        next_review=system.next_review_date,
        use_cases_shipped=shipped,
        use_cases_total=uc_total,
        subprofile_ids=tuple(sub_ids),
    )


def stage_counts(readiness: Iterable[Readiness]) -> Dict[str, int]:
    counts = {s: 0 for s in STAGES}
    for r in readiness:
        counts[r.stage] += 1
    return counts
