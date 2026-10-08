"""Pull the SOC's mandatory items into a role profile, rather than retyping.

Adopting the twelve common roles from the catalogue produces twelve drafts
with no gate requirements, which is deliberate: the catalogue describes a
role, not an organisation's vetting. But a role profile that grants an ION
role cannot be published without a gate -- an empty gate never clears, so
the role could never be conferred -- which leaves a lead retyping the same
four mandatory items twelve times.

Retyping them is not merely tedious, it is how they drift. Gate items are
matched across journeys BY NAME (``verified_gate_names``), so "Security
awareness induction" on one profile and "Security Awareness Induction" on
another are two different requirements: somebody who cleared one is asked
to do the other again, and the carry-across that makes the gate
person-level silently stops working.

So the baseline is the single definition and a profile inherits from it.
The lead still has to ask for it -- it is not applied on adopt -- because
which mandatory items a role carries is a decision, and a profile that
quietly acquired requirements would be worse than one that has none.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, PHASE_READINESS
from ion.services import workforce_service as wf


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


@pytest.fixture
def lead(db):
    role = Role(name="lead")
    role.permissions = [
        Permission(name="workforce:manage", resource="workforce",
                   action="manage"),
    ]
    u = User(username="lead", email="l@x", password_hash="x", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def baseline(db, lead):
    profile = wf.create_profile(db, name="Mandatory Induction",
                                is_baseline=True)
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="Right to work", kind="vetting",
                       phase=PHASE_GATE)
    wf.add_requirement(db, version, name="Acceptable use", kind="document",
                       phase=PHASE_GATE, validity_months=12)
    wf.add_requirement(db, version, name="Security induction", kind="course",
                       phase=PHASE_GATE, validity_months=12)
    # A baseline may also carry readiness items of its own; those are not
    # the gate and must not travel.
    wf.add_requirement(db, version, name="Tooling walkthrough", kind="course",
                       phase=PHASE_READINESS)
    wf.publish_version(db, version, lead)
    db.commit()
    return profile


@pytest.fixture
def role_draft(db, lead):
    profile = wf.create_profile(db, name="SOC Analyst (L2)")
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="GIAC GCIA (or equivalent)",
                       kind="cert", phase=PHASE_READINESS,
                       validity_months=36)
    db.commit()
    return version


class TestInheriting:
    def test_the_gate_items_arrive(self, db, lead, baseline, role_draft):
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        names = {r.name for r in role_draft.requirements
                 if r.phase == PHASE_GATE}
        assert names == {"Right to work", "Acceptable use",
                         "Security induction"}

    def test_the_names_match_the_baseline_exactly(self, db, lead, baseline,
                                                  role_draft):
        """Gate items are carried across journeys by name. A difference in
        wording makes them two requirements, so somebody who cleared one
        is asked for the other and the carry-across stops working."""
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        base_version = wf.latest_published(db, baseline.id)
        expected = {r.name for r in base_version.requirements
                    if r.phase == PHASE_GATE}
        got = {r.name for r in role_draft.requirements
               if r.phase == PHASE_GATE}
        assert got == expected

    def test_the_validity_periods_come_too(self, db, lead, baseline,
                                           role_draft):
        """An agreement valid for a year on the baseline and forever on a
        role profile is the same drift in another column."""
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        aup = next(r for r in role_draft.requirements
                   if r.name == "Acceptable use")
        assert aup.validity_months == 12

    def test_readiness_items_on_the_baseline_do_not_travel(
        self, db, lead, baseline, role_draft
    ):
        """Only the gate is person-level. The baseline's own readiness is
        the baseline's."""
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        names = {r.name for r in role_draft.requirements}
        assert "Tooling walkthrough" not in names

    def test_the_role_keeps_its_own_requirements(self, db, lead, baseline,
                                                 role_draft):
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        assert any(r.name.startswith("GIAC GCIA")
                   for r in role_draft.requirements)

    def test_applying_twice_does_not_duplicate(self, db, lead, baseline,
                                               role_draft):
        """The same item twice means the person satisfies it twice and the
        gate count is wrong."""
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        wf.apply_baseline_gate(db, role_draft, actor=lead)
        gate = [r for r in role_draft.requirements if r.phase == PHASE_GATE]
        assert len(gate) == len({r.name for r in gate})

    def test_it_reports_what_it_added(self, db, lead, baseline, role_draft):
        added = wf.apply_baseline_gate(db, role_draft, actor=lead)
        assert added == 3
        assert wf.apply_baseline_gate(db, role_draft, actor=lead) == 0


class TestRefusals:
    def test_a_published_version_is_refused(self, db, lead, baseline,
                                            role_draft):
        """Editing a published version would change what people already on
        it are held to."""
        role_draft.profile.grants_role_id = None
        wf.add_requirement(db, role_draft, name="x", kind="document",
                           phase=PHASE_GATE)
        wf.publish_version(db, role_draft, lead)
        db.commit()
        with pytest.raises(wf.WorkforceError):
            wf.apply_baseline_gate(db, role_draft, actor=lead)

    def test_no_baseline_is_a_clear_error(self, db, lead, role_draft):
        """Rather than silently adding nothing and leaving the lead
        wondering why the profile still will not publish."""
        with pytest.raises(wf.WorkforceError) as exc:
            wf.apply_baseline_gate(db, role_draft, actor=lead)
        assert "baseline" in str(exc.value).lower()

    def test_it_needs_permission(self, db, baseline, role_draft):
        nobody = User(username="n", email="n@x", password_hash="x",
                      is_active=True)
        db.add(nobody)
        db.commit()
        with pytest.raises(wf.WorkforceError):
            wf.apply_baseline_gate(db, role_draft, actor=nobody)


class TestItUnblocksPublishing:
    def test_an_adopted_profile_can_publish_once_it_has_the_gate(
        self, db, lead, baseline, role_draft
    ):
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        role_draft.profile.grants_role_id = analyst.id
        db.commit()

        with pytest.raises(wf.WorkforceError):
            wf.publish_version(db, role_draft, lead)

        wf.apply_baseline_gate(db, role_draft, actor=lead)
        wf.publish_version(db, role_draft, lead)
        assert role_draft.is_published
