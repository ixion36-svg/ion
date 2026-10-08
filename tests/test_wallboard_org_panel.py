"""The wallboard says how the SOC is staffed, and who is on duty.

A board that shows alert counts and nothing about people answers "what is
happening" and not "who is dealing with it". Two things belong on it:

* the establishment against what is actually filled, so a standing gap is
  visible to the room rather than only to whoever opens the ORBAT;
* who is on duty this week, because the first question when something
  lands out of hours is who to call.

The panel's job is to be honest about the empty cases, which is where a
staffing widget goes wrong. "0 gaps" with no establishment defined reads
as fully staffed. A blank duty line reads as "not loaded". Both have to
say what they actually mean.
"""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.duty_roster import DUTY_ANALYST
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, OrgPost
from ion.services import duty_roster_service as duty
from ion.services import workforce_service as wf
from ion.services.wallboard_service import _collect_org


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
        Permission(name="workforce:verify", resource="workforce",
                   action="verify"),
    ]
    u = User(username="lead", email="l@x", password_hash="x",
             display_name="Rita Okonjo", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


def establish(db, lead, *role_ids):
    analyst = Role(name="analyst")
    db.add(analyst)
    db.commit()
    for role_id in role_ids:
        profile = wf.adopt_catalogue_role(db, role_id, adopter=lead)
        version = wf.draft_version(db, profile)
        wf.add_requirement(db, version, name="Right to work", kind="vetting",
                           phase=PHASE_GATE)
        profile.grants_role_id = analyst.id
        db.commit()
        wf.publish_version(db, version, lead)
        db.commit()
    wf.establish_from_catalogue(db, actor=lead)


class TestTheEmptyCases:
    def test_no_establishment_says_so_rather_than_zero_gaps(self, db):
        """"0 gaps" on a board with nothing established reads as fully
        staffed to everyone who walks past it."""
        panel = _collect_org(db)
        assert panel["established"] == 0
        assert panel["has_establishment"] is False
        assert "no establishment" in panel["headline"].lower()

    def test_nobody_on_duty_is_stated(self, db):
        """A blank line reads as "not loaded"."""
        panel = _collect_org(db)
        assert panel["duty"]["assigned"] is False
        assert "nobody" in panel["duty"]["summary"].lower()


class TestWithAnEstablishment:
    def test_it_reports_the_shortfall(self, db, lead):
        establish(db, lead, "l1_soc_analyst")
        panel = _collect_org(db)
        assert panel["has_establishment"] is True
        assert panel["established"] == 6
        assert panel["gap"] == 6
        assert panel["filled"] == 0

    def test_somebody_still_training_is_not_counted_as_filled(self, db, lead):
        establish(db, lead, "l1_soc_analyst")
        person = User(username="j", email="j@x", password_hash="x",
                      is_active=True)
        db.add(person)
        db.commit()
        profile = next(p for p in db.query(wf.RoleProfile).all()
                       if p.name == "SOC Analyst (L1)")
        version = wf.latest_published(db, profile.id)
        journey = wf.assign_profile(db, user=person, version=version,
                                    assigner=lead)
        post = db.query(OrgPost).first()
        wf.fill_post(db, post=post, journey_id=journey.id, actor=lead)

        panel = _collect_org(db)
        assert panel["filling"] == 1
        assert panel["filled"] == 0

    def test_the_worst_staffed_roles_are_named(self, db, lead):
        """A headline number tells the room it is short. Which role it is
        short of is the thing somebody can act on."""
        establish(db, lead, "l1_soc_analyst", "grc_analyst")
        panel = _collect_org(db)
        names = [r["role"] for r in panel["worst"]]
        assert "SOC Analyst (L1)" in names

    def test_a_gapped_lead_post_is_called_out(self, db, lead):
        """"Nobody answers for detection engineering" is a different
        problem from being one analyst short."""
        establish(db, lead, "lead_engineer", "detection_engineer")
        panel = _collect_org(db)
        assert panel["leads_gapped"] == 1


class TestTheDutyLine:
    def test_the_holder_is_named(self, db, lead):
        today = date(2026, 10, 7)
        duty.assign(db, duty=DUTY_ANALYST, week_start=today, user=lead,
                    actor=lead)
        panel = _collect_org(db, today=today)
        assert panel["duty"]["assigned"] is True
        assert panel["duty"]["user"]["name"] == "Rita Okonjo"

    def test_an_unacknowledged_duty_is_flagged(self, db, lead):
        """A rota entry nobody picked up is a plan, and the board should
        not present it as cover."""
        today = date(2026, 10, 7)
        duty.assign(db, duty=DUTY_ANALYST, week_start=today, user=lead,
                    actor=lead)
        panel = _collect_org(db, today=today)
        assert panel["duty"]["acknowledged"] is False

    def test_unfilled_weeks_ahead_are_counted(self, db, lead):
        today = date(2026, 10, 7)
        duty.assign(db, duty=DUTY_ANALYST, week_start=today, user=lead,
                    actor=lead)
        panel = _collect_org(db, today=today)
        assert panel["duty_unfilled_weeks"] >= 1


class TestItNeverBreaksTheBoard:
    def test_the_panel_has_a_stable_shape(self, db):
        """The renderer reads these keys whatever state the SOC is in."""
        panel = _collect_org(db)
        for key in ("established", "filled", "filling", "gap",
                    "has_establishment", "headline", "worst", "duty",
                    "leads_gapped", "duty_unfilled_weeks"):
            assert key in panel, key

    def test_it_is_wired_into_the_snapshot(self):
        source = (_SRC / "ion" / "services" / "wallboard_service.py").read_text(
            encoding="utf-8")
        assert '"org":' in source
        assert "_collect_org" in source

    def test_the_snapshot_wraps_it_in_safe(self):
        """A failure in the staffing panel must not take the board down."""
        source = (_SRC / "ion" / "services" / "wallboard_service.py").read_text(
            encoding="utf-8")
        block = source.split('"org":')[1][:200]
        assert "_safe(" in block
