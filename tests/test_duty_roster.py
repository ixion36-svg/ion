"""The weekly duty analyst, who runs the daily standup.

Distinct from the establishment and from a shift rota. A post says the SOC
needs an L2; a shift says who is working Tuesday night; a duty says who
carries a named responsibility for the week, whatever posts they hold.

Most of these tests are about the empty cases, because a duty rota's
failure mode is not a wrong name against a week -- somebody notices that
on the Monday. It is a week with no name at all, which looks exactly like
a week nobody has scrolled to, and quietly becomes the week the standup
did not happen.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.duty_roster import DUTY_ANALYST, DutyAssignment
from ion.models.user import Permission, Role, User
from ion.services import duty_roster_service as duty


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
def analyst(db):
    u = User(username="ana", email="a@x", password_hash="x",
             display_name="Ana Analyst", is_active=True)
    db.add(u)
    db.commit()
    return u


MONDAY = date(2026, 10, 5)      # a real Monday
WEDNESDAY = date(2026, 10, 7)


# -- The week ------------------------------------------------------------


class TestTheWeek:
    def test_a_duty_is_assigned_for_a_week(self, db, lead, analyst):
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                          user=analyst, actor=lead)
        assert row.week_start == MONDAY
        assert row.user_id == analyst.id

    def test_any_day_in_the_week_normalises_to_its_monday(self, db, lead,
                                                          analyst):
        """Otherwise a rota ends up with overlapping weeks that each look
        valid on their own, and two people are both "this week"."""
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=WEDNESDAY,
                          user=analyst, actor=lead)
        assert row.week_start == MONDAY

    def test_reassigning_the_same_week_replaces_rather_than_duplicates(
        self, db, lead, analyst
    ):
        other = User(username="b", email="b@x", password_hash="x",
                     is_active=True)
        db.add(other)
        db.commit()
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=other,
                    actor=lead)
        rows = db.query(DutyAssignment).all()
        assert len(rows) == 1
        assert rows[0].user_id == other.id

    def test_different_weeks_coexist(self, db, lead, analyst):
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY + timedelta(days=7),
                    user=analyst, actor=lead)
        assert db.query(DutyAssignment).count() == 2


# -- Nobody on duty is the case that matters -----------------------------


class TestTheEmptyWeek:
    def test_an_unassigned_week_says_so_rather_than_returning_nothing(
        self, db
    ):
        """None is ambiguous at a call site: it reads the same as "we have
        not loaded it yet". The caller needs to be able to say "nobody is
        running the standup this week" out loud."""
        current = duty.current(db, duty=DUTY_ANALYST, today=MONDAY)
        assert current["assigned"] is False
        assert current["user"] is None
        assert "nobody" in current["summary"].lower()

    def test_an_assigned_week_names_the_person(self, db, lead, analyst):
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        current = duty.current(db, duty=DUTY_ANALYST, today=WEDNESDAY)
        assert current["assigned"] is True
        assert current["user"]["name"] == "Ana Analyst"

    def test_gaps_in_the_coming_weeks_are_listed(self, db, lead, analyst):
        """The point of looking ahead is to find the week nobody has
        filled, so it has to come back as a row rather than be absent."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        weeks = duty.upcoming(db, duty=DUTY_ANALYST, weeks=4, today=MONDAY)
        assert len(weeks) == 4
        assert weeks[0]["assigned"] is True
        assert all(w["assigned"] is False for w in weeks[1:])

    def test_the_count_of_unfilled_weeks_is_reported(self, db, lead, analyst):
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        summary = duty.rota_summary(db, duty=DUTY_ANALYST, weeks=4,
                                    today=MONDAY)
        assert summary["unfilled"] == 3


# -- Acknowledgement -----------------------------------------------------


class TestAcknowledgement:
    def test_an_assignment_starts_unacknowledged(self, db, lead, analyst):
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                          user=analyst, actor=lead)
        assert row.acknowledged_at is None

    def test_the_holder_can_acknowledge_it(self, db, lead, analyst):
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                          user=analyst, actor=lead)
        duty.acknowledge(db, assignment_id=row.id, actor=analyst)
        db.refresh(row)
        assert row.acknowledged_at is not None

    def test_somebody_else_cannot_acknowledge_on_their_behalf(
        self, db, lead, analyst
    ):
        """A rota entry nobody acknowledged is a plan, not a fact, and the
        difference matters on the Monday somebody is off sick. A lead
        ticking it for them erases exactly that signal."""
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                          user=analyst, actor=lead)
        with pytest.raises(duty.DutyError):
            duty.acknowledge(db, assignment_id=row.id, actor=lead)

    def test_current_reports_whether_it_was_acknowledged(self, db, lead,
                                                         analyst):
        row = duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                          user=analyst, actor=lead)
        assert duty.current(db, duty=DUTY_ANALYST,
                            today=MONDAY)["acknowledged"] is False
        duty.acknowledge(db, assignment_id=row.id, actor=analyst)
        assert duty.current(db, duty=DUTY_ANALYST,
                            today=MONDAY)["acknowledged"] is True


# -- Who may set it ------------------------------------------------------


class TestPermission:
    def test_assigning_needs_permission(self, db, analyst):
        with pytest.raises(duty.DutyError):
            duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                        user=analyst, actor=analyst)

    def test_an_unknown_duty_is_refused(self, db, lead, analyst):
        with pytest.raises(duty.DutyError) as exc:
            duty.assign(db, duty="tea_rota", week_start=MONDAY,
                        user=analyst, actor=lead)
        assert "tea_rota" in str(exc.value)

    def test_an_inactive_user_is_refused(self, db, lead, analyst):
        """Rostering somebody who has left reads as covered until the
        Monday it is not."""
        analyst.is_active = False
        db.commit()
        with pytest.raises(duty.DutyError):
            duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY,
                        user=analyst, actor=lead)

    def test_assigning_is_audited(self, db, lead, analyst):
        from ion.models.user import AuditLog

        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=analyst,
                    actor=lead)
        actions = [a.action for a in db.query(AuditLog).all()]
        assert "duty_assigned" in actions


# -- Looking back --------------------------------------------------------


class TestHistory:
    def test_a_past_week_is_still_readable(self, db, lead, analyst):
        """Who was on duty when something went wrong is a question people
        ask afterwards."""
        past = MONDAY - timedelta(days=14)
        duty.assign(db, duty=DUTY_ANALYST, week_start=past, user=analyst,
                    actor=lead)
        row = duty.for_week(db, duty=DUTY_ANALYST, week_start=past)
        assert row is not None
        assert row.user_id == analyst.id

    def test_current_does_not_pick_up_last_weeks_holder(self, db, lead,
                                                        analyst):
        """Carrying a stale name forward is worse than showing nobody: it
        says somebody is covering when they think they finished on
        Friday."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY - timedelta(days=7),
                    user=analyst, actor=lead)
        current = duty.current(db, duty=DUTY_ANALYST, today=MONDAY)
        assert current["assigned"] is False
