"""The standup record says who was on duty, and who actually ran it.

The rota names a duty analyst for the week and says they run the daily
standup. The standup itself is signed by whoever types their name into a
free-text box. Nothing connected the two, so the rota could say one thing
and the record another, every day, and no screen would ever disagree
with itself.

The design here is deliberately not enforcement. A duty holder off sick
must not block the standup, so anybody can run it -- but the saved record
names both the person on the rota and the person who signed, and says so
when they differ. A rota nobody follows is not a rota, and the only way
to find that out is to write it down each day.

Three states have to stay distinct, because collapsing them is how this
goes wrong:

* nobody is on the rota        -> not a mismatch, an empty rota
* the duty holder signed       -> the rota held
* somebody else signed         -> the rota did not hold, and that is fine
                                  as long as it is visible
"""

from __future__ import annotations

import sys
from datetime import date
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
from ion.services import duty_roster_service as duty

MONDAY = date(2026, 10, 5)
WEDNESDAY = date(2026, 10, 7)


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
    u = User(username="lead", email="l@x", password_hash="x",
             display_name="Rita Okonjo", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


@pytest.fixture
def other(db):
    u = User(username="pnuno", email="p@x", password_hash="x",
             display_name="Pat Nuno", is_active=True)
    db.add(u)
    db.commit()
    return u


class TestAnEmptyRota:
    def test_nobody_on_duty_is_not_a_mismatch(self, db, other):
        """"Signed by the wrong person" and "nobody was rostered" are
        different problems, and only one of them is anybody's fault."""
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        assert att["matches_rota"] is None
        assert att["duty"]["assigned"] is False
        assert "nobody" in att["note"].lower()

    def test_it_still_records_who_ran_it(self, db, other):
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        assert att["signed_by"] == "Pat Nuno"


class TestTheRotaHeld:
    def test_the_duty_holder_signing_matches(self, db, lead):
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Rita Okonjo", signatory_user_id=lead.id,
            today=WEDNESDAY)
        assert att["matches_rota"] is True
        assert att["duty"]["user"]["name"] == "Rita Okonjo"

    def test_the_user_id_decides_not_the_typed_name(self, db, lead):
        """The name is free text. If the signed-in user is the duty
        holder it matches regardless of what they typed, because a typo
        in a name box is not a rota breach."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="R. Okonjo", signatory_user_id=lead.id,
            today=WEDNESDAY)
        assert att["matches_rota"] is True

    def test_a_typed_name_alone_can_match(self, db, lead):
        """Older standups post a name with no user id. Falling back to a
        tolerant name match beats reporting every one of them as a
        breach."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="  rita okonjo ", signatory_user_id=None,
            today=WEDNESDAY)
        assert att["matches_rota"] is True


class TestTheRotaDidNotHold:
    def test_somebody_else_signing_is_recorded_not_rejected(
            self, db, lead, other):
        """Anybody can run the standup. The point is that it is written
        down, not that it is blocked."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        assert att["matches_rota"] is False

    def test_the_note_names_both_people(self, db, lead, other):
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        assert "Pat Nuno" in att["note"]
        assert "Rita Okonjo" in att["note"]

    def test_an_unacknowledged_rota_is_surfaced(self, db, lead):
        """A rota entry the holder never picked up is a plan. If the
        standup is then run by somebody else, the plan was fiction all
        week and the record should let somebody notice."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Rita Okonjo", signatory_user_id=lead.id,
            today=WEDNESDAY)
        assert att["duty"]["acknowledged"] is False


class TestNobodySigned:
    def test_an_unsigned_standup_is_not_a_match(self, db, lead):
        """An empty signature box must not read as "the duty holder did
        it" just because nobody contradicted the rota."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="", signatory_user_id=None, today=WEDNESDAY)
        assert att["matches_rota"] is False
        assert att["signed_by"] is None
        assert "not signed" in att["note"].lower() or \
               "unsigned" in att["note"].lower()


class TestTheSavedRecord:
    """The saved standup document is the thing anybody reads a week later.

    Its sign-off block used to print "Duty Analyst: <whatever was typed>",
    which asserts the one fact it has no way of knowing. The typed name
    is the signatory; the duty analyst is whoever the rota says.
    """

    def _data(self, analyst_name="Pat Nuno"):
        from ion.web.daily_standup_api import StandupSaveRequest
        return StandupSaveRequest(analyst_name=analyst_name, signed_off=True)

    def _user(self):
        return User(username="pnuno", email="p@x", password_hash="x",
                    display_name="Pat Nuno", is_active=True)

    def test_the_typed_name_is_not_labelled_duty_analyst(self, db, lead,
                                                         other):
        from ion.web.daily_standup_api import _render_standup_html

        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        html = _render_standup_html(self._data(), self._user(),
                                    attribution=att)
        # Anywhere in the document, not just the footer. The first pass
        # fixed the sign-off block and left the meta header still
        # printing "Duty Analyst: <signatory>" two inches above it.
        assert "Duty Analyst" not in html
        assert "Signed off by" in html
        # Once, not twice. The header and the sign-off block both carried
        # the signatory in identical words, which read as a stutter the
        # moment the two labels agreed.
        assert html.count("Signed off by") == 1

    def test_it_names_the_person_actually_on_the_rota(self, db, lead,
                                                      other):
        from ion.web.daily_standup_api import _render_standup_html

        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        html = _render_standup_html(self._data(), self._user(),
                                    attribution=att)
        assert "Rita Okonjo" in html
        assert "Pat Nuno" in html

    def test_an_empty_rota_is_stated_in_the_record(self, db, other):
        from ion.web.daily_standup_api import _render_standup_html

        att = duty.standup_attribution(
            db, signatory_name="Pat Nuno", signatory_user_id=other.id,
            today=WEDNESDAY)
        html = _render_standup_html(self._data(), self._user(),
                                    attribution=att)
        assert "obody" in html      # "Nobody was on duty analyst duty..."

    def test_without_attribution_it_claims_no_duty_analyst(self):
        """The PDF path and older callers pass nothing. They must not get
        the old claim back by default."""
        from ion.web.daily_standup_api import _render_standup_html

        html = _render_standup_html(self._data(), self._user())
        assert "Duty Analyst:</strong> Pat Nuno" not in html
        assert "Pat Nuno" in html


class TestTheDutyLineLoadsOnItsOwn:
    """Found by opening the page, not by reading it.

    /checks is operator-triggered: nothing loads until somebody presses
    "Run checks", and it sweeps Elasticsearch for cluster health, alerts
    and log sources. The duty rota is a single local row. Hanging it off
    that sweep means the page says "checking the duty rota" until a
    button is pressed, and says nothing at all if Elasticsearch is down
    -- which is exactly when knowing who is on call matters.

    So the rota gets its own endpoint the page can call on load.
    """

    def _source(self):
        return (_SRC / "ion" / "web" / "daily_standup_api.py").read_text(
            encoding="utf-8")

    def test_there_is_a_duty_endpoint(self):
        from ion.web.daily_standup_api import router

        paths = {getattr(r, "path", "") for r in router.routes}
        assert "/daily-standup/duty" in paths, sorted(paths)

    def test_it_requires_a_permission(self):
        block = self._source().split("def standup_duty(")[1][:600]
        assert "require_permission(" in block

    def test_it_does_not_touch_elasticsearch(self):
        """The whole point is that it answers when ES does not."""
        block = self._source().split("def standup_duty(")[1][:600]
        for forbidden in ("_check_cluster_health", "_check_critical_alerts",
                          "elasticsearch", "_es_"):
            assert forbidden not in block, forbidden

    def test_the_page_loads_it_without_waiting_for_the_checks_sweep(self):
        page = (_SRC / "ion" / "web" / "templates"
                / "daily_standup.html").read_text(encoding="utf-8")
        assert "/api/daily-standup/duty" in page, \
            "the page must fetch the rota on load, not only via runChecks"


class TestTheWiring:
    """Both render paths must agree. A printed standup that claims the
    rota held while the saved one says otherwise is worse than neither
    saying anything."""

    def _source(self):
        return (_SRC / "ion" / "web" / "daily_standup_api.py").read_text(
            encoding="utf-8")

    def test_save_passes_the_attribution(self):
        block = self._source().split("def save_daily_standup(")[1][:1200]
        assert "_standup_attribution(" in block

    def test_pdf_passes_the_attribution(self):
        block = self._source().split("def export_standup_pdf(")[1][:1200]
        assert "_standup_attribution(" in block
        assert "attribution=attribution" in block

    def test_checks_reports_who_is_on_duty(self):
        block = self._source().split("def get_daily_checks(")[1][:2500]
        assert '"duty":' in block

    def test_the_duty_lookup_cannot_break_the_page(self):
        """Every other check in this endpoint is wrapped so one failure
        does not take the panel down; the rota lookup is no different."""
        block = self._source().split("def _duty_today(")[1][:1200]
        assert "except Exception" in block


class TestTheShape:
    def test_it_always_returns_the_same_keys(self, db):
        att = duty.standup_attribution(
            db, signatory_name="", signatory_user_id=None, today=WEDNESDAY)
        for key in ("duty", "signed_by", "signed_by_user_id",
                    "matches_rota", "note"):
            assert key in att, key

    def test_it_is_scoped_to_the_week_being_asked_about(self, db, lead):
        """Last week's holder must not be reported as running today's
        standup."""
        duty.assign(db, duty=DUTY_ANALYST, week_start=MONDAY, user=lead,
                    actor=lead)
        att = duty.standup_attribution(
            db, signatory_name="Rita Okonjo", signatory_user_id=lead.id,
            today=date(2026, 10, 14))      # the following week
        assert att["duty"]["assigned"] is False
        assert att["matches_rota"] is None
