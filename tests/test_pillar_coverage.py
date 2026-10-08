"""Coverage of the day-to-day pillars, from three kinds of evidence.

A SOC asking "are we covered for forensics tomorrow" is asking about
three different things that get added together and should not be:

* somebody whose job it is -- in post, training finished, the pillar is
  what their role is accountable for;
* somebody who has rated themselves capable in it but does something
  else -- useful as secondary cover, and self-rated;
* somebody holding a current certificate in it -- examined on it once,
  which is not the same as doing it here.

One number hides all of that. "Three people" reading as cover when it is
three analysts who each ticked 4 out of 5 on a form is the failure this
is built to avoid, so every count stays visible next to the weighted
total and anything resting on self-rating says so.

The other thing it has to get right is the empty case. Nobody assessed
is not the same as nobody capable, and a pillar reported as uncovered
when the truth is unmeasured sends a lead recruiting for a gap that may
not exist.
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
from ion.models.skills import CapabilityThreshold, SkillAssessment, TeamCertification
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE
from ion.services import coverage_service as cov
from ion.services import workforce_service as wf
from ion.data import skills_matrix as sm

TODAY = date(2026, 10, 8)


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
        Permission(name="workforce:manage", resource="workforce", action="manage"),
        Permission(name="workforce:verify", resource="workforce", action="verify"),
    ]
    u = User(username="lead", email="l@x", password_hash="x",
             display_name="Rita Okonjo", is_active=True)
    u.roles = [role]
    db.add(u)
    db.commit()
    return u


def person(db, username, name):
    u = User(username=username, email=f"{username}@x", password_hash="x",
             display_name=name, is_active=True)
    db.add(u)
    db.commit()
    return u


def adopt_and_publish(db, lead, catalogue_id):
    """A published profile for a catalogue role, with a gate item."""
    granted = db.query(Role).filter(Role.name == "analyst").one_or_none()
    if granted is None:
        granted = Role(name="analyst")
        db.add(granted)
        db.commit()
    profile = wf.adopt_catalogue_role(db, catalogue_id, adopter=lead)
    version = wf.draft_version(db, profile)
    wf.add_requirement(db, version, name="Right to work", kind="vetting",
                       phase=PHASE_GATE)
    profile.grants_role_id = granted.id
    db.commit()
    wf.publish_version(db, version, lead)
    db.commit()
    return profile


def seat(db, lead, user, catalogue_id, *, operational=True):
    """Give somebody a live journey against a catalogue role.

    No org post: coverage is drawn from journeys rather than from the
    establishment on purpose. Somebody cleared and operational on a role
    is cover for its pillars whether or not the ORBAT has a numbered post
    for them, and a SOC that has not run the establishment yet should not
    read as having no capability.
    """
    profile = db.query(wf.RoleProfile).filter(
        wf.RoleProfile.catalogue_id == catalogue_id).one_or_none()
    if profile is None:
        profile = adopt_and_publish(db, lead, catalogue_id)
    version = wf.latest_published(db, profile.id)
    journey = wf.assign_profile(db, user=user, version=version, assigner=lead)
    if operational:
        journey.stage = wf.STAGE_OPERATIONAL
        db.commit()
    return journey


def rate(db, user, pillar, level):
    """Self-rate every skill in a pillar at one level."""
    for key in sm.skill_keys(pillar):
        db.add(SkillAssessment(user_id=user.id, skill_key=key, rating=level))
    db.commit()


def certify(db, user, cert, *, expires=None, status="active"):
    db.add(TeamCertification(user_id=user.id, cert_name=cert,
                             expiry_date=expires, status=status))
    db.commit()


def pillar(report, name):
    return next(p for p in report["pillars"] if p["pillar"] == name)


# --- the empty cases --------------------------------------------------------


class TestNothingRecorded:
    def test_an_unmeasured_pillar_is_not_reported_as_uncovered(self, db):
        """"Uncovered" sends a lead recruiting. "Unmeasured" sends them to
        ask the team to fill the form in. They are different jobs."""
        report = cov.pillar_coverage(db, today=TODAY)
        ir = pillar(report, "Incident Response")
        assert ir["state"] == "unmeasured"
        assert ir["weighted"] == 0.0
        assert "nobody" in ir["headline"].lower() or \
               "no " in ir["headline"].lower()

    def test_every_pillar_appears(self, db):
        report = cov.pillar_coverage(db, today=TODAY)
        assert [p["pillar"] for p in report["pillars"]] == list(sm.PILLARS)

    def test_it_says_the_whole_report_rests_on_nothing(self, db):
        report = cov.pillar_coverage(db, today=TODAY)
        assert report["measured"] is False


# --- primary cover ----------------------------------------------------------


class TestSomebodyWhoseJobItIs:
    def test_an_operational_responder_covers_incident_response(self, db, lead):
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        ir = pillar(cov.pillar_coverage(db, today=TODAY), "Incident Response")
        assert ir["primary"] == 1
        assert ir["weighted"] == pytest.approx(1.0)
        assert ir["state"] == "covered"

    def test_they_are_named(self, db, lead):
        """A count tells a lead they are short. A name is what they act
        on."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        ir = pillar(cov.pillar_coverage(db, today=TODAY), "Incident Response")
        assert [p["name"] for p in ir["people"]] == ["Sam Reilly"]
        assert ir["people"][0]["basis"] == "primary"

    def test_still_in_training_is_not_cover(self, db, lead):
        """Somebody in the post whose journey is unfinished is reported
        apart from the cover, because they are not it yet."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder", operational=False)
        ir = pillar(cov.pillar_coverage(db, today=TODAY), "Incident Response")
        assert ir["primary"] == 0
        assert ir["in_training"] == 1
        assert ir["weighted"] == 0.0
        assert ir["state"] != "covered"

    def test_a_role_covers_only_the_pillars_it_owns(self, db, lead):
        """An incident responder is not cover for threat intelligence, and
        a model that spreads them across every pillar they have any target
        in would say they are."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        report = cov.pillar_coverage(db, today=TODAY)
        assert pillar(report, "Threat Intelligence")["primary"] == 0

    def test_a_profile_the_matrix_cannot_place_is_reported_not_dropped(
            self, db, lead):
        """A vulnerability analyst has no matrix role, so they count
        towards no pillar. Silently contributing nothing is the same
        output as not existing, so they are listed."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "vuln_analyst")
        report = cov.pillar_coverage(db, today=TODAY)
        assert "Sam Reilly" in [p["name"] for p in report["unplaced"]]


# --- secondary cover --------------------------------------------------------


class TestSelfRatedSecondaryCover:
    def test_a_capable_analyst_is_partial_cover(self, db, lead):
        """An L2 who rates themselves competent at forensics is worth
        something tomorrow. Not a forensics analyst."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        rate(db, sam, "Digital Forensics", 4)
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["secondary"] == 1
        assert df["primary"] == 0
        assert 0 < df["weighted"] < 1.0

    def test_it_is_labelled_self_rated(self, db, lead):
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        rate(db, sam, "Digital Forensics", 4)
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["self_rated_only"] is True
        assert "self-rated" in df["headline"].lower() or \
               "self-assessed" in df["headline"].lower()
        assert df["people"][0]["basis"] == "secondary"
        assert df["people"][0]["measured"] is False

    def test_a_low_rating_is_not_cover(self, db, lead):
        """Rating yourself "aware" of memory forensics is not cover for
        it, and counting it would make every pillar look staffed."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        rate(db, sam, "Digital Forensics", 1)
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["secondary"] == 0
        assert df["state"] != "covered"

    def test_a_rating_without_a_post_is_not_cover(self, db):
        """Somebody with no live journey is not on the rota, whatever they
        rated themselves."""
        sam = person(db, "sam", "Sam Reilly")
        rate(db, sam, "Digital Forensics", 5)
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["secondary"] == 0

    def test_primary_is_not_double_counted_as_secondary(self, db, lead):
        """Somebody whose job it is, who also rated themselves highly in
        it, is one person."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        rate(db, sam, "Incident Response", 5)
        ir = pillar(cov.pillar_coverage(db, today=TODAY), "Incident Response")
        assert ir["primary"] == 1
        assert ir["secondary"] == 0
        assert ir["weighted"] == pytest.approx(1.0)
        assert len(ir["people"]) == 1


# --- certificates -----------------------------------------------------------


class TestCertificates:
    def test_a_current_certificate_adds_to_cover(self, db, lead):
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        certify(db, sam, "GIAC GCFA", expires=TODAY + timedelta(days=200))
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["certified"] == 1
        assert df["weighted"] > 0

    def test_an_expired_certificate_does_not(self, db, lead):
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        certify(db, sam, "GIAC GCFA", expires=TODAY - timedelta(days=1))
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["certified"] == 0
        assert df["expired_certs"] == 1

    def test_a_planned_certificate_does_not(self, db, lead):
        """"Planned" is a development item. Counting it as cover would
        credit the SOC with a course nobody has sat."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        certify(db, sam, "GIAC GCFA", status="planned")
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["certified"] == 0

    def test_a_certificate_with_no_expiry_counts(self, db, lead):
        """Plenty of certificates do not expire, and treating a blank
        expiry as expired would quietly delete them."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        certify(db, sam, "Offensive Security OSCP")
        off = pillar(cov.pillar_coverage(db, today=TODAY), "Offensive Security")
        assert off["certified"] == 1

    def test_a_certificate_cannot_make_somebody_more_than_one_person(
            self, db, lead):
        """Self-rated plus two certificates is still one body on shift."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        rate(db, sam, "Digital Forensics", 5)
        certify(db, sam, "GIAC GCFA")
        certify(db, sam, "GIAC GCFE")
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["weighted"] <= 1.0
        assert len(df["people"]) == 1

    def test_a_certificate_alone_does_not_outweigh_the_job(self, db, lead):
        """Deliberate ordering: whoever owns the pillar counts for more
        than whoever has the badge for it."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "l2_soc_analyst")
        certify(db, sam, "GIAC GCFA")
        pat = person(db, "pat", "Pat Nuno")
        seat(db, lead, pat, "dfir_analyst")
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        people = {p["name"]: p["weight"] for p in df["people"]}
        assert people["Pat Nuno"] > people["Sam Reilly"]


# --- what a lead reads off it -----------------------------------------------


class TestTheHonestyOfTheHeadline:
    def test_cover_resting_only_on_self_rating_says_so(self, db, lead):
        """Three analysts who each ticked 4 on a form is not three
        forensics analysts, and the one screen a lead trusts for this has
        to say which it is."""
        for n in range(3):
            u = person(db, f"a{n}", f"Analyst {n}")
            seat(db, lead, u, "l2_soc_analyst")
            rate(db, u, "Digital Forensics", 4)
        df = pillar(cov.pillar_coverage(db, today=TODAY), "Digital Forensics")
        assert df["self_rated_only"] is True
        assert df["state"] == "self_rated"

    def test_a_threshold_is_honoured(self, db, lead):
        db.add(CapabilityThreshold(capability_key="Incident Response",
                                   min_staff=2, min_level=3))
        db.commit()
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        ir = pillar(cov.pillar_coverage(db, today=TODAY), "Incident Response")
        assert ir["min_staff"] == 2
        assert ir["state"] == "thin"

    def test_a_pillar_nobody_in_post_owns_is_called_out(self, db, lead):
        """Not the same as unmeasured: this SOC has people, and nobody
        whose job this is."""
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        off = pillar(cov.pillar_coverage(db, today=TODAY), "Offensive Security")
        assert off["primary"] == 0
        assert off["state"] == "uncovered"

    def test_the_report_counts_the_uncovered_pillars(self, db, lead):
        sam = person(db, "sam", "Sam Reilly")
        seat(db, lead, sam, "incident_responder")
        report = cov.pillar_coverage(db, today=TODAY)
        assert report["uncovered"] >= 1
        assert report["measured"] is True

    def test_the_endpoint_is_gated_like_the_rest_of_the_module(self):
        """Who is thin on what capability is staffing information. It
        reads behind workforce:read and 404s with the module off, the
        same as every other route here."""
        from ion.web import workforce_api

        route = next(r for r in workforce_api.router.routes
                     if getattr(r, "path", "") == "/workforce/coverage")
        gates = {getattr(d.dependency, "__name__", "")
                 for d in (route.dependencies or [])}
        assert "require_workforce_module" in gates

        source = (_SRC / "ion" / "web" / "workforce_api.py").read_text(
            encoding="utf-8")
        block = source.split("def coverage(")[1].split("\n\n\n")[0]
        assert 'require_permission("workforce:read")' in block

    def test_the_shape_is_stable(self, db):
        """The wallboard and the ORBAT read these keys in every state."""
        report = cov.pillar_coverage(db, today=TODAY)
        for key in ("pillars", "measured", "uncovered", "unplaced",
                    "self_rated_pillars"):
            assert key in report, key
        for p in report["pillars"]:
            for key in ("pillar", "owners", "people", "primary", "secondary",
                        "certified", "in_training", "expired_certs",
                        "weighted", "state", "headline", "self_rated_only",
                        "min_staff"):
                assert key in p, (p.get("pillar"), key)
