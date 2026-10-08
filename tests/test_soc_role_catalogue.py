"""A catalogue to pick from, and adopting one into a real role profile.

A lead building their establishment should not start from an empty page,
but the catalogue must not quietly become the SOC's configuration either.
Nothing exists until somebody adopts it, adopting builds an ordinary role
profile they can then edit, and the numbers and certificates it suggests
are suggestions.

The tests below are mostly about what the catalogue must not claim:

* the certificates are typical of the role, not required to do it, and
  any requirement can be met by assessed proficiency instead;
* an adopted profile is a draft, not a published one, so a lead reviews
  what they are taking on before anyone is held to it;
* adopting twice does not quietly make a second profile.
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

from ion.data.soc_role_catalogue import (
    CATEGORIES,
    SOC_ROLE_CATALOGUE,
    by_category,
    get_role,
)
from ion.models.base import Base
from ion.models.user import Permission, Role, User
from ion.models.workforce import PHASE_GATE, PHASE_READINESS, RoleProfile
from ion.services import workforce_service as wf
from ion.services.role_skills_service import ROLE_DEFINITIONS


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


# -- The catalogue itself -------------------------------------------------


class TestTheCatalogue:
    def test_it_covers_the_usual_shape_of_a_soc(self):
        ids = {r["id"] for r in SOC_ROLE_CATALOGUE}
        for expected in ("l1_soc_analyst", "l2_soc_analyst", "soc_shift_lead",
                         "detection_engineer", "incident_responder",
                         "cti_analyst", "grc_analyst"):
            assert expected in ids, expected

    @pytest.mark.parametrize("role", SOC_ROLE_CATALOGUE,
                             ids=lambda r: r["id"])
    def test_every_entry_is_complete(self, role):
        for field in ("id", "name", "category", "tier", "common",
                      "description", "typical_certifications",
                      "core_skills", "typical_establishment"):
            assert field in role, f"{role['id']} missing {field}"

    @pytest.mark.parametrize("role", SOC_ROLE_CATALOGUE,
                             ids=lambda r: r["id"])
    def test_the_category_is_a_known_one(self, role):
        assert role["category"] in CATEGORIES

    @pytest.mark.parametrize("role", SOC_ROLE_CATALOGUE,
                             ids=lambda r: r["id"])
    def test_a_skills_link_points_at_a_real_questionnaire(self, role):
        """ION has five questionnaires, not twenty. A link to one that
        does not exist sends a lead looking for an assessment nobody can
        take."""
        if not role.get("skills_role_id"):
            return
        known = {r["id"] for r in ROLE_DEFINITIONS}
        assert role["skills_role_id"] in known, role["id"]

    @pytest.mark.parametrize("role", SOC_ROLE_CATALOGUE,
                             ids=lambda r: r["id"])
    def test_every_role_says_something_useful(self, role):
        assert len(role["description"]) > 30
        assert role["core_skills"], role["id"]

    def test_ids_are_unique(self):
        ids = [r["id"] for r in SOC_ROLE_CATALOGUE]
        assert len(ids) == len(set(ids))

    def test_grouping_keeps_everything(self):
        grouped = by_category()
        assert sum(len(v) for v in grouped.values()) == len(SOC_ROLE_CATALOGUE)


# -- Adopting one ---------------------------------------------------------


class TestAdoption:
    def test_adopting_builds_a_role_profile(self, db, lead):
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        assert isinstance(profile, RoleProfile)
        assert profile.name == "SOC Analyst (L2)"

    def test_it_carries_the_skills_link(self, db, lead):
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        assert profile.skills_role_id == "l2_soc_analyst"

    def test_the_certificates_become_readiness_requirements(self, db, lead):
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        version = wf.draft_version(db, profile)
        certs = [r for r in version.requirements if r.kind == "cert"]
        assert certs
        assert all(r.phase == PHASE_READINESS for r in certs)

    def test_a_certificate_requirement_says_or_equivalent(self, db, lead):
        """The catalogue lists what the role usually asks for, not what
        somebody needs to do the job. The requirement has to carry that,
        or adopting it quietly hardens a suggestion into a rule."""
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        version = wf.draft_version(db, profile)
        certs = [r for r in version.requirements if r.kind == "cert"]
        assert any("equivalent" in r.name.lower() for r in certs)

    def test_the_version_is_left_as_a_draft(self, db, lead):
        """A lead reviews what they are taking on before anybody is held
        to it. Publishing on adopt would skip that."""
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        version = wf.draft_version(db, profile)
        assert not version.is_published

    def test_adopting_twice_returns_the_same_profile(self, db, lead):
        first = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        second = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        assert second.id == first.id
        assert db.query(RoleProfile).count() == 1

    def test_an_unknown_role_is_refused(self, db, lead):
        with pytest.raises(wf.WorkforceError) as exc:
            wf.adopt_catalogue_role(db, "chief_vibes_officer", adopter=lead)
        assert "chief_vibes_officer" in str(exc.value)

    def test_it_needs_permission(self, db):
        nobody = User(username="n", email="n@x", password_hash="x",
                      is_active=True)
        db.add(nobody)
        db.commit()
        with pytest.raises(wf.WorkforceError):
            wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=nobody)

    def test_adoption_is_audited(self, db, lead):
        from ion.models.user import AuditLog

        wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        actions = [a.action for a in db.query(AuditLog).all()]
        assert "workforce_role_adopted" in actions

    @pytest.mark.parametrize("role_id", [r["id"] for r in SOC_ROLE_CATALOGUE])
    def test_every_catalogue_role_can_be_adopted(self, db, lead, role_id):
        """A catalogue entry that cannot be adopted is decoration."""
        profile = wf.adopt_catalogue_role(db, role_id, adopter=lead)
        assert profile.id is not None


class TestAdoptionDoesNotInventAGate:
    def test_the_mandatory_items_come_from_the_baseline_not_the_catalogue(
        self, db, lead
    ):
        """The catalogue describes a role, not an organisation's vetting.
        Right-to-work and the acceptable use agreement are the SOC's to
        define once, on its baseline, not something a role catalogue
        should be guessing at per role."""
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        version = wf.draft_version(db, profile)
        gate = [r for r in version.requirements if r.phase == PHASE_GATE]
        assert gate == []

    def test_so_an_adopted_profile_is_not_publishable_until_a_gate_exists(
        self, db, lead
    ):
        """Which the publish guard already enforces for anything granting
        a role -- the lead has to decide the mandatory items deliberately."""
        profile = wf.adopt_catalogue_role(db, "l2_soc_analyst", adopter=lead)
        analyst = Role(name="analyst")
        db.add(analyst)
        db.commit()
        profile.grants_role_id = analyst.id
        db.commit()
        version = wf.draft_version(db, profile)
        with pytest.raises(wf.WorkforceError):
            wf.publish_version(db, version, lead)
