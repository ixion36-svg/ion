"""A role profile says which skills assessment belongs to it.

ION holds the same idea in three places that do not refer to each other:

  role_skills_service   five career roles (L1/L2/L3 analyst, SOC engineer,
                        threat hunter), each with competency areas and a
                        self-rated questionnaire, scored into RoleAssessment
  TeamCertification     what certificates a person actually holds
  RoleProfile           the workforce role, with its cert and signoff
                        requirements

So a lead recording an equivalence against "CompTIA Security+ (or
equivalent)" for an L2 analyst had to know, from nowhere in particular,
that ``l2_soc_analyst`` was the assessment to go and look at. Nothing in
the profile said so, and the two vocabularies were only ever joined in
somebody's head.

``skills_role_id`` is that join. It is optional -- a SOC can define a role
profile for something the questionnaires do not cover -- and it is
validated against the career roles that actually exist, because a profile
pointing at ``l4_analyst`` sends the next person looking for an assessment
nobody can take.
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
from ion.services import workforce_service as wf
from ion.services.role_skills_service import ROLE_DEFINITIONS


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


class TestTheLink:
    def test_a_profile_can_name_its_career_role(self, db):
        profile = wf.create_profile(db, name="SOC Analyst L2",
                                    skills_role_id="l2_soc_analyst")
        assert profile.skills_role_id == "l2_soc_analyst"

    def test_it_is_optional(self, db):
        """A SOC may define a role the questionnaires do not cover."""
        profile = wf.create_profile(db, name="Purple Team Liaison")
        assert profile.skills_role_id is None

    def test_an_unknown_career_role_is_refused(self, db):
        """A profile pointing at an assessment nobody can take sends the
        next person looking for something that does not exist."""
        with pytest.raises(wf.WorkforceError) as exc:
            wf.create_profile(db, name="Bad", skills_role_id="l4_analyst")
        assert "l4_analyst" in str(exc.value)

    def test_the_refusal_lists_what_is_available(self, db):
        with pytest.raises(wf.WorkforceError) as exc:
            wf.create_profile(db, name="Bad", skills_role_id="nonsense")
        message = str(exc.value)
        assert "l1_soc_analyst" in message

    @pytest.mark.parametrize(
        "role_id", [r["id"] for r in ROLE_DEFINITIONS])
    def test_every_career_role_is_accepted(self, db, role_id):
        """The validation must stay in step with the questionnaires; a
        career role that cannot be referenced is a dead one."""
        profile = wf.create_profile(db, name=f"Profile for {role_id}",
                                    skills_role_id=role_id)
        assert profile.skills_role_id == role_id


class TestResolvingTheAssessment:
    def test_the_profile_resolves_to_its_competency_areas(self, db):
        """What the link is for: a lead recording an equivalence can see
        which areas the assessment covers without knowing the slug."""
        profile = wf.create_profile(db, name="SOC Analyst L2",
                                    skills_role_id="l2_soc_analyst")
        areas = wf.skills_areas_for(profile)
        assert areas
        assert any(a["id"] == "rule_tuning" for a in areas)

    def test_a_profile_with_no_link_resolves_to_nothing(self, db):
        profile = wf.create_profile(db, name="Purple Team Liaison")
        assert wf.skills_areas_for(profile) == []

    def test_it_does_not_raise_on_a_stale_link(self, db):
        """If a career role is removed from the questionnaires later, an
        existing profile must degrade to "no areas" rather than break the
        page that renders it."""
        profile = wf.create_profile(db, name="SOC Analyst L2",
                                    skills_role_id="l2_soc_analyst")
        profile.skills_role_id = "retired_role"
        db.commit()
        assert wf.skills_areas_for(profile) == []


class TestItIsExposed:
    def test_the_api_accepts_it(self):
        source = (_SRC / "ion" / "web" / "workforce_api.py").read_text(
            encoding="utf-8")
        block = source.split("class ProfileIn(BaseModel):")[1][:500]
        assert "skills_role_id" in block

    def test_the_profile_listing_reports_it(self):
        """So the page can show which assessment belongs to the role."""
        source = (_SRC / "ion" / "web" / "workforce_api.py").read_text(
            encoding="utf-8")
        assert '"skills_role_id": p.skills_role_id' in source
