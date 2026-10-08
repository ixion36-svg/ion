"""Somebody other than the ION administrator has to be able to verify.

Found by walking onboarding in the browser, 8 October 2026. A joiner
submitted all four mandatory items, the SOC lead signed in to verify them,
opened /workforce/people and got::

    {"detail":"Permission denied"}

The three workforce permissions were held like this::

    workforce:manage | admin
    workforce:read   | admin, principal_analyst
    workforce:verify | admin

So the only account that could verify anybody's onboarding was the ION
administrator. The ``lead`` role -- the role whose description is "SOC Lead
with team oversight and operational management" -- held none of the three,
and could not see their own team's queue, let alone action it.

That makes the whole submit-then-verify split unusable in practice. Either
the administrator does every verification in the SOC, or somebody is given
admin to approve induction paperwork, which is the worse of the two.

Two changes:

* ``lead`` gains read and verify. A lead runs their team's onboarding; it
  is the job. They do not get ``manage``, which defines role profiles and
  assigns roles -- that is a change to the establishment, not to one
  person's progress.

* A ``grc`` role exists, because governance and compliance is who signs
  off vetting and agreements in most organisations, and because an
  assessor needs an account that can read and verify the record without
  also being able to rewrite the role profiles it was measured against.
  GRC gets read and verify, not manage, for exactly that reason.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_SERVICE = (_SRC / "ion" / "auth" / "service.py").read_text(encoding="utf-8")


def _role_block(name: str) -> str:
    """The permission list literal for a seeded role."""
    marker = f'"{name}",'
    idx = _SERVICE.find(marker)
    assert idx != -1, f"no seeded role named {name}"
    start = _SERVICE.find("[", idx)
    end = _SERVICE.find("]", start)
    return _SERVICE[start:end]


class TestTheLeadCanRunTheirTeam:
    def test_lead_can_verify(self):
        assert "workforce:verify" in _role_block("lead"), (
            "a lead could not verify their own team's onboarding, so every "
            "verification in the SOC fell to the ION administrator"
        )

    def test_lead_can_read(self):
        assert "workforce:read" in _role_block("lead")

    def test_lead_cannot_manage(self):
        """manage defines role profiles and assigns roles. That is a change
        to the establishment, not to one person's progress."""
        assert "workforce:manage" not in _role_block("lead")


class TestTheGrcRoleExists:
    def test_there_is_a_grc_role(self):
        assert '"grc",' in _SERVICE, (
            "governance and compliance is who signs off vetting and "
            "agreements in most organisations"
        )

    def test_grc_can_verify(self):
        assert "workforce:verify" in _role_block("grc")

    def test_grc_can_read(self):
        assert "workforce:read" in _role_block("grc")

    def test_grc_cannot_manage(self):
        """An assessor needs to read and verify the record without being
        able to rewrite the role profiles it was measured against."""
        assert "workforce:manage" not in _role_block("grc")

    def test_grc_is_not_an_analyst_role(self):
        """It governs the record; it does not work the queue. Bundling
        alert and case access into it would make the compliance account a
        standing way into operational data."""
        block = _role_block("grc")
        for permission in ("alert:triage", "case:create", "playbook:execute",
                           "response:approve"):
            assert permission not in block, permission

    def test_grc_can_see_the_audit_trail(self):
        """Verifying somebody's onboarding without being able to read the
        audit log is signing for something you cannot check."""
        block = _role_block("grc")
        assert "security:read" in block


class TestManageStaysNarrow:
    def test_only_admin_manages_the_establishment(self):
        """Everyone who can define role profiles can decide what the SOC's
        own requirements are, so the list should stay short and deliberate."""
        holders = [
            name for name in ("analyst", "senior_analyst", "principal_analyst",
                              "lead", "grc", "forensic", "soc_engineer",
                              "senior_engineer", "platform_engineer",
                              "engineering")
            if "workforce:manage" in _role_block(name)
        ]
        assert holders == [], holders


class TestTheVerificationPathIsStillGuarded:
    def test_the_people_page_still_requires_verify(self):
        """Widening who holds the permission must not remove the check."""
        server = (_SRC / "ion" / "web" / "server.py").read_text(encoding="utf-8")
        assert 'require_page_permission("workforce:verify")' in server

    def test_a_sponsor_may_still_verify_their_own_people(self):
        """The existing escape hatch: a named sponsor can verify without
        holding the global permission."""
        wf = (_SRC / "ion" / "services" / "workforce_service.py").read_text(
            encoding="utf-8")
        block = wf.split("def _may_verify(")[1][:400]
        assert "sponsor_id" in block
