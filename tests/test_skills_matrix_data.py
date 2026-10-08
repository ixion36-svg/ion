"""The skills matrix is the same on both sides.

It was JavaScript in training.html and nothing on the server could read
it, which is why pillar coverage could be drawn as a heatmap and never
compared against who is actually in post. It now lives in
ion.data.skills_matrix, and the template still carries a copy for the
heatmap it renders in the browser.

Two copies of reference data drift. Nobody notices, because each page
looks right on its own -- the heatmap keeps using the old targets and
coverage uses the new ones, and the two screens disagree about the same
SOC. These tests parse the template's literal and compare it, so the
drift fails here rather than in a conversation about which number is
right.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.data import skills_matrix as sm
from ion.data.soc_role_catalogue import SOC_ROLE_CATALOGUE

_TEMPLATE = _SRC / "ion" / "web" / "templates" / "training.html"


def _parse_js_object(src: str, name: str) -> dict:
    """The named object literal out of the template, as Python.

    Narrow on purpose. It handles the two literals this test checks and
    nothing else; a general JavaScript parser here would be a second thing
    to maintain.
    """
    block = src[src.index(f"const {name} = {{"):]
    block = block[block.index("{"):]
    depth = 0
    for i, ch in enumerate(block):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                block = block[:i + 1]
                break
    js = re.sub(r"'([^']*)'", lambda m: json.dumps(m.group(1)), block)
    js = re.sub(r"(\{|,)\s*([A-Za-z_][\w-]*)\s*:",
                lambda m: f'{m.group(1)}"{m.group(2)}":', js)
    js = re.sub(r",(\s*[}\]])", r"\1", js)
    return json.loads(js)


class TestTheTwoCopiesAgree:
    def test_the_matrix_matches_the_template(self):
        template = _parse_js_object(
            _TEMPLATE.read_text(encoding="utf-8"), "SKILLS_MATRIX")
        assert template == json.loads(json.dumps(sm.SKILLS_MATRIX)), (
            "training.html and ion.data.skills_matrix disagree. Edit one, "
            "copy to the other, or the heatmap and coverage will describe "
            "different SOCs."
        )

    def test_the_pillars_match_the_template(self):
        caps = _parse_js_object(
            _TEMPLATE.read_text(encoding="utf-8"), "SOC_CAPABILITIES")
        assert {k: v["cat"] for k, v in caps.items()} == sm.PILLARS

    def test_every_pillar_names_a_category_that_exists(self):
        for pillar, category in sm.PILLARS.items():
            assert category in sm.SKILLS_MATRIX, (pillar, category)
            assert sm.skill_keys(pillar), pillar


class TestOwnership:
    def test_every_pillar_has_somebody_who_owns_it(self):
        """A pillar nobody's targets make them accountable for cannot be
        covered by anybody, so coverage would read as a permanent gap with
        no role to fill it."""
        for pillar in sm.pillars():
            assert sm.owners_of(pillar), pillar

    def test_juniors_own_nothing(self):
        """An L1 is working towards pillars, not answerable for one. The
        top-scoring clause in the owner rule would credit them with SIEM
        at a mean target of 1.0 without the floor."""
        assert "l1-analyst" not in sm.pillars_owned_by("l1-analyst")
        assert sm.pillars_owned_by("l1-analyst") == ()
        assert sm.pillars_owned_by("l2-analyst") == ()

    def test_the_obvious_owners_are_the_obvious_roles(self):
        assert "incident-responder" in sm.owners_of("Incident Response")
        assert "threat-intel" in sm.owners_of("Threat Intelligence")
        assert "detection-engineer" in sm.owners_of("Detection Engineering")
        assert "digital-forensics" in sm.owners_of("Digital Forensics")
        assert "grc" in sm.owners_of("Governance & Leadership")
        assert "pen-tester" in sm.owners_of("Offensive Security")

    def test_a_role_can_own_more_than_one(self):
        """Real roles straddle pillars, and forcing one owner each would
        make the second pillar look uncovered."""
        assert len(sm.pillars_owned_by("detection-engineer")) >= 2

    def test_the_under_specified_roles_are_named_not_hidden(self):
        """These are roles whose targets never reach ownership of
        anything. Asserted explicitly so adding a role to the matrix
        without filling in its targets fails here, where the fix is
        obvious, rather than showing up as a pillar that looks short.

        malware-analyst is on this list because the matrix gives it
        targets on two of the five Forensics & Malware skills and nothing
        on the rest, so its mean never clears the floor. That is a gap in
        the targets, not in the rule -- a malware analyst plainly does own
        malware work -- and it means coverage understates what seating one
        buys until somebody fills the row in.
        """
        assert sm.roles_without_a_pillar() == (
            "l1-analyst", "l2-analyst", "malware-analyst")


class TestCertificates:
    def test_every_catalogue_certificate_is_mapped(self):
        """A certificate the map has never heard of silently contributes
        nothing, and the SOC cannot tell that from one that genuinely
        covers no pillar."""
        unknown = []
        for role in SOC_ROLE_CATALOGUE:
            for cert in role.get("typical_certifications", []):
                if sm.pillars_for_cert(cert) is None:
                    unknown.append(cert)
        assert sorted(set(unknown)) == [], sorted(set(unknown))

    def test_the_issuing_body_is_ignored(self):
        """People record the same certificate three different ways."""
        for spelling in ("GCIH", "GIAC GCIH", "SANS GCIH", "  giac gcih  "):
            assert sm.pillars_for_cert(spelling) == ("Incident Response",), \
                spelling

    def test_the_or_equivalent_suffix_still_matches(self):
        """This is the real path, not a hypothetical. Adopting a
        catalogue role writes its certificates as requirements phrased
        "GIAC GCIA (or equivalent)", and verifying one writes a
        TeamCertification under that exact name. An exact-match lookup
        would recognise none of them, so every certificate earned through
        onboarding would contribute nothing to coverage."""
        assert sm.pillars_for_cert("GIAC GCIA (or equivalent)") == \
            ("SIEM & Log Analysis", "Network Defense")

    def test_unknown_and_not_pillar_specific_are_different_answers(self):
        """One means "go and map this", the other means "mapped, and the
        answer is no pillar". Collapsing them to zero hides the first."""
        assert sm.pillars_for_cert("Advanced Basket Weaving") is None
        assert sm.pillars_for_cert("CompTIA Security+") == ()

    def test_every_mapped_pillar_is_a_real_pillar(self):
        for cert, pillars in sm.CERT_PILLARS.items():
            for pillar in pillars:
                assert pillar in sm.PILLARS, (cert, pillar)


class TestTheCatalogueBridge:
    def test_every_catalogue_role_has_an_entry(self):
        """Without this a role added to the catalogue maps to nothing and
        its people stop counting towards any pillar, with no error."""
        missing = [r["id"] for r in SOC_ROLE_CATALOGUE
                   if r["id"] not in sm.CATALOGUE_TO_SKILLS_ROLE]
        assert missing == [], missing

    def test_every_mapped_role_exists_in_the_matrix(self):
        known = set(sm.role_ids())
        for cat_id, role_id in sm.CATALOGUE_TO_SKILLS_ROLE.items():
            if role_id is not None:
                assert role_id in known, (cat_id, role_id)

    def test_the_unmapped_roles_are_declared(self):
        """Three catalogue roles have no matrix equivalent. Borrowing a
        neighbouring role's targets would be worse -- a vulnerability
        analyst is not a penetration tester -- so they map to None and
        that is asserted rather than left to be discovered."""
        assert sm.unmapped_catalogue_roles() == [
            "insider_threat_analyst", "ot_security_analyst", "vuln_analyst"]
