"""Certificates suggested for the role somebody holds and the one next.

Three vocabularies meet to answer this and none was written for it.
UserCareerGoal stores matrix role ids ("l2-analyst"), the certificates
are listed on catalogue posts ("l2_soc_analyst"), and
skills_matrix.CATALOGUE_TO_SKILLS_ROLE bridges them -- in the direction
catalogue -> matrix, so it has to be inverted here.

The inversion is many to one, which is the part worth testing rather than
assuming: five catalogue posts map to l3-analyst, so a suggestion built
from the first post found would silently drop four lists.
"""
from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.data import skills_matrix  # noqa: E402
from ion.data.skills_matrix import CATALOGUE_TO_SKILLS_ROLE  # noqa: E402
from ion.services.role_skills_service import (  # noqa: E402
    _recorded_as,
    certifications_for_role,
)


class TestTheInverseBridge:
    def test_it_round_trips_every_mapped_catalogue_role(self):
        """Each mapped post appears under the matrix role it maps to.

        Asserted over the whole table rather than a sample, because the
        failure this guards is a post quietly contributing nothing.
        """
        for catalogue_id, matrix_id in CATALOGUE_TO_SKILLS_ROLE.items():
            if matrix_id is None:
                continue
            assert catalogue_id in skills_matrix.catalogue_roles_for(matrix_id)

    def test_it_is_many_to_one(self):
        """l3-analyst is held by five catalogue posts. A caller taking the
        first would lose the other four certificate lists."""
        assert len(skills_matrix.catalogue_roles_for("l3-analyst")) > 1

    def test_an_unmapped_role_gets_an_empty_tuple(self):
        assert skills_matrix.catalogue_roles_for("no-such-role") == ()
        assert skills_matrix.catalogue_roles_for("") == ()

    def test_roles_mapped_to_none_are_not_reachable(self):
        """`None` means the matrix cannot speak about that post. It must
        not become a bucket that posts fall into."""
        assert skills_matrix.catalogue_roles_for(None) == ()


class TestTheSuggestions:
    def test_a_known_role_suggests_certificates(self):
        certs = certifications_for_role("l1-analyst")
        assert certs, "l1-analyst should have suggestions"
        assert all(c["name"] for c in certs)

    def test_they_are_deduplicated_across_posts(self):
        """Several posts behind one role list the same certificate. It
        should appear once, not once per post."""
        certs = certifications_for_role("l3-analyst")
        names = [c["name"].upper() for c in certs]
        assert len(names) == len(set(names))

    def test_the_most_widely_listed_comes_first(self):
        """How many of the role's posts ask for a certificate is the only
        ranking signal available, and it is a real one."""
        certs = certifications_for_role("l3-analyst")
        counts = [len(c["listed_by"]) for c in certs]
        assert counts == sorted(counts, reverse=True)

    def test_each_records_which_posts_listed_it(self):
        for cert in certifications_for_role("l3-analyst"):
            assert cert["listed_by"], f"{cert['name']} lists no source post"

    def test_pillars_keep_their_three_way_answer(self):
        """A tuple of pillars, () for a real certificate that is not
        pillar-specific, and None for one nothing has mapped. Collapsing
        the last two would hide every certificate ION has not been
        taught, which is what skills_matrix.pillars_for_cert refuses to
        do and this must not undo."""
        seen_empty = False
        for role in ("l1-analyst", "l2-analyst", "l3-analyst",
                     "detection-engineer"):
            for cert in certifications_for_role(role):
                pillars = cert["pillars"]
                assert pillars is None or isinstance(pillars, tuple)
                if pillars == ():
                    seen_empty = True
        assert seen_empty, (
            "no certificate came back as mapped-but-not-pillar-specific; "
            "Security+ is one, so the distinction has been flattened"
        )

    def test_an_unmapped_role_suggests_nothing(self):
        assert certifications_for_role("no-such-role") == []


class TestMatchingWhatSomebodyAlreadyHolds:
    """The same certificate is recorded as GCIA, GIAC GCIA and SANS GCIA."""

    def test_it_matches_a_longer_recorded_name(self):
        assert _recorded_as({"GIAC GCIA": "active"}, "GCIA") == "active"

    def test_it_matches_a_shorter_recorded_name(self):
        assert _recorded_as({"GCIA": "active"}, "GIAC GCIA") == "active"

    def test_it_carries_the_status_through(self):
        """Held and lapsed are different answers: somebody whose GCIA
        expired is not where somebody who never sat it is."""
        assert _recorded_as({"GIAC GCIA": "expired"}, "GCIA") == "expired"

    def test_an_unheld_certificate_is_none(self):
        assert _recorded_as({"GIAC GCIA": "active"}, "OSCP") is None

    def test_an_empty_name_matches_nothing(self):
        """Otherwise a blank would substring-match every record."""
        assert _recorded_as({"GIAC GCIA": "active"}, "") is None
