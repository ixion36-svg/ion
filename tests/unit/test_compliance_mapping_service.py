"""Tests for compliance_mapping_service — detection coverage as a control scorecard.

This module was at 0% when the coverage ratchet first measured the tree. Its
output is shown to auditors, so the failures that cost something are the ones
that flatter: a control scored "covered" when a technique has no rule behind
it, a sub-technique credited to the wrong parent, or a TIDE outage rendered as
0% rather than "unknown". A scorecard that cannot tell "no coverage" from "no
data" is worse than no scorecard.

The five framework catalogues are hand-curated data, and the scoring reads
``c["techniques"]`` directly, so ``TestCatalogueIntegrity`` guards the data as
well as the arithmetic.
"""

from __future__ import annotations

import re

import pytest

from ion.services import compliance_mapping_service as svc

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class FakeTide:
    """Stands in for TideService: only ``enabled`` and the one method matter."""

    def __init__(self, coverage=None, *, enabled=True, raises=None):
        self.enabled = enabled
        self._coverage = coverage
        self._raises = raises
        self.calls = 0

    def get_global_mitre_coverage(self):
        self.calls += 1
        if self._raises:
            raise self._raises
        return self._coverage


def _tide(*technique_ids, counts=None):
    """A TIDE whose coverage reports one rule for each named technique."""
    counts = counts or {}
    return FakeTide({"techniques": {
        tid: {"rule_count": counts.get(tid, 1)} for tid in technique_ids
    }})


def _framework(controls, fid="test_fw"):
    return {"id": fid, "name": "Test FW", "version": "1", "url": "http://x",
            "description": "d", "controls": controls}


class TestListFrameworks:
    def test_every_registered_framework_is_listed(self):
        assert len(svc.list_frameworks()) == len(svc.FRAMEWORKS)

    def test_controls_are_omitted_from_the_listing(self):
        """The listing feeds a dropdown; shipping every control is wasteful."""
        for f in svc.list_frameworks():
            assert "controls" not in f

    def test_the_control_count_matches_the_catalogue(self):
        listed = {f["id"]: f["control_count"] for f in svc.list_frameworks()}
        for f in svc.FRAMEWORKS:
            assert listed[f["id"]] == len(f["controls"])

    def test_the_listing_carries_the_metadata_the_page_shows(self):
        f = svc.list_frameworks()[0]
        assert set(f) == {"id", "name", "version", "description", "url",
                         "control_count"}


class TestGetFramework:
    def test_a_known_id_returns_the_catalogue_with_controls(self):
        f = svc.get_framework("nist_csf")
        assert f is not None
        assert f["controls"]

    def test_an_unknown_id_is_none(self):
        assert svc.get_framework("sarbanes_oxley") is None

    def test_the_index_covers_every_registered_framework(self):
        """A framework appended to FRAMEWORKS but missing from the index would
        be listed in the UI and then 404 when clicked."""
        for f in svc.FRAMEWORKS:
            assert svc.get_framework(f["id"]) is f


class TestCoveredTechniques:
    def test_techniques_with_a_rule_are_covered(self):
        assert svc._covered_techniques(_tide("T1071", "T1078")) == {
            "T1071", "T1078"}

    def test_a_technique_with_no_rules_is_not_covered(self):
        """A mapping row with zero rules is an intention, not a detection."""
        tide = _tide("T1071", "T1078", counts={"T1078": 0})
        assert svc._covered_techniques(tide) == {"T1071"}

    def test_no_tide_service_means_no_coverage(self):
        assert svc._covered_techniques(None) == set()

    def test_a_disabled_tide_means_no_coverage(self):
        assert svc._covered_techniques(FakeTide({}, enabled=False)) == set()

    def test_a_tide_error_is_swallowed_into_no_coverage(self):
        tide = FakeTide(raises=RuntimeError("502 from TIDE"))
        assert svc._covered_techniques(tide) == set()

    def test_an_empty_coverage_payload_is_no_coverage(self):
        assert svc._covered_techniques(FakeTide(None)) == set()
        assert svc._covered_techniques(FakeTide({})) == set()

    def test_a_null_technique_entry_does_not_crash(self):
        """TIDE has shipped null bodies for techniques before now."""
        tide = FakeTide({"techniques": {"T1071": None, "T1078": {"rule_count": 2}}})
        assert svc._covered_techniques(tide) == {"T1078"}


class TestScoring:
    def test_a_control_with_every_technique_covered_is_covered(self):
        fw = _framework([{"id": "C1", "name": "n", "techniques": ["T1071", "T1078"]}])

        out = svc._score_framework(fw, {"T1071", "T1078"})

        c = out["controls"][0]
        assert c["score"] == 100
        assert c["state"] == "covered"
        assert c["gap_techniques"] == []
        assert out["summary"]["fully_covered"] == 1

    def test_a_control_with_some_techniques_covered_is_partial(self):
        fw = _framework([{"id": "C1", "name": "n",
                          "techniques": ["T1071", "T1078", "T1003", "T1110"]}])

        c = svc._score_framework(fw, {"T1071", "T1078"})["controls"][0]

        assert c["score"] == 50
        assert c["state"] == "partial"
        assert c["covered"] == 2 and c["total"] == 4
        assert c["covered_techniques"] == ["T1071", "T1078"]
        assert c["gap_techniques"] == ["T1003", "T1110"]

    def test_a_control_with_nothing_covered_is_blind(self):
        fw = _framework([{"id": "C1", "name": "n", "techniques": ["T1071"]}])

        out = svc._score_framework(fw, set())

        assert out["controls"][0]["state"] == "blind"
        assert out["controls"][0]["score"] == 0
        assert out["summary"]["no_coverage"] == 1

    def test_the_score_is_truncated_not_rounded(self):
        """2 of 3 is 66, not 67 — stated so an auditor's arithmetic matches."""
        fw = _framework([{"id": "C1", "name": "n",
                          "techniques": ["T1071", "T1078", "T1003"]}])

        assert svc._score_framework(fw, {"T1071", "T1078"})[
            "controls"][0]["score"] == 66

    def test_a_covered_parent_credits_its_sub_techniques(self):
        """A rule on T1110 detects password guessing however it is sub-typed."""
        fw = _framework([{"id": "C1", "name": "n",
                          "techniques": ["T1110.001", "T1110.003"]}])

        assert svc._score_framework(fw, {"T1110"})["controls"][0]["score"] == 100

    def test_a_covered_sub_technique_does_not_credit_a_sibling(self):
        fw = _framework([{"id": "C1", "name": "n",
                          "techniques": ["T1110.001", "T1110.003"]}])

        c = svc._score_framework(fw, {"T1110.001"})["controls"][0]

        assert c["covered_techniques"] == ["T1110.001"]
        assert c["gap_techniques"] == ["T1110.003"]

    def test_a_covered_sub_technique_does_not_credit_its_parent(self):
        """One sub-technique rule is not coverage of the whole technique."""
        fw = _framework([{"id": "C1", "name": "n", "techniques": ["T1110"]}])

        assert svc._score_framework(fw, {"T1110.001"})["controls"][0][
            "state"] == "blind"

    def test_a_control_listing_no_techniques_is_not_assessable_not_blind(self):
        """Nothing was assessed, so claiming a gap would be a fabrication.

        Review 2026-10-08 §18 renamed this state from ``unknown`` to
        ``not_assessable`` and excluded it from the mean, so the summary
        now carries its own count and the scored denominator.
        """
        fw = _framework([{"id": "C1", "name": "n", "techniques": []}])

        out = svc._score_framework(fw, {"T1071"})

        assert out["controls"][0]["state"] == "not_assessable"
        assert out["summary"] == {"fully_covered": 0, "partial": 0,
                                 "no_coverage": 0, "not_assessable": 1,
                                 "scored_controls": 0, "total_controls": 1}

    def test_a_control_with_no_techniques_key_is_tolerated(self):
        fw = _framework([{"id": "C1", "name": "n"}])
        assert svc._score_framework(fw, {"T1071"})["controls"][0][
            "state"] == "not_assessable"

    def test_the_overall_score_is_the_mean_of_the_control_scores(self):
        fw = _framework([
            {"id": "C1", "name": "n", "techniques": ["T1071"]},            # 100
            {"id": "C2", "name": "n", "techniques": ["T1003", "T1110"]},   # 0
        ])

        assert svc._score_framework(fw, {"T1071"})["overall_score"] == 50

    def test_an_unassessed_control_no_longer_drags_the_overall_score_down(self):
        """The wart the previous version of this test recorded but did not endorse.

        A ``techniques: []`` control used to score 0 inside the mean while
        reporting state 'unknown', so controls nobody had mapped silently
        depressed the framework score. Review 2026-10-08 §18: it is now
        excluded from the mean and counted separately.
        """
        fw = _framework([
            {"id": "C1", "name": "n", "techniques": ["T1071"]},
            {"id": "C2", "name": "n", "techniques": []},
        ])

        out = svc._score_framework(fw, {"T1071"})
        assert out["overall_score"] == 100
        assert out["summary"]["scored_controls"] == 1
        assert out["summary"]["not_assessable"] == 1

    def test_an_empty_framework_is_unscored_rather_than_dividing_by_zero(self):
        """Nothing to score reads as absent, not as 0% coverage.

        Same principle as test_no_tide_is_an_error_not_a_zero_score below:
        0 means "no detections found", None means "we did not measure".
        """
        out = svc._score_framework(_framework([]), {"T1071"})
        assert out["overall_score"] is None
        assert out["summary"]["scored_controls"] == 0
        assert out["summary"]["total_controls"] == 0

    def test_the_scorecard_identifies_its_framework(self):
        out = svc._score_framework(svc.NIST_CSF, set())
        assert out["framework_id"] == "nist_csf"
        assert out["framework"] == svc.NIST_CSF["name"]
        assert out["version"] == svc.NIST_CSF["version"]
        assert out["url"] == svc.NIST_CSF["url"]

    def test_a_control_description_is_passed_through_or_none(self):
        fw = _framework([
            {"id": "C1", "name": "n", "techniques": ["T1071"], "description": "d"},
            {"id": "C2", "name": "n", "techniques": ["T1071"]},
        ])

        out = svc._score_framework(fw, {"T1071"})

        assert out["controls"][0]["description"] == "d"
        assert out["controls"][1]["description"] is None


class TestPosture:
    def test_a_posture_is_computed_for_the_named_framework(self):
        out = svc.get_compliance_posture(_tide("T1071"), "cis_v8")
        assert out["framework_id"] == "cis_v8"

    def test_the_default_framework_is_nist_csf(self):
        assert svc.get_compliance_posture(_tide("T1071"))[
            "framework_id"] == "nist_csf"

    def test_an_unknown_framework_is_an_error_naming_the_id(self):
        out = svc.get_compliance_posture(_tide("T1071"), "nope")
        assert out["error"] == "Unknown framework: nope"
        # Explicitly absent rather than missing, so a caller doing
        # .get("overall_score", 0) cannot read it as zero coverage.
        assert out["overall_score"] is None

    def test_an_unknown_framework_is_rejected_before_tide_is_called(self):
        """No point making a TIDE round-trip for a framework we cannot score."""
        tide = _tide("T1071")
        svc.get_compliance_posture(tide, "nope")
        assert tide.calls == 0

    def test_no_tide_is_an_error_not_a_zero_score(self):
        """0% means 'no detections'. This means 'we do not know'."""
        out = svc.get_compliance_posture(None)
        assert out["error"] == "TIDE not configured"
        assert out["framework_id"] == "nist_csf"
        # Present and None beats absent: an absent key lets a caller's
        # .get("overall_score", 0) turn "unknown" into "0% covered".
        assert out["overall_score"] is None
        assert out["availability"] == "source_not_configured"

    def test_a_disabled_tide_is_the_same_error(self):
        out = svc.get_compliance_posture(FakeTide({}, enabled=False))
        assert out["error"] == "TIDE not configured"

    def test_tide_with_no_coverage_data_is_distinguished_from_no_tide(self):
        out = svc.get_compliance_posture(FakeTide({"techniques": {}}))
        assert out["error"] == "TIDE returned no coverage data"
        assert out["framework_id"] == "nist_csf"


class TestAllPostures:
    def test_every_framework_is_scored(self):
        out = svc.get_all_postures(_tide("T1071"))
        assert [f["framework_id"] for f in out["frameworks"]] == [
            f["id"] for f in svc.FRAMEWORKS]

    def test_tide_is_queried_once_for_all_frameworks(self):
        """Five scorecards must not be five round-trips to TIDE."""
        tide = _tide("T1071")

        svc.get_all_postures(tide)

        assert tide.calls == 1

    def test_no_tide_is_an_error_with_an_empty_list(self):
        out = svc.get_all_postures(None)
        assert out["error"] == "TIDE not configured"
        assert out["frameworks"] == []

    def test_no_coverage_data_is_an_error_with_an_empty_list(self):
        out = svc.get_all_postures(FakeTide({"techniques": {}}))
        assert out["error"] == "TIDE returned no coverage data"
        assert out["frameworks"] == []


class TestCatalogueIntegrity:
    """The frameworks are data, and the scoring reads them directly."""

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_a_framework_carries_every_field_the_api_returns(self, f):
        assert set(f) == {"id", "name", "version", "description", "url",
                          "controls"}

    def test_framework_ids_are_unique(self):
        ids = [f["id"] for f in svc.FRAMEWORKS]
        assert len(set(ids)) == len(ids)

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_control_ids_are_unique_within_a_framework(self, f):
        ids = [c["id"] for c in f["controls"]]
        assert len(set(ids)) == len(ids)

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_every_control_is_named_and_mapped(self, f):
        for c in f["controls"]:
            assert c["name"], c["id"]
            assert c.get("techniques"), f"{f['id']}/{c['id']} maps to nothing"

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_every_technique_id_is_well_formed(self, f):
        """A malformed id can never match TIDE coverage, so the control would
        read as a permanent blind spot with no way to clear it."""
        bad = [f"{c['id']}:{t}" for c in f["controls"]
               for t in c.get("techniques", []) if not TECHNIQUE_ID.match(t)]
        assert not bad, bad

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_no_control_lists_the_same_technique_twice(self, f):
        """A duplicate would be counted twice and cannot change the score, but
        it inflates the 'total' shown next to the control."""
        dupes = [c["id"] for c in f["controls"]
                 if len(set(c.get("techniques", []))) != len(c.get("techniques", []))]
        assert not dupes, dupes

    @pytest.mark.parametrize("f", svc.FRAMEWORKS, ids=lambda f: f["id"])
    def test_listing_a_parent_beside_its_sub_techniques_weights_the_control(self, f):
        """Several controls list both ``T1110`` and ``T1110.001`` — curated, not
        a mistake, and the scoring reads it as intended: a rule on the parent
        satisfies all three entries, while a rule on one sub-technique alone
        scores a third. So the pairing is a weighting device, and what must hold
        is that a sub-technique never appears without a plausible parent id."""
        orphans = [f"{c['id']}: {t}" for c in f["controls"]
                   for t in c.get("techniques", [])
                   if "." in t and not TECHNIQUE_ID.match(t.split(".")[0])]
        assert not orphans, orphans

    def test_a_fully_covered_estate_scores_every_framework_at_one_hundred(self):
        """End to end over the real catalogues: if every mapped technique had a
        rule, no framework may report less than full coverage."""
        every = {t for f in svc.FRAMEWORKS for c in f["controls"]
                 for t in c.get("techniques", [])}

        out = svc.get_all_postures(_tide(*every))

        for scorecard in out["frameworks"]:
            assert scorecard["overall_score"] == 100, scorecard["framework_id"]
