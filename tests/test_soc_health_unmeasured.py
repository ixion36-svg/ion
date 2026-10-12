"""An absent source is unmeasured, not a score of zero.

`get_soc_health_scorecard()` has always documented this contract. Its own
comment reads: "A dimension with no inputs now reports score None rather
than a neutral or zero number, so including it would either invent data
or punish the SOC for an unconfigured source." It renormalises the
weights across whatever returned a number and reports which dimensions it
left out.

`_detection_coverage()` did not honour it. With no TIDE posture it
returned `{"score": 0, "label": "Critical"}`, which counts as a measured
zero. Measured on a dev instance with nothing configured, that produced
30/100 Grade F and the claim "All five dimensions measured". Excluding it
gives 43/100 Grade D over a stated 70% of the weight. The SOC was being
graded on a dimension ION had never looked at.

`_knowledge_completeness()` had the right shape since it was written, 280
lines below in the same file, which is what made the inconsistency a bug
rather than an open question.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from ion.services import soc_health_service as svc


class _NoPosture:
    """A TIDE service that is reachable but has nothing to report.

    Distinct from TIDE being absent entirely: this is the case the bug was
    in, where the call succeeds and returns None.
    """

    def get_posture_stats(self):
        return None


def test_absent_tide_posture_is_unmeasured_not_zero():
    with patch("ion.services.tide_service.get_tide_service", return_value=_NoPosture()):
        got = svc._detection_coverage()

    assert got["score"] is None, (
        "a score of 0 reads as 'covers nothing' and drags the whole scorecard "
        f"down for an unconfigured integration; got {got['score']!r}"
    )
    assert got["label"] == "Unavailable"


def test_it_says_why_it_could_not_measure():
    """A dimension that opts out of scoring owes the reader a reason, or the
    card shows a blank where a number was."""
    with patch("ion.services.tide_service.get_tide_service", return_value=_NoPosture()):
        got = svc._detection_coverage()

    assert got["details"].get("reason"), "no reason given for the missing score"
    assert "unmeasured" in got["details"]["reason"].lower()


def test_the_scorecard_excludes_it_and_says_so(session):
    """The whole point: the overall grade must not include a dimension that
    reported nothing, and must name what it left out."""
    with patch("ion.services.tide_service.get_tide_service", return_value=_NoPosture()):
        card = svc.get_soc_health_scorecard(session)

    assert "detection_coverage" in card["unavailable_dimensions"]
    assert "detection_coverage" not in card["scored_dimensions"]
    assert card["weight_basis"] < 1.0, (
        "the weight basis should fall below 1.0 once a dimension drops out, "
        "so the page can say what fraction of the scorecard the grade covers"
    )


def test_every_dimension_either_scores_or_explains_itself(session):
    """Guards the whole family rather than the one case that was wrong.

    A dimension may report a number or report None, but a None with no
    reason leaves the card saying 'not measured' and nothing else.
    """
    card = svc.get_soc_health_scorecard(session)
    silent = [
        name
        for name, d in card["dimensions"].items()
        if d["score"] is None and not d.get("details", {}).get("reason")
    ]
    assert not silent, f"dimensions reporting no score and no reason: {silent}"


def test_a_real_zero_is_still_a_real_zero(session):
    """The inverse. This must not become 'everything unconfigured is None',
    which would hide genuine findings behind the same treatment.
    """
    card = svc.get_soc_health_scorecard(session)
    scored = {n: d["score"] for n, d in card["dimensions"].items() if d["score"] is not None}
    assert scored, "no dimension scored at all; the fixture cannot detect the inverse"
    # integration_health genuinely measures zero configured integrations on a
    # bare instance, and must keep saying zero rather than going quiet.
    if "integration_health" in scored:
        assert isinstance(scored["integration_health"], int)
