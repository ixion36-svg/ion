"""Triage priority is held to the severities the alert queue renders.

Defect: the triage routes stored any string as `priority`. A lab-fixture
alert's severity is read straight from that column, so one analyst could put
text of their choosing in front of every other analyst as an alert's severity.
The page now escapes it on the way out; this is the same door closed on the
way in.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from ion.web.api import TRIAGE_PRIORITIES, BulkTriageUpdate, TriageUpdate


def _single(priority):
    return TriageUpdate(priority=priority)


def _bulk(priority):
    return BulkTriageUpdate(alert_ids=["a-1"], priority=priority)


BUILDERS = pytest.mark.parametrize("build", [_single, _bulk], ids=["single", "bulk"])


@BUILDERS
@pytest.mark.parametrize("value", TRIAGE_PRIORITIES)
def test_every_severity_the_queue_offers_is_accepted(build, value):
    assert build(value).priority == value


@BUILDERS
def test_case_and_padding_are_normalised(build):
    assert build("  HIGH ").priority == "high"


@BUILDERS
@pytest.mark.parametrize("value", [None, "", "   "])
def test_an_unset_priority_stays_unset(build, value):
    """The routes skip the column when priority is None, so a blank control
    must not arrive as a value to store."""
    assert build(value).priority is None


@BUILDERS
@pytest.mark.parametrize(
    "value",
    ["<img src=x>", 'x" data-click-action="logout', "urgent", "p1", "high low"],
)
def test_anything_else_is_refused(build, value):
    with pytest.raises(ValidationError):
        build(value)
