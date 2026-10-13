"""The Attack Story Timeline panel as a fragment.

Every test drives the route through TestClient with the API handler the
route calls monkeypatched. The template is never rendered with a hand-built
context: on this project every first-pass mutation survivor was a template
tested directly while the module that built its context went undriven.

Measured on cases.html before the change, by reading loadCaseTimeline:

  * `const events = data.events || []`. The function already told a failed
    request ("Timeline unavailable") from an empty one ("No events yet"),
    so two outcomes were distinct. A 200 whose body was not that shape fell
    to `|| []` and read as "No events yet", which says we looked.
  * `const counts = data.counts || {}` and then `counts.total || 0` four
    times. A payload that stopped carrying counts printed four confident
    zeros, and `counts.bob || 0` could not tell a real zero from a missing
    key.
  * `new Date(e.ts).toLocaleString()`. `ts` is `isoformat()` of a naive UTC
    column, and JavaScript reads a zoneless string as the viewer's local
    time, so every timestamp on the timeline was wrong by the viewer's
    offset. This is the same defect `_shared.parse_instant` was written for
    after it was found in ageLabel.
  * `kindMeta[e.kind] || kindMeta.system`. An event of an unrecognised kind
    was labelled SYSTEM, which is a claim about where it came from.
  * `verdictColors[verdict] || verdictColors.inconclusive`. A verdict the
    map did not know was painted as "inconclusive", which is a verdict
    rather than an absence of one. The server derives the verdict by
    splitting a title on an arrow, so it is an arbitrary string.
  * `(c.value || '').toString()`. A citation whose value is 0 or false
    rendered as empty, and those are findings.
  * Two colour maps of rgba() and hex literals, plus `#6de4ff` and
    `rgba(109,228,255,...)` written into the markup in six places. The
    accent could not be rethemed because the page owned it.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.cases import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
SHEET = ROOT / "src/ion/web/static/css/cases-page.css"
PAGE = ROOT / "src/ion/web/templates/cases.html"

URL = "/ui/cases/7/timeline"


class _User:
    id = 1
    username = "cases-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(*permissions, accept=None):
    headers = {"accept": accept} if accept else None
    with TestClient(_app(_User(*permissions))) as client:
        return client.get(URL, headers=headers)


@pytest.fixture
def answers(monkeypatch):
    def set(payload=None, raises=None):
        def handler(case_id, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.case_lifecycle_api.get_case_timeline", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _event(**over):
    row = {
        "ts": "2026-09-01T10:30:00",
        "kind": "bob",
        "phase": None,
        "title": "Investigation complete",
        "detail": "beaconing confirmed",
        "source_type": "investigation",
        "source_id": 4,
        "citations": [],
    }
    row.update(over)
    return row


def _counts(**over):
    c = {"total": 1, "system": 0, "analyst": 0, "bob": 1}
    c.update(over)
    return c


def _payload(events=None, narrative=None, counts="default"):
    return {
        "case_id": 7,
        "events": [_event()] if events is None else events,
        "narrative": narrative,
        "counts": _counts() if counts == "default" else counts,
    }


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_own_permission(answers):
    answers(payload=_payload(events=[]))
    assert _get().status_code == 403
    assert _get(PERMISSION).status_code == 200


# ---------------------------------------------------------------------------
# Three outcomes
# ---------------------------------------------------------------------------


def test_a_read_that_raised_says_unavailable_not_empty(answers):
    answers(raises=RuntimeError("the union query fell over"))
    body = flat(_get(PERMISSION).text)
    assert "Timeline unavailable" in body
    assert "No events yet" not in body


def test_a_missing_case_says_unavailable(answers):
    """The endpoint raises 404 for a case that is not there."""
    answers(raises=HTTPException(status_code=404, detail="Case not found"))
    body = flat(_get(PERMISSION).text)
    assert "Timeline unavailable" in body
    assert "No events yet" not in body


@pytest.mark.parametrize("payload", [
    {},
    {"events": None},
    {"events": "two"},
    [],
    None,
])
def test_a_payload_that_is_not_that_shape_is_unreadable_not_empty(
        answers, payload):
    answers(payload=payload)
    body = flat(_get(PERMISSION).text)
    assert "Timeline unavailable" in body, payload
    assert "No events yet" not in body, payload


def test_an_empty_timeline_says_so(answers):
    answers(payload=_payload(events=[], counts=_counts(total=0, bob=0)))
    body = flat(_get(PERMISSION).text)
    assert "No events yet" in body
    assert "Timeline unavailable" not in body


def test_events_render_their_title_detail_and_lane(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    body = flat(html)
    assert "Investigation complete" in body
    assert "beaconing confirmed" in body
    assert "BOB" in body
    assert "case-tl-bob" in html


# ---------------------------------------------------------------------------
# The timestamp, which was wrong by the viewer's offset
# ---------------------------------------------------------------------------


def test_a_zoneless_timestamp_is_read_as_utc_and_says_so(answers):
    """`new Date('2026-09-01T10:30:00')` is 10:30 in the viewer's zone, and
    the column stores UTC. The reader is told which zone they are seeing."""
    answers(payload=_payload(events=[_event(ts="2026-09-01T10:30:00")]))
    body = flat(_get(PERMISSION).text)
    assert "2026-09-01 10:30 UTC" in body


def test_a_timestamp_that_already_carries_a_zone_is_converted_not_relabelled(
        answers):
    answers(payload=_payload(events=[_event(ts="2026-09-01T12:30:00+02:00")]))
    body = flat(_get(PERMISSION).text)
    assert "2026-09-01 10:30 UTC" in body


@pytest.mark.parametrize("value", [None, "", "not a date", 17])
def test_an_unreadable_timestamp_does_not_invent_one(answers, value):
    answers(payload=_payload(events=[_event(ts=value)]))
    body = flat(_get(PERMISSION).text)
    assert "Investigation complete" in body, "the event still renders"
    assert "UTC" not in body
    assert "1970" not in body


# ---------------------------------------------------------------------------
# Counts: missing is unknown, not zero
# ---------------------------------------------------------------------------


def test_the_counts_strip_reads_the_servers_figures(answers):
    answers(payload=_payload(counts=_counts(total=9, bob=3, analyst=4,
                                            system=2)))
    body = flat(_get(PERMISSION).text)
    for n in ("9", "3", "4", "2"):
        assert n in body


def test_a_genuine_zero_count_still_reads_as_zero(answers):
    answers(payload=_payload(counts=_counts(total=1, bob=1, analyst=0,
                                            system=0)))
    body = flat(_get(PERMISSION).text)
    assert "0 analyst" in body
    assert "unknown analyst" not in body


@pytest.mark.parametrize("counts", [None, {}, "nine", {"total": "lots"}])
def test_counts_that_cannot_be_read_do_not_print_zero(answers, counts):
    """`counts.total || 0` printed four confident zeros for a payload that
    had stopped carrying them."""
    answers(payload=_payload(counts=counts))
    body = flat(_get(PERMISSION).text)
    assert "0 events" not in body, counts
    assert "unknown" in body.lower(), counts


# ---------------------------------------------------------------------------
# A kind the map does not know is not SYSTEM
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind,label,cls", [
    ("bob", "BOB", "case-tl-bob"),
    ("analyst", "ANALYST", "case-tl-analyst"),
    ("system", "SYSTEM", "case-tl-system"),
])
def test_each_known_kind_keeps_its_lane(answers, kind, label, cls):
    answers(payload=_payload(events=[_event(kind=kind)]))
    html = _get(PERMISSION).text
    assert cls in html
    assert label in flat(html)


@pytest.mark.parametrize("kind", ["enrichment", None, "", 3])
def test_an_unrecognised_kind_is_not_labelled_system(answers, kind):
    answers(payload=_payload(events=[_event(kind=kind)]))
    html = _get(PERMISSION).text
    assert "Investigation complete" in flat(html), "the event still renders"
    assert "SYSTEM" not in flat(html)
    assert "case-tl-unknown" in html


# ---------------------------------------------------------------------------
# Bob's narrative
# ---------------------------------------------------------------------------


def test_the_narrative_renders_its_summary(answers):
    answers(payload=_payload(narrative={
        "summary": "credential access then lateral movement",
        "verdict": "true_positive", "citations": [], "ts": None}))
    body = flat(_get(PERMISSION).text)
    assert "credential access then lateral movement" in body
    assert "true positive" in body.lower()


def test_no_narrative_renders_no_narrative_block(answers):
    answers(payload=_payload(narrative=None))
    html = _get(PERMISSION).text
    assert "case-tl-bob" in html, (
        "the events rendered, so the missing narrative is the claim")
    assert "case-tl-verdict" not in html


@pytest.mark.parametrize("verdict,expected", [
    ("true_positive", "case-tl-verdict-true_positive"),
    ("false_positive", "case-tl-verdict-false_positive"),
    ("benign_true_positive", "case-tl-verdict-benign_true_positive"),
    ("inconclusive", "case-tl-verdict-inconclusive"),
])
def test_a_known_verdict_names_itself_for_the_stylesheet(
        answers, verdict, expected):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": verdict, "citations": []}))
    assert expected in _get(PERMISSION).text


@pytest.mark.parametrize("verdict", ["escalated", "something new", 4])
def test_an_unrecognised_verdict_is_not_painted_as_inconclusive(
        answers, verdict):
    """The server derives the verdict by splitting a title on an arrow, so
    it is an arbitrary string. Calling it inconclusive is a verdict."""
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": verdict, "citations": []}))
    html = _get(PERMISSION).text
    assert "case-tl-verdict-inconclusive" not in html
    assert "case-tl-verdict-unknown" in html


def test_a_narrative_with_no_verdict_shows_no_verdict_badge(answers):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": None, "citations": []}))
    html = _get(PERMISSION).text
    assert "s" in flat(html)
    assert "case-tl-verdict-" not in html


def test_citations_render_their_field_value_and_significance(answers):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": "true_positive", "citations": [
            {"field": "process.name", "value": "rundll32.exe",
             "significance": "unsigned parent"}]}))
    body = flat(_get(PERMISSION).text)
    assert "process.name" in body
    assert "rundll32.exe" in body
    assert "unsigned parent" in body


@pytest.mark.parametrize("value,shown", [(0, "0"), (False, "False")])
def test_a_citation_value_that_is_falsey_still_renders(answers, value, shown):
    """`(c.value || '').toString()` dropped it, and a count of zero is a
    finding."""
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": "true_positive",
        "citations": [{"field": "signature.count", "value": value,
                       "significance": None}]}))
    body = flat(_get(PERMISSION).text)
    assert "signature.count" in body
    assert shown in body


def test_a_citation_that_is_not_a_mapping_is_skipped_not_fatal(answers):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": "true_positive",
        "citations": ["junk", {"field": "a", "value": "b",
                               "significance": None}]}))
    body = flat(_get(PERMISSION).text)
    assert "a" in body and "b" in body


def test_citations_that_are_not_a_list_do_not_break_the_narrative(answers):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": "true_positive", "citations": "lots"}))
    assert "s" in flat(_get(PERMISSION).text)


# ---------------------------------------------------------------------------
# Truncation, as the page did it
# ---------------------------------------------------------------------------


def test_a_long_detail_is_cut_and_marked(answers):
    answers(payload=_payload(events=[_event(detail="x" * 400)]))
    body = flat(_get(PERMISSION).text)
    assert "x" * 220 in body
    assert "x" * 221 not in body
    assert "…" in body


def test_a_short_detail_is_not_marked_as_cut(answers):
    answers(payload=_payload(events=[_event(detail="short")]))
    body = flat(_get(PERMISSION).text)
    assert "short" in body
    assert "…" not in body


# ---------------------------------------------------------------------------
# CSP, and where the colours live
# ---------------------------------------------------------------------------


def test_the_panel_ships_no_colour_of_its_own(answers):
    answers(payload=_payload(narrative={
        "summary": "s", "verdict": "true_positive", "citations": [
            {"field": "a", "value": "b", "significance": "c"}]}))
    html = _get(PERMISSION).text
    assert "case-tl-bob" in html, "the lane rendered, so the absence is real"
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "rgba(" not in html
    assert "var(--" not in html


def test_the_panel_has_no_inline_style_attribute(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    assert "case-tl-bob" in html, "the lane rendered, so the absence is real"
    assert not re.search(r'\sstyle="', html)


def test_the_stylesheet_paints_every_class_the_panel_can_emit():
    sheet = SHEET.read_text(encoding="utf-8")
    for kind in ("bob", "analyst", "system", "unknown"):
        assert f".case-tl-{kind}" in sheet, kind
    for verdict in ("true_positive", "false_positive",
                    "benign_true_positive", "inconclusive", "unknown"):
        assert f".case-tl-verdict-{verdict}" in sheet, verdict


# ---------------------------------------------------------------------------
# One object, rendered either way
# ---------------------------------------------------------------------------


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(payload=_payload())
    body = _get(PERMISSION, accept="application/json").json()
    assert body["events"][0]["kind_key"] == "bob"
    assert body["events"][0]["when"] == "2026-09-01 10:30 UTC"


def test_an_unreadable_read_is_visible_in_the_json_too(answers):
    answers(payload={"events": "two"})
    assert _get(PERMISSION, accept="application/json").json()["events"] is None


# ---------------------------------------------------------------------------
# The page no longer builds this panel itself
# ---------------------------------------------------------------------------


def test_the_page_no_longer_writes_the_timeline(answers):
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction loadCaseTimeline\(.*?\n\}", body, re.S)
    assert block, "the loader is still there to drive the panel"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "/ui/cases/" in block.group(0)
    # The two colour maps and the hard-coded accent went with the markup.
    assert "rgba(" not in block.group(0)
    assert "#6de4ff" not in block.group(0)
    assert "toLocaleString" not in block.group(0)
