"""The "Similar Closed Cases" panel as a fragment.

Every test drives the route through TestClient with the API handler the
route calls monkeypatched, because the real one is pgvector and cannot be
made to fail on demand from SQLite. The template is never rendered with a
hand-built context: on this project every first-pass mutation survivor was
a template tested directly while the module that built its context went
undriven.

Measured on cases.html before the change, by reading loadSimilarCases:

  * `const items = data.similar || []`. The function already separated a
    failed request (`!resp.ok` -> "Similarity unavailable") from an empty
    answer, so two of the three outcomes were distinct. The third was not:
    a 200 whose body was not the expected shape, or was not a dict at all,
    fell to `|| []` and rendered "No similar closed cases yet", which reads
    as "we looked and there are none".
  * `Math.round((s.similarity || 0) * 100) + '%'`. A row that arrived
    without a similarity printed a confident "0%", the one value that
    means the opposite of unknown.
  * `data-args='[' + s.case_id + ']'` interpolated straight into the
    attribute. event-delegation.js parses that with JSON.parse and on a
    throw logs and returns, so a non-numeric id gives a card that looks
    live and does nothing.
  * `href="javascript:openCaseDetail(...)"`, which this CSP blocks. It
    worked only because the click bubbled to the parent card's
    data-click-action.
  * A closureColors map held rgba() and var() literals, and the similarity
    badge carried `bg-[rgba(109,228,255,.12)] text-[#6de4ff]`, so the
    palette lived in the page's JavaScript.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.cases import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/cases_similar.html"
SHEET = ROOT / "src/ion/web/static/css/cases-page.css"

URL = "/ui/cases/7/similar"


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
    """Make the API handler the route calls return, or raise, on demand."""

    def set(payload=None, raises=None):
        def handler(case_id, limit=5, min_similarity=0.5,
                    current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.case_lifecycle_api.get_similar_cases", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _row(case_id=11, **over):
    row = {
        "case_id": case_id,
        "case_number": f"CASE-{case_id}",
        "title": "beaconing to a known c2",
        "severity": "high",
        "closure_reason": "true_positive",
        "closed_at": "2026-09-01T10:00:00",
        "similarity": 0.874,
    }
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_own_permission(answers):
    answers(payload={"similar": [], "count": 0})
    assert _get().status_code == 403
    assert _get(PERMISSION).status_code == 200


def test_the_panel_is_not_gated_on_a_licence_module(answers):
    """The API it reads carries case:read and no module gate, and so does
    the page route. A fragment that added one would 404 a panel that works
    on every deployment today."""
    answers(payload={"similar": [], "count": 0})
    assert _get(PERMISSION).status_code == 200


# ---------------------------------------------------------------------------
# Three outcomes
# ---------------------------------------------------------------------------


def test_a_read_that_raised_says_unavailable_not_empty(answers):
    answers(raises=RuntimeError("pgvector is not there"))
    body = flat(_get(PERMISSION).text)
    assert "Similarity unavailable" in body
    assert "No similar closed cases" not in body


def test_an_http_error_from_the_handler_says_unavailable(answers):
    answers(raises=HTTPException(status_code=503, detail="no embeddings"))
    body = flat(_get(PERMISSION).text)
    assert "Similarity unavailable" in body
    assert "No similar closed cases" not in body


@pytest.mark.parametrize("payload", [
    {},                            # the key is gone
    {"similar": None},             # the key is there and is not a list
    {"similar": "three"},          # a string is iterable, which is the trap
    [],                            # the body is not a dict at all
    None,                          # the handler answered nothing
])
def test_a_payload_that_is_not_that_shape_is_unreadable_not_empty(
        answers, payload):
    """The defect this fragment exists to fix. `data.similar || []` rendered
    every one of these as "No similar closed cases yet"."""
    answers(payload=payload)
    body = flat(_get(PERMISSION).text)
    assert "Similarity unavailable" in body, payload
    assert "No similar closed cases" not in body, payload


def test_an_empty_answer_says_so_and_carries_the_servers_reason(answers):
    answers(payload={"similar": [], "reason": "query case not embedded yet"})
    body = flat(_get(PERMISSION).text)
    assert "No similar closed cases yet" in body
    assert "query case not embedded yet" in body
    assert "Similarity unavailable" not in body


def test_an_empty_answer_with_no_reason_shows_no_empty_brackets(answers):
    answers(payload={"similar": [], "count": 0})
    html = _get(PERMISSION).text
    assert "No similar closed cases yet" in flat(html)
    assert "()" not in flat(html)


def test_rows_render_the_case_its_score_and_the_verdict(answers):
    answers(payload={"similar": [_row()], "count": 1})
    body = flat(_get(PERMISSION).text)
    assert "CASE-11" in body
    assert "87%" in body
    assert "True Positive" in body, (
        "the words _shared.closure_label already uses everywhere else, "
        "rather than the raw enum with its underscores swapped for spaces")
    assert "beaconing to a known c2" in body


def test_a_case_with_no_number_falls_back_to_its_id(answers):
    answers(payload={"similar": [_row(case_number=None)], "count": 1})
    assert "#11" in flat(_get(PERMISSION).text)


# ---------------------------------------------------------------------------
# A missing score is unknown, not zero
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "high", {}])
def test_a_row_with_no_readable_similarity_does_not_claim_zero(
        answers, value):
    answers(payload={"similar": [_row(similarity=value)], "count": 1})
    body = flat(_get(PERMISSION).text)
    assert "CASE-11" in body, "the row still renders"
    assert "0%" not in body
    assert "unknown" in body.lower()


def test_a_genuine_zero_similarity_still_reads_as_zero(answers):
    """`|| 0` could not tell a missing score from a real one. Guarding with
    `is not none` has to keep the real one."""
    answers(payload={"similar": [_row(similarity=0.0)], "count": 1})
    body = flat(_get(PERMISSION).text)
    assert "0%" in body
    assert "unknown" not in body.lower()


# ---------------------------------------------------------------------------
# The attribute the dispatcher parses
# ---------------------------------------------------------------------------


def test_every_data_args_on_the_panel_is_parseable_json(answers):
    answers(payload={"similar": [_row(case_id=11), _row(case_id=12)],
                     "count": 2})
    html = _get(PERMISSION).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found, "the cards carry the argument the dispatcher reads"
    for raw in found:
        assert json.loads(unescape(raw)) is not None


def test_a_case_id_that_is_not_a_number_does_not_produce_broken_json(
        answers):
    """`'[' + s.case_id + ']'` with a string id gave `[CASE-9]`, which
    JSON.parse throws on, and the dispatcher logs and returns."""
    answers(payload={"similar": [_row(case_id="CASE-9")], "count": 1})
    resp = _get(PERMISSION)
    assert resp.status_code == 200
    found = re.findall(r"data-args='([^']*)'", resp.text)
    assert found, "the card renders and carries the attribute"
    for raw in found:
        json.loads(unescape(raw))


# ---------------------------------------------------------------------------
# CSP, and where the colours live
# ---------------------------------------------------------------------------


def test_the_panel_has_no_javascript_url(answers):
    answers(payload={"similar": [_row()], "count": 1})
    html = _get(PERMISSION).text
    assert "CASE-11" in html, "the card rendered, so the absence is about it"
    assert "javascript:" not in html


def test_the_panel_has_no_inline_style_attribute(answers):
    answers(payload={"similar": [_row()], "count": 1})
    html = _get(PERMISSION).text
    assert "CASE-11" in html, "the card rendered, so the absence is about it"
    assert not re.search(r'\sstyle="', html)


def test_the_panel_ships_no_colour_of_its_own(answers):
    """The closureColors map and the cyan similarity badge put ION's
    palette in the page. A theme cannot reach a colour the server emits."""
    answers(payload={"similar": [_row()], "count": 1})
    html = _get(PERMISSION).text
    assert "case-closure-true_positive" in html, (
        "the verdict badge rendered, so the absence is about it")
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "rgba(" not in html
    assert "var(--" not in html


@pytest.mark.parametrize("reason,expected", [
    ("true_positive", "case-closure-true_positive"),
    ("false_positive", "case-closure-false_positive"),
    ("benign_true_positive", "case-closure-benign_true_positive"),
    ("duplicate", "case-closure-duplicate"),
    ("insufficient_data", "case-closure-insufficient_data"),
    ("not_applicable", "case-closure-not_applicable"),
    ("something_new", "case-closure-other"),
    (None, "case-closure-other"),
])
def test_the_verdict_badge_names_its_reason_for_the_stylesheet(
        answers, reason, expected):
    answers(payload={"similar": [_row(closure_reason=reason)], "count": 1})
    assert expected in _get(PERMISSION).text


def test_the_stylesheet_paints_every_closure_class_the_panel_can_emit():
    """A class the fragment emits and the sheet does not know renders as an
    unstyled chip, which no route test can see."""
    sheet = SHEET.read_text(encoding="utf-8")
    for reason in ["true_positive", "false_positive", "benign_true_positive",
                   "duplicate", "insufficient_data", "not_applicable",
                   "other"]:
        assert f".case-closure-{reason}" in sheet, reason


def test_the_similarity_badge_is_themeable():
    """It was `text-[#6de4ff]`, the brand cyan, hard-coded into the page."""
    sheet = SHEET.read_text(encoding="utf-8")
    assert ".case-sim-badge" in sheet


def test_nothing_later_in_the_cascade_paints_the_badge_itself():
    """The chips are a single class, and so is `.cpanel-alert-badge`. If
    that rule ever sets a background or a colour, every verdict chip
    silently goes one colour and no route test can see it.

    This used to read the page, and said the fix was for the in-body
    `<style>` block to "finish moving to the sheet". The block has moved,
    and that did not resolve this: it was appended, so
    `.cpanel-alert-badge` now sits at the end of cases-page.css, far
    after the `.case-closure-*` rules near the top. At equal specificity
    the later rule still wins. The hazard is the same one, relocated from
    "an in-body block beats head_css" to "later in one sheet beats
    earlier", so the guard is unchanged and only its address is.

    The rule sets geometry and type only today. This fails if that
    changes, which is the point at which the chips need
    `.cpanel-alert-badge.case-closure-x`, or the two groups need to swap
    order in the sheet.
    """
    sheet = SHEET.read_text(encoding="utf-8")
    block = re.search(r"\.cpanel-alert-badge\s*\{([^}]*)\}", sheet)
    assert block, "the rule the chips sit on top of"
    declarations = block.group(1)
    assert "background" not in declarations
    assert not re.search(r"(^|[;\s])color\s*:", declarations)


def test_the_badge_rule_is_still_the_later_one_so_the_guard_above_is_needed():
    """If the order ever reverses, the guard above becomes unnecessary and
    should be deleted rather than left looking load-bearing. Asserting the
    order is what makes the difference visible."""
    sheet = SHEET.read_text(encoding="utf-8")
    badge = re.search(r"\.cpanel-alert-badge\s*\{", sheet)
    closure = re.search(r"\.case-closure-\w+", sheet)
    assert badge and closure
    assert badge.start() > closure.start(), (
        "the closure chips now come after .cpanel-alert-badge, so that rule "
        "no longer overrides them and the guard above is moot")


# ---------------------------------------------------------------------------
# One object, rendered either way
# ---------------------------------------------------------------------------


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(payload={"similar": [_row()], "count": 1})
    body = _get(PERMISSION, accept="application/json").json()
    assert body["cases"][0]["label"] == "CASE-11"
    assert body["cases"][0]["similarity_pct"] == 87
    assert body["cases"][0]["closure_key"] == "true_positive"


def test_htmx_still_gets_html(answers):
    """htmx sends `text/html, */*; q=0.01`, so the negotiation has to be
    strict about html being named."""
    answers(payload={"similar": [_row()], "count": 1})
    resp = _get(PERMISSION, accept="text/html, */*; q=0.01")
    assert resp.text.lstrip().startswith("<")


def test_an_unreadable_read_is_visible_in_the_json_too(answers):
    answers(payload={"similar": "three"})
    body = _get(PERMISSION, accept="application/json").json()
    assert body["cases"] is None


# ---------------------------------------------------------------------------
# The page no longer builds this panel itself
# ---------------------------------------------------------------------------


def test_the_page_no_longer_writes_the_similar_cases_panel():
    page = (ROOT / "src/ion/web/templates/cases.html").read_text(
        encoding="utf-8")
    body = re.sub(r"\{#.*?#\}", "", page, flags=re.S)
    block = re.search(r"\bfunction loadSimilarCases\(.*?\n\}", body, re.S)
    assert block, "the loader is still there to drive the panel"
    # htmx's own swap option is spelled innerHTML, so the claim is about an
    # assignment, which is what tools/ui_redesign_status.py counts.
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "/ui/cases/" in block.group(0)
    # The colour map and the javascript: href went with the markup.
    assert "rgba(" not in block.group(0)
    assert "javascript:" not in block.group(0)
