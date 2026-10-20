"""The cross-case observable sightings panel as a fragment.

Every test drives the route through TestClient with the API handler the
route calls monkeypatched. The template is never rendered with a hand-built
context.

Measured on cases.html before the change, by reading loadSimilarObservables:

  * `const shared = data.shared || []`. A failed request and an empty
    answer were already distinct; a 200 whose body was not that shape fell
    to `|| []` and read as "No observables in this case match other cases".
  * `const o = row.observable;` with no guard, then `o.tlp`. One row
    arriving without its observable threw, and the throw landed in the
    function's single catch, so the whole panel read "Cross-case lookup
    unavailable" because of one bad row among good ones.
  * `o.sighting_count || 1` printed "1x" for an observable whose count was
    missing, and could not tell that from a genuine 1.
  * `data-args='[' + s.case_id + ']'` interpolated into the attribute, and
    `href="javascript:openCaseDetail(...)"`, which this CSP blocks.
  * A tlpColors map and four hard-coded pills (`text-[#fca5a5]`,
    `text-[#cbd5e1]`, `text-[#6de4ff]`) put the palette in the page.

On the TLP fallback specifically: `tlpColors[o.tlp] || tlpColors.amber`
looks like it invents a marking, and it does not. Observable.tlp is
`nullable=False, default="amber"`, so amber is what the schema means by an
unset TLP and the fallback agrees with it. What the fallback cannot do is
tell amber from a value outside the five it knows, because the column is a
plain String(8): such a value was painted amber while its own text was
shown in the pill. That case keeps its own key here.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from page_css import page_css

from ion.web.ui.cases import PERMISSION, SIGHTINGS_SHOWN, router

ROOT = Path(__file__).resolve().parents[2]
#: Retired into the one build; this is the
#: body[data-page="cases"] block and only that block.
SHEET_TEXT = page_css("cases")
PAGE = ROOT / "src/ion/web/templates/cases.html"

URL = "/ui/cases/7/similar-observables"


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
            "ion.web.case_lifecycle_api.get_case_similar_observables", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _obs(**over):
    o = {
        "id": 3, "type": "ipv4-addr", "value": "203.0.113.9",
        "normalized_value": "203.0.113.9", "tlp": "amber", "pap": "amber",
        "is_ioc": True, "threat_level": "high", "sighting_count": 4,
        "first_seen": None, "last_seen": None,
    }
    o.update(over)
    return o


def _sighting(case_id=22, **over):
    s = {"case_id": case_id, "case_number": f"CASE-{case_id}",
         "title": "second sighting", "severity": "high",
         "status": "open", "last_seen": None}
    s.update(over)
    return s


def _row(observable=None, sightings=None):
    return {
        "observable": _obs() if observable is None else observable,
        "sightings": [_sighting()] if sightings is None else sightings,
    }


def _payload(shared=None):
    rows = [_row()] if shared is None else shared
    return {"shared": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# Gate and the three outcomes
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_own_permission(answers):
    answers(payload=_payload(shared=[]))
    assert _get().status_code == 403
    assert _get(PERMISSION).status_code == 200


def test_a_read_that_raised_says_unavailable_not_empty(answers):
    answers(raises=RuntimeError("the link walk fell over"))
    body = flat(_get(PERMISSION).text)
    assert "Cross-case lookup unavailable" in body
    assert "match other cases" not in body


def test_an_http_error_says_unavailable(answers):
    answers(raises=HTTPException(status_code=404, detail="Case not found"))
    assert "Cross-case lookup unavailable" in flat(_get(PERMISSION).text)


@pytest.mark.parametrize("payload", [
    {}, {"shared": None}, {"shared": "two"}, [], None,
])
def test_a_payload_that_is_not_that_shape_is_unreadable_not_empty(
        answers, payload):
    answers(payload=payload)
    body = flat(_get(PERMISSION).text)
    assert "Cross-case lookup unavailable" in body, payload
    assert "match other cases" not in body, payload


def test_an_empty_answer_says_so(answers):
    answers(payload=_payload(shared=[]))
    body = flat(_get(PERMISSION).text)
    assert "No observables in this case match other cases" in body
    assert "unavailable" not in body


def test_a_row_renders_its_indicator_and_its_sightings(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    body = flat(html)
    assert "203.0.113.9" in body
    assert "ipv4-addr" in body
    assert "AMBER" in body
    assert "IOC" in body
    assert "CASE-22" in body
    assert "second sighting" in body


# ---------------------------------------------------------------------------
# One bad row no longer takes the panel down
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [
    {"sightings": []},                      # no observable key at all
    {"observable": None, "sightings": []},
    {"observable": "junk", "sightings": []},
    "junk",
])
def test_a_row_without_a_readable_observable_is_skipped_not_fatal(
        answers, bad):
    """`const o = row.observable` then `o.tlp` threw into the one catch, so
    a single bad row rendered the whole panel as unavailable."""
    answers(payload=_payload(shared=[bad, _row()]))
    body = flat(_get(PERMISSION).text)
    assert "203.0.113.9" in body, (bad, "the good row still renders")
    assert "Cross-case lookup unavailable" not in body


def test_a_panel_whose_every_row_is_unreadable_says_unavailable(answers):
    """Not "no matches": we were told there were matches and could not read
    any of them."""
    answers(payload=_payload(shared=["junk", {"observable": None}]))
    body = flat(_get(PERMISSION).text)
    assert "Cross-case lookup unavailable" in body
    assert "No observables in this case match other cases" not in body


def test_a_sighting_that_is_not_a_mapping_is_skipped(answers):
    answers(payload=_payload(shared=[_row(sightings=["junk", _sighting()])]))
    assert "CASE-22" in flat(_get(PERMISSION).text)


# ---------------------------------------------------------------------------
# A missing count is unknown, not one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "many", {}])
def test_an_unreadable_sighting_count_does_not_claim_one(answers, value):
    answers(payload=_payload(shared=[_row(observable=_obs(
        sighting_count=value))]))
    body = flat(_get(PERMISSION).text)
    assert "203.0.113.9" in body, "the row still renders"
    assert "1x" not in body


def test_a_genuine_count_of_one_reads_as_one(answers):
    answers(payload=_payload(shared=[_row(observable=_obs(
        sighting_count=1))]))
    assert "1x" in flat(_get(PERMISSION).text)


def test_an_observable_with_no_value_still_names_its_type(answers):
    """`esc(o.value)` printed the word "undefined" into the cell. The cell
    is simply not drawn, which is why this asserts on the element and not
    on a word: asserting "undefined" is absent passes against a port that
    prints "None" instead, and a mutation round caught exactly that."""
    answers(payload=_payload(shared=[_row(observable=_obs(value=None))]))
    html = _get(PERMISSION).text
    assert "ipv4-addr" in flat(html)
    assert "case-obs-value" not in html
    assert "undefined" not in html
    assert ">None<" not in html


# ---------------------------------------------------------------------------
# TLP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tlp,cls", [
    ("red", "case-tlp-red"),
    ("amber", "case-tlp-amber"),
    ("green", "case-tlp-green"),
    ("clear", "case-tlp-clear"),
    ("white", "case-tlp-white"),
])
def test_each_known_tlp_names_itself_for_the_stylesheet(answers, tlp, cls):
    answers(payload=_payload(shared=[_row(observable=_obs(tlp=tlp))]))
    html = _get(PERMISSION).text
    assert cls in html
    assert tlp.upper() in flat(html)


@pytest.mark.parametrize("tlp", ["purple", "AMBER+STRICT", 4])
def test_a_tlp_outside_the_five_is_not_painted_as_amber(answers, tlp):
    """The column is a plain String(8), so a value outside the five is
    reachable. It was painted amber while its own text showed in the pill,
    which is a pill that disagrees with itself."""
    answers(payload=_payload(shared=[_row(observable=_obs(tlp=tlp))]))
    html = _get(PERMISSION).text
    assert "case-tlp-amber" not in html
    assert "case-tlp-unknown" in html


def test_a_missing_tlp_is_amber_because_that_is_what_the_column_means(
        answers):
    """Observable.tlp is nullable=False default="amber". A row that reaches
    us without one is an unset TLP, and amber is what the schema means by
    that, so this is not a fallback inventing a marking."""
    answers(payload=_payload(shared=[_row(observable=_obs(tlp=None))]))
    html = _get(PERMISSION).text
    assert "case-tlp-amber" in html
    assert "AMBER" in flat(html)


# ---------------------------------------------------------------------------
# The cap the page applied
# ---------------------------------------------------------------------------


def test_the_sightings_list_is_capped_and_says_how_many_it_hid(answers):
    many = [_sighting(case_id=100 + n) for n in range(SIGHTINGS_SHOWN + 3)]
    answers(payload=_payload(shared=[_row(sightings=many)]))
    body = flat(_get(PERMISSION).text)
    assert "3 more" in body
    assert f"CASE-{100 + SIGHTINGS_SHOWN - 1}" in body
    assert f"CASE-{100 + SIGHTINGS_SHOWN}" not in body


def test_exactly_the_cap_hides_nothing(answers):
    many = [_sighting(case_id=100 + n) for n in range(SIGHTINGS_SHOWN)]
    answers(payload=_payload(shared=[_row(sightings=many)]))
    assert "more" not in flat(_get(PERMISSION).text)


# ---------------------------------------------------------------------------
# CSP, and where the colours live
# ---------------------------------------------------------------------------


def test_every_data_args_is_parseable_json(answers):
    answers(payload=_payload(shared=[_row(sightings=[
        _sighting(case_id=22), _sighting(case_id="CASE-X")])]))
    html = _get(PERMISSION).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found, "the sighting cards carry the dispatcher's argument"
    for raw in found:
        json.loads(unescape(raw))


def test_the_panel_has_no_javascript_url(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    assert "203.0.113.9" in html, "the row rendered, so the absence is real"
    assert "javascript:" not in html


def test_the_panel_ships_no_colour_of_its_own(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    assert "case-tlp-amber" in html, "the pill rendered"
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "rgba(" not in html
    assert "var(--" not in html


def test_the_panel_has_no_inline_style_attribute(answers):
    answers(payload=_payload())
    html = _get(PERMISSION).text
    assert "case-tlp-amber" in html, "the pill rendered"
    assert not re.search(r'\sstyle="', html)


def test_the_stylesheet_paints_every_class_the_panel_can_emit():
    sheet = SHEET_TEXT
    for tlp in ("red", "amber", "green", "clear", "white", "unknown"):
        assert f".case-tlp-{tlp}" in sheet, tlp
    assert ".case-ioc-badge" in sheet
    assert ".case-sighting-status" in sheet


# ---------------------------------------------------------------------------
# One object, rendered either way
# ---------------------------------------------------------------------------


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(payload=_payload())
    body = _get(PERMISSION, accept="application/json").json()
    assert body["rows"][0]["tlp_key"] == "amber"
    assert body["rows"][0]["sighting_count"] == 4


def test_an_unreadable_read_is_visible_in_the_json_too(answers):
    answers(payload={"shared": "two"})
    assert _get(PERMISSION, accept="application/json").json()["rows"] is None


# ---------------------------------------------------------------------------
# The page no longer builds this panel itself
# ---------------------------------------------------------------------------


def test_the_page_no_longer_writes_the_panel(answers):
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction loadSimilarObservables\(.*?\n\}", body,
                      re.S)
    assert block, "the loader is still there to drive the panel"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "rgba(" not in block.group(0)
    assert "javascript:" not in block.group(0)
