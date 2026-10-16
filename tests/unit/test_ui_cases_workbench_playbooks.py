"""The case workbench kanban, the playbook browser and the closure buttons.

A FAILED PINS READ SHOWED AN EMPTY EVIDENCE WORKBENCH

    const pins = pinsResp.ok ? (await pinsResp.json()).pins || [] : [];
    ...
    renderWorkbenchKanban(caseId, pins);

Three columns, each reading "no pins". The workbench is the case's
evidence board and the ledger behind it is tamper-evident, so "nothing
has been pinned" is a claim about an investigation, and it was being made
on the strength of a read that returned 403 or 500.

The verify banner beside it is already right: `if (!verify)` renders
"verify unavailable" under `wb-verify-unknown` rather than claiming a
valid chain. That behaviour is preserved, not rewritten.

A PLAYBOOK WITH NO NAME TOOK THE BROWSER DOWN

    filtered = playbooks.filter(p =>
        p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase()...)

`p.description` is guarded and `p.name` is not, so one nameless playbook
threw inside the filter and the whole browser fell into the catch, which
then blamed the load.

A PLAYBOOK NAME WITH A DOUBLE QUOTE BROKE ITS ACTION ARGUMENTS

    data-args='[" + caseId + "," + p.id + ",\"" + esc(p.name) + "\"]'

`esc` turns `"` into `&quot;`, which is correct for an attribute and
wrong for JSON inside one: the parser decodes it back to `"` and the
array ends early. `|tojson` is the escaping that holds, and Jinja's
`tojson` escapes `"` rather than `'`, which is why these attributes are
single-quoted.

Also `p.step_count` and the pin card's figures went in raw, so a playbook
with no step count read "undefined steps", and the failure message
carried `#f44336` as a literal in a JavaScript string.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.cases import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"

WORKBENCH = "/ui/cases/7/workbench"
PLAYBOOKS = "/ui/cases/7/playbooks"


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


def _get(url, user, **params):
    with TestClient(_app(user)) as client:
        return client.get(url, params=params)


def _reader():
    """The page's permission plus the two the reads themselves need.

    GET /api/alert-cases/{id}/pins takes forensic:read and GET
    /api/playbooks takes playbook:read, where the cases page is
    case:read. The page reached them over HTTP so FastAPI applied those
    dependencies; a fragment calls the function directly and must check
    them itself, which is what test_withheld below covers.
    """
    return _User(PERMISSION, "forensic:read", "playbook:read")


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def pins(monkeypatch):
    def set(payload=None, raises=None):
        def handler(case_id, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr("ion.web.ui.cases.read_case_pins", handler,
                            raising=False)

    return set


@pytest.fixture
def library(monkeypatch):
    def set(payload=None, raises=None):
        def handler(**kwargs):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr("ion.web.ui.cases.read_playbooks", handler,
                            raising=False)

    return set


def _pin(**over):
    p = {"id": 3, "finding_status": "triage", "severity": "high",
         "source_type": "alert", "title": "Suspicious logon",
         "summary": "a summary", "pinned_by_username": "lyndon",
         "pinned_at": "2026-10-13T09:00:00"}
    p.update(over)
    return p


def _playbook(**over):
    p = {"id": 5, "name": "Phishing triage", "description": "a runbook",
         "is_active": True, "step_count": 6}
    p.update(over)
    return p


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_both_panels_need_the_pages_permission(pins, library):
    pins(payload={"pins": []})
    library(payload={"playbooks": []})
    for url in (WORKBENCH, PLAYBOOKS):
        assert _get(url, _User()).status_code == 403, url
        assert _get(url, _reader()).status_code == 200, url


def test_each_panel_withholds_what_its_own_read_requires(pins, library):
    """A fragment calling the endpoint function directly runs the body
    with none of its Depends(...) applied, so case:read alone would have
    read both. That is the bug I shipped on the pcap page."""
    pins(payload={"pins": [_pin()]})
    library(payload={"playbooks": [_playbook()]})
    page_only = _User(PERMISSION)

    body = flat(_get(WORKBENCH, page_only).text)
    assert "forensic:read" in body
    assert "Suspicious logon" not in body

    body = flat(_get(PLAYBOOKS, page_only).text)
    assert "playbook:read" in body
    assert "Phishing triage" not in body


# ---------------------------------------------------------------------------
# The empty evidence workbench
# ---------------------------------------------------------------------------


def test_a_failed_pins_read_is_not_an_empty_workbench(pins):
    """The defect this panel exists to fix."""
    pins(raises=RuntimeError("the ledger went away"))
    body = flat(_get(WORKBENCH, _reader()).text)
    assert "no pins" not in body
    assert "could not" in body.lower()


def test_an_unreadable_pins_payload_is_not_an_empty_workbench(pins):
    pins(payload={"pins": "three"})
    body = flat(_get(WORKBENCH, _reader()).text)
    assert "no pins" not in body
    assert "not in a shape" in body


def test_a_genuinely_empty_workbench_still_says_no_pins(pins):
    pins(payload={"pins": []})
    body = flat(_get(WORKBENCH, _reader()).text)
    assert body.count("no pins") == 3, body


def test_the_three_columns_are_unchanged(pins):
    pins(payload={"pins": []})
    html = _get(WORKBENCH, _reader()).text
    for key in ("triage", "confirmed", "reported"):
        assert 'data-col="%s"' % key in html, key


def test_a_pin_lands_in_its_own_column(pins):
    pins(payload={"pins": [
        _pin(id=1, finding_status="triage", title="in triage"),
        _pin(id=2, finding_status="reported", title="reported one")]})
    html = _get(WORKBENCH, _reader()).text
    triage = html.index('data-col="triage"')
    confirmed = html.index('data-col="confirmed"')
    assert triage < html.index("in triage") < confirmed


def test_a_dismissed_pin_is_not_shown(pins):
    pins(payload={"pins": [_pin(finding_status="dismissed",
                                title="gone")]})
    assert "gone" not in flat(_get(WORKBENCH, _reader()).text)


def test_a_pin_in_an_unknown_column_is_not_silently_dropped(pins):
    """A status outside the three columns belonged to no column, so the
    pin vanished from a tamper-evident evidence board with nothing to say
    so."""
    pins(payload={"pins": [_pin(finding_status="escalated",
                                title="nowhere to go")]})
    body = flat(_get(WORKBENCH, _reader()).text)
    assert "nowhere to go" in body or "not categorised" in body


def test_the_visible_pin_count_is_reported(pins):
    pins(payload={"pins": [_pin(id=1), _pin(id=2),
                           _pin(id=3, finding_status="dismissed")]})
    html = _get(WORKBENCH, _reader()).text
    assert 'id="workbench-pin-count-7"' in html
    assert ">2<" in html.replace(" ", "").replace("\n", "")


def test_a_pin_with_no_title_says_so(pins):
    pins(payload={"pins": [_pin(title=None)]})
    assert "(untitled)" in flat(_get(WORKBENCH, _reader()).text)


def test_a_pin_summary_is_truncated_and_escaped(pins):
    pins(payload={"pins": [_pin(summary="<b>" + "x" * 300)]})
    html = _get(WORKBENCH, _reader()).text
    assert "<b>x" not in html
    assert "&lt;b&gt;" in html


def test_a_pin_action_argument_is_serialised(pins):
    pins(payload={"pins": [_pin()]})
    html = _get(WORKBENCH, _reader()).text
    for match in re.finditer(r"data-args='([^']*)'", html):
        json.loads(unescape(match.group(1)))


# ---------------------------------------------------------------------------
# The playbook browser
# ---------------------------------------------------------------------------


def test_a_nameless_playbook_does_not_take_the_browser_down(library):
    """`p.name.toLowerCase()` threw inside the filter."""
    library(payload={"playbooks": [_playbook(name=None),
                                   _playbook(id=6, name="Kept")]})
    body = flat(_get(PLAYBOOKS, _reader(), filter="kept").text)
    assert "Kept" in body


def test_a_nameless_playbook_is_still_listed_unfiltered(library):
    library(payload={"playbooks": [_playbook(name=None)]})
    html = _get(PLAYBOOKS, _reader()).text
    assert "undefined" not in html
    assert "an-absent" in html or "unnamed" in flat(html)


def test_a_failed_library_read_is_not_no_matching_playbooks(library):
    library(raises=RuntimeError("gone"))
    body = flat(_get(PLAYBOOKS, _reader()).text)
    assert "No matching playbooks" not in body
    assert "could not" in body.lower()


def test_an_unreadable_library_payload_is_not_no_playbooks(library):
    library(payload={"playbooks": "lots"})
    body = flat(_get(PLAYBOOKS, _reader()).text)
    assert "No matching playbooks" not in body
    assert "not in a shape" in body


def test_an_empty_library_says_so(library):
    library(payload={"playbooks": []})
    assert "No playbooks" in flat(_get(PLAYBOOKS, _reader()).text)


def test_a_filter_that_matches_nothing_says_so(library):
    library(payload={"playbooks": [_playbook()]})
    body = flat(_get(PLAYBOOKS, _reader(), filter="zzz").text)
    assert "No matching playbooks" in body


def test_the_filter_matches_name_and_description(library):
    library(payload={"playbooks": [
        _playbook(id=1, name="Alpha", description="about phishing"),
        _playbook(id=2, name="Phishing beta", description="other")]})
    body = flat(_get(PLAYBOOKS, _reader(), filter="phishing").text)
    assert "Alpha" in body
    assert "Phishing beta" in body


def test_active_and_library_playbooks_are_grouped(library):
    library(payload={"playbooks": [
        _playbook(id=1, name="Live", is_active=True),
        _playbook(id=2, name="Shelved", is_active=False)]})
    html = _get(PLAYBOOKS, _reader()).text
    assert "Active Playbooks" in html
    assert "Library Playbooks" in html
    assert html.index("Live") < html.index("Library Playbooks")


def test_a_playbook_with_no_step_count_does_not_print_undefined(library):
    library(payload={"playbooks": [_playbook(step_count=None)]})
    html = _get(PLAYBOOKS, _reader()).text
    assert "undefined" not in html
    assert "an-absent" in html


def test_a_description_is_truncated_at_eighty_characters(library):
    library(payload={"playbooks": [_playbook(description="y" * 200)]})
    body = flat(_get(PLAYBOOKS, _reader()).text)
    assert "y" * 80 in body
    assert "y" * 100 not in body


def test_a_playbook_name_with_a_double_quote_keeps_its_arguments_valid(
        library):
    """`esc(p.name)` turns `"` into `&quot;`, which the parser decodes
    back inside the single-quoted attribute and ends the JSON array
    early."""
    library(payload={"playbooks": [
        _playbook(name='Say "hello" to the analyst')]})
    html = _get(PLAYBOOKS, _reader()).text
    found = [json.loads(unescape(m.group(1)))
             for m in re.finditer(r"data-args='([^']*)'", html)]
    assert any('Say "hello" to the analyst' in a for args in found
               for a in args if isinstance(a, str)), found


def test_a_playbook_name_cannot_inject_markup(library):
    library(payload={"playbooks": [
        _playbook(name="<img src=x onerror=alert(1)>")]})
    html = _get(PLAYBOOKS, _reader()).text
    assert "<img src=x" not in html


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_these_panels():
    body = _scripts()
    for name in ("renderWorkbenchKanban", "renderWorkbenchPinCard",
                 "renderCasePlaybookBrowser", "renderCasePlaybookItem"):
        assert not re.search(r"function " + name + r"\b", body), name


def test_the_verify_banner_still_refuses_to_claim_a_valid_chain():
    """It was already right, and it is not part of this conversion. A
    tamper check that could not be read must not read as verified."""
    body = _scripts()
    assert "function renderWorkbenchVerifyBanner" in body
    assert "wb-verify-unknown" in body
    assert "verify unavailable" in body


def test_the_closure_buttons_are_cloned_not_built():
    page = PAGE.read_text(encoding="utf-8")
    for ident in ("tpl-closure-ai-idle", "tpl-closure-ai-busy",
                  "tpl-closure-ai-revert"):
        assert 'id="' + ident + '"' in page, ident
    body = _scripts()
    assert "icon-sparkles" not in body
    assert "icon-rotate-ccw" not in body


def test_the_playbook_failure_colour_is_not_a_literal_in_javascript():
    assert "#f44336" not in _scripts()
