"""The AI chat answer panels: citations, the grounding advisory, feedback.

AN ABSENT GROUNDING BOX MEANT TWO OPPOSITE THINGS

The grounding pass exists to tell an analyst which specifics in an answer
the cited sources do not support. ai_api.py emits it only when it ran:

    if not grounding.get("skipped"):
        yield f"data: {json.dumps({'grounding': grounding})}\\n\\n"

and the page discarded what little was left:

    if (!g || g.skipped) return '';

So no grounding box meant either "checked, and every specific is in the
sources" or "never checked" — the feature is off by default, and skips
when RAG returned nothing to check against. For an advisory whose whole
job is to say whether to trust the specifics, those two are opposites. The
fragment says which, including when the stream carried no grounding event
at all.

The service also collects a `notes` field, the model's own explanation of
what it could not support, and caps it at 500 characters. Nothing ever
rendered it.

A GROUNDING WARNING COULD BECOME A REASSURANCE

    if (g.grounded && !claims.length) return 'Every specific here appears
                                              in the cited sources.'

with `claims = g.unsupported_claims || []`. A claims payload that is not
a list becomes an empty one. The service now stores that value as None
and does not derive a pass from it. This fragment's unreadable state is
that result, and it refuses the reassurance unless the claims list was
readable.

CITATIONS

`if (!citations || !citations.length) return ''` renders a payload that is
not a list as "no sources", which for a cited answer is the wrong way to
be wrong.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.chat import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/chat.html"

URL = "/ui/chat/answer-meta"


class _User:
    id = 1
    username = "chat-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    return application


def _post(user, **form):
    with TestClient(_app(user)) as client:
        return client.post(URL, data=form)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _meta(citations=None, grounding=None, msg_id="msg-1",
          show_citations=True):
    form = {"msg_id": msg_id,
            "show_citations": "true" if show_citations else "false"}
    if citations is not None:
        form["citations"] = json.dumps(citations)
    if grounding is not None:
        form["grounding"] = json.dumps(grounding)
    return form


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_chat_permission():
    assert _post(_User(), **_meta()).status_code == 403
    assert _post(_reader(), **_meta()).status_code == 200


# ---------------------------------------------------------------------------
# The grounding advisory
# ---------------------------------------------------------------------------


def test_no_grounding_event_says_the_answer_was_not_checked(_=None):
    """The defect this panel exists to fix. The box was simply absent,
    which is what a clean check also looked like."""
    body = flat(_post(_reader(), **_meta()).text)
    assert "not checked" in body.lower()
    assert "appears in the cited sources" not in body


def test_a_skipped_check_reports_its_reason():
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": True, "grounded": None,
        "reason": "no sources were retrieved"})).text)
    assert "not checked" in body.lower()
    assert "no sources were retrieved" in body


def test_a_clean_check_says_so():
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": True,
        "unsupported_claims": []})).text)
    assert "appears in the cited sources" in body
    assert "not checked" not in body.lower()


def test_unsupported_claims_are_listed():
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": False,
        "unsupported_claims": ["CVE-2026-1 is exploited",
                               "the host is a domain controller"]})).text)
    assert "CVE-2026-1 is exploited" in body
    assert "the host is a domain controller" in body
    assert "Not found in the cited sources" in body


def test_the_models_notes_are_rendered():
    """The service collects and caps `notes` and nothing read it."""
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": False,
        "unsupported_claims": ["a claim"],
        "notes": "the context covers only the first host"})).text)
    assert "the context covers only the first host" in body


def test_an_unreadable_claims_list_is_not_a_clean_check():
    """`g.unsupported_claims || []` turned it into one."""
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": True,
        "unsupported_claims": "lots of things"})).text)
    assert "appears in the cited sources" not in body
    assert "not in a shape" in body or "could not" in body.lower()


def test_the_service_records_an_unreadable_list_as_the_unreadable_state():
    """The service emits None for a claims value that was not a list, and
    leaves skipped false. That is this panel's unreadable state, not the
    reassurance and not the not-checked box."""
    from ion.services.chat_grounding_service import _normalize_result

    recorded = _normalize_result(
        {"unsupported_claims": "CVE-2024-1 is used in the wild"})
    assert recorded["skipped"] is False
    body = flat(_post(_reader(), **_meta(grounding=recorded)).text)
    assert "not in a shape" in body
    assert "appears in the cited sources" not in body
    assert "Not checked against sources" not in body


def test_not_grounded_with_no_claims_listed_says_that():
    """The page drew the warning box with a header, a footer and nothing
    between them."""
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": False,
        "unsupported_claims": []})).text)
    assert "did not list" in body or "listed none" in body
    assert "appears in the cited sources" not in body


def test_a_claim_is_escaped():
    html = _post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": False,
        "unsupported_claims": ["<img src=x onerror=alert(1)>"]})).text
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_a_grounding_payload_that_is_not_an_object_is_reported():
    body = flat(_post(_reader(), **_meta(grounding=["broken"])).text)
    assert "not in a shape" in body or "could not" in body.lower()


def test_grounding_that_is_not_json_is_reported():
    with TestClient(_app(_reader())) as client:
        body = flat(client.post(URL, data={
            "msg_id": "msg-1", "grounding": "{not json"}).text)
    assert "could not" in body.lower() or "not in a shape" in body


def test_the_advisory_says_it_is_advisory():
    """It annotates an answer the analyst already has. It must not read
    as a verdict on the answer."""
    body = flat(_post(_reader(), **_meta(grounding={
        "skipped": False, "grounded": False,
        "unsupported_claims": ["a claim"]})).text)
    assert "Advisory" in body
    assert "verify before acting" in body.lower()


# ---------------------------------------------------------------------------
# Citations
# ---------------------------------------------------------------------------


def test_citations_are_listed_with_their_kind():
    html = _post(_reader(), **_meta(citations=[
        {"type": "knowledge_base", "title": "Phishing runbook"},
        {"type": "playbook", "title": "IR-7"}])).text
    body = flat(html)
    assert "Phishing runbook" in body
    assert "KB" in body
    assert "IR-7" in body
    assert "PB" in body


def test_an_unknown_citation_kind_keeps_its_text_but_not_its_class():
    """`escapeHtml(labels[c.type] || c.type)` put the raw type in the
    text, which is fine, but the chip class came from a fixed set."""
    html = _post(_reader(), **_meta(citations=[
        {"type": "weird kind", "title": "T"}])).text
    assert "weird kind" in flat(html)
    assert 'class="ai-citation-chip weird kind"' not in html


def test_a_citation_title_is_escaped():
    html = _post(_reader(), **_meta(citations=[
        {"type": "user_note", "title": "<script>alert(1)</script>"}])).text
    assert "<script>alert(1)" not in html
    assert "alert(1)" in flat(html)


def test_a_citation_with_no_title_says_so_rather_than_nothing():
    body = flat(_post(_reader(), **_meta(citations=[
        {"type": "user_note"}])).text)
    assert "untitled" in body.lower()


def test_citations_that_are_not_a_list_are_reported():
    body = flat(_post(_reader(), **_meta(citations={"a": 1})).text)
    assert "not in a shape" in body or "could not" in body.lower()


def test_no_citations_draws_no_citations_bar():
    html = _post(_reader(), **_meta(citations=[])).text
    assert "ai-citations-bar" not in html


def test_citations_are_withheld_when_the_preference_is_off():
    html = _post(_reader(), **_meta(
        citations=[{"type": "user_note", "title": "T"}],
        show_citations=False)).text
    assert "ai-citations-bar" not in html
    assert "T" not in flat(html)


def test_the_grounding_advisory_is_shown_even_with_citations_off():
    """The preference hides sources, not a warning about the answer."""
    body = flat(_post(_reader(), **_meta(
        grounding={"skipped": False, "grounded": False,
                   "unsupported_claims": ["a claim"]},
        show_citations=False)).text)
    assert "a claim" in body


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


def test_the_feedback_row_carries_the_message_id():
    html = _post(_reader(), **_meta(msg_id="msg-42")).text
    assert 'data-msg-id="msg-42"' in html


def test_a_message_id_cannot_break_out_of_its_attribute():
    html = _post(_reader(), **_meta(msg_id='" onmouseover="alert(1)')).text
    assert 'onmouseover="alert(1)' not in html


def test_the_feedback_buttons_are_present():
    html = _post(_reader(), **_meta()).text
    assert "submitFeedback" in html
    assert html.count("ai-fb-btn") >= 2


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page_js() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    return re.sub(r"//[^\n]*", "", body)


def test_the_page_no_longer_builds_the_answer_panels():
    body = _page_js()
    for name in ("renderCitations", "renderGrounding", "renderFeedback"):
        assert "function " + name not in body, name


def test_the_page_asks_for_the_panels_once_the_stream_ends():
    body = _page_js()
    assert "/ui/chat/answer-meta" in body
