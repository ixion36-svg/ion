"""The discover search results as a fragment.

Measured on discover.html before the change, by reading displaySearchResults
and its caller:

  * ``header.innerHTML = displayFields.map(f => `<th>${f}</th>`)``. Field
    names come from Elasticsearch document keys, which in a log ingest
    system are whatever the logs carried, and they went into the markup
    unescaped. The cells were escaped; the headers were not.

  * `!data.hits || data.hits.length === 0` rendered "No results found", so
    a body whose `hits` was not a list said we looked and there were none.

  * ``countBadge.textContent = `${data.total} hits (${data.took_ms}ms)` ``
    printed "undefined hits (undefinedms)" for a payload missing either.

  * The endpoint distinguishes four failures and the page showed one
    sentence for all of them: 400 for Elasticsearch not enabled, 400 for
    not configured, 403 for an index pattern outside the allowed set, and
    500 for a search error. "Elasticsearch is not configured" and "that
    query failed" lead to different actions.

  * A cell whose field was absent from the hit and a cell whose value was
    explicitly null both rendered "-". In log analysis those differ.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.discover import PERMISSION, PRIORITY_FIELDS, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/discover.html"

URL = "/ui/discover/search"


class _User:
    id = 1
    username = "discover-tester"

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


def _post(user, accept=None, **form):
    headers = {"accept": accept} if accept else {}
    body = {"index_pattern": "logs-*", "query": "*"}
    body.update(form)
    with TestClient(_app(user)) as client:
        return client.post(URL, data=body, headers=headers)


def _reader():
    return _User(PERMISSION)


@pytest.fixture
def answers(monkeypatch):
    def set(result=None, raises=None):
        async def handler(request, current_user=None):
            if raises is not None:
                raise raises
            return result

        monkeypatch.setattr(
            "ion.web.elasticsearch_api.discover_search", handler)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


def _hit(**over):
    h = {"@timestamp": "2026-09-01T10:30:00Z", "message": "sshd accepted",
         "host.name": "web-01", "_index": "logs-2026.09.01"}
    h.update(over)
    return h


def _result(hits=None, **over):
    r = {"hits": [_hit()] if hits is None else hits, "total": 1,
         "took_ms": 7}
    r.update(over)
    return r


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_search_needs_the_pages_permission(answers):
    """The endpoint is bare authentication and the page is gated on
    alert:read, so the fragment takes the page's: stricter than the
    endpoint, never softer."""
    answers(result=_result())
    assert _post(_User()).status_code == 403
    assert _post(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# The failures the page showed as one sentence
# ---------------------------------------------------------------------------


def test_elasticsearch_not_configured_says_so(answers):
    answers(raises=HTTPException(status_code=400,
                                 detail="Elasticsearch is not configured"))
    body = flat(_post(_reader()).text)
    assert "not configured" in body
    assert "No results found" not in body


def test_an_index_pattern_outside_the_allowed_set_says_so(answers):
    """403 from _validate_index_pattern is a refusal, not a failure, and not
    an empty result."""
    answers(raises=HTTPException(status_code=403,
                                 detail="index pattern not allowed"))
    body = flat(_post(_reader()).text)
    assert "not allowed" in body or "refused" in body.lower()
    assert "No results found" not in body


def test_a_search_error_says_the_search_failed(answers):
    answers(raises=HTTPException(status_code=500, detail="shard failure"))
    body = flat(_post(_reader()).text)
    assert "could not" in body.lower() or "failed" in body.lower()
    assert "No results found" not in body


def test_an_unexpected_exception_still_renders_a_failure(answers):
    answers(raises=RuntimeError("the client went away"))
    body = flat(_post(_reader()).text)
    assert "No results found" not in body
    assert "could not" in body.lower() or "failed" in body.lower()


@pytest.mark.parametrize("result", [
    {}, {"hits": None}, {"hits": "two"}, [], None,
])
def test_a_body_that_is_not_that_shape_is_unreadable_not_empty(
        answers, result):
    answers(result=result)
    body = flat(_post(_reader()).text)
    assert "No results found" not in body, result
    assert "could not" in body.lower() or "failed" in body.lower(), result


def test_no_hits_says_no_results(answers):
    answers(result=_result(hits=[], total=0))
    body = flat(_post(_reader()).text)
    assert "No results found" in body
    assert "failed" not in body.lower()


# ---------------------------------------------------------------------------
# Field names are content, not markup
# ---------------------------------------------------------------------------


def test_a_field_name_carrying_markup_is_escaped(answers):
    """The headers went in unescaped while the cells were escaped. Field
    names are Elasticsearch document keys, which are whatever the logs
    carried."""
    answers(result=_result(hits=[{"<img src=x onerror=alert(1)>": "v",
                                  "message": "m"}]))
    html = _post(_reader()).text
    # The claim is that no tag was created, not that the text disappeared.
    # `=` needs no escaping in element content, so `onerror=alert(1)` is
    # still in the output as inert text, which is correct.
    assert "<img" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    # And the field name is inside the header cell the server wrote, as
    # escaped text, rather than having opened a tag of its own.
    header = re.search(r'id="search-results-header".*?</tr>', html, re.S)
    assert header, html
    cells = re.findall(r"<th>(.*?)</th>", header.group(0), re.S)
    assert "&lt;img src=x onerror=alert(1)&gt;" in cells, cells


def test_a_cell_value_carrying_markup_is_escaped(answers):
    answers(result=_result(hits=[{"message": "<script>alert(1)</script>"}]))
    html = _post(_reader()).text
    assert "<script>alert(1)" not in html


# ---------------------------------------------------------------------------
# Which columns are shown
# ---------------------------------------------------------------------------


def test_priority_fields_come_first_and_in_order(answers):
    answers(result=_result(hits=[{"zzz": 1, "message": "m",
                                  "@timestamp": "t", "host.name": "h"}]))
    html = _post(_reader()).text
    headers = re.findall(r"<th[^>]*>(.*?)</th>", html, re.S)
    headers = [unescape(h).strip() for h in headers]
    assert headers[0] == "@timestamp"
    assert "message" in headers
    for field in headers:
        assert field in PRIORITY_FIELDS or field == "zzz", field


def test_the_column_list_is_topped_up_to_five(answers):
    """`if (displayFields.length < 5)` filled from the remaining keys."""
    hit = {"message": "m", "a": 1, "b": 2, "c": 3, "d": 4, "e": 5}
    answers(result=_result(hits=[hit]))
    headers = re.findall(r"<th[^>]*>(.*?)</th>", _post(_reader()).text, re.S)
    assert len(headers) == 5, headers


def test_underscore_fields_are_not_offered_as_columns(answers):
    """`if (!k.startsWith('_')) allKeys.add(k)`, except _index which is in
    the priority list."""
    answers(result=_result(hits=[{"_score": 1, "_id": "x", "message": "m"}]))
    headers = [unescape(h).strip() for h in
               re.findall(r"<th[^>]*>(.*?)</th>", _post(_reader()).text,
                          re.S)]
    assert "_score" not in headers
    assert "_id" not in headers


def test_a_hit_that_is_not_a_mapping_is_skipped_not_fatal(answers):
    answers(result=_result(hits=["junk", _hit()]))
    body = flat(_post(_reader()).text)
    assert "sshd accepted" in body
    assert "failed" not in body.lower()


# ---------------------------------------------------------------------------
# Cells
# ---------------------------------------------------------------------------


def test_a_long_value_is_cut_and_marked(answers):
    answers(result=_result(hits=[{"message": "x" * 200}]))
    body = flat(_post(_reader()).text)
    assert "x" * 100 in body
    assert "x" * 101 not in body


def test_an_object_value_is_rendered_as_json(answers):
    answers(result=_result(hits=[{"message": {"nested": "value"}}]))
    assert "nested" in flat(_post(_reader()).text)


def test_a_field_absent_from_a_hit_reads_differently_from_a_null(answers):
    """Both rendered "-". In log analysis a field that is not there and a
    field explicitly set to null are different facts."""
    answers(result=_result(hits=[
        {"message": "present", "host.name": None},
    ]))
    body = _post(_reader()).text
    assert "null" in flat(body).lower()


# ---------------------------------------------------------------------------
# The count badge
# ---------------------------------------------------------------------------


def test_the_count_badge_reports_the_total_and_the_time(answers):
    answers(result=_result(total=42, took_ms=13))
    body = flat(_post(_reader()).text)
    assert "42" in body
    assert "13" in body


@pytest.mark.parametrize("over", [{"total": None}, {"took_ms": None},
                                  {"total": "lots"}])
def test_a_missing_figure_is_not_printed_as_undefined(answers, over):
    answers(result=_result(**over))
    body = flat(_post(_reader()).text)
    assert "undefined" not in body
    assert "None" not in body


# ---------------------------------------------------------------------------
# One object, rendered either way
# ---------------------------------------------------------------------------


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(result=_result())
    view = _post(_reader(), accept="application/json").json()
    assert view["state"] == "data"
    assert view["total"] == 1
    assert "@timestamp" in view["fields"]


def test_the_page_no_longer_builds_the_results_table():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction displaySearchResults\(.*?\n\}", body,
                      re.S)
    assert block, "the entry point is still there"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
