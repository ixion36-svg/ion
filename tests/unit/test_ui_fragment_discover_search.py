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


# ---------------------------------------------------------------------------
# The time histogram
# ---------------------------------------------------------------------------


HIST = "/ui/discover/histogram"


@pytest.fixture
def histogram(monkeypatch):
    def set(result=None, raises=None):
        async def handler(request, current_user=None):
            if raises is not None:
                raise raises
            return result

        monkeypatch.setattr(
            "ion.web.elasticsearch_api.discover_histogram", handler)

    return set


def _hpost(user, accept=None):
    headers = {"accept": accept} if accept else {}
    with TestClient(_app(user)) as client:
        return client.post(HIST, data={"index_pattern": "logs-*"},
                           headers=headers)


def test_the_histogram_needs_the_pages_permission(histogram):
    histogram(result={"buckets": [], "total": 0})
    assert _hpost(_User()).status_code == 403
    assert _hpost(_reader()).status_code == 200


def test_bars_are_scaled_against_the_tallest_bucket(histogram):
    histogram(result={"buckets": [
        {"timestamp": "t1", "count": 5},
        {"timestamp": "t2", "count": 10},
    ], "total": 15})
    html = _hpost(_reader()).text
    assert "height: 100.0%" in html or "height: 100%" in html
    assert "height: 50.0%" in html or "height: 50%" in html


def test_a_bucket_with_an_unreadable_count_is_not_drawn_as_zero(histogram):
    """`Math.max(...buckets.map(b => b.count))` made every height NaN if any
    one count was not a number, so the whole chart rendered as nothing. A
    zero-height bar also reads as a quiet hour, which is a claim."""
    histogram(result={"buckets": [
        {"timestamp": "t1", "count": 10},
        {"timestamp": "t2", "count": "lots"},
    ], "total": 10})
    html = _hpost(_reader()).text
    assert "dsc-bar-unmeasured" in html
    assert "height: 100.0%" in html or "height: 100%" in html


def test_a_bar_title_carrying_a_quote_cannot_break_the_attribute(histogram):
    """The page interpolated an Elasticsearch timestamp into
    `title="${b.timestamp}: ..."` with no escaping."""
    histogram(result={"buckets": [
        {"timestamp": 'x" onmouseover="alert(1)', "count": 1}], "total": 1})
    html = _hpost(_reader()).text
    assert 'onmouseover="alert(1)"' not in html
    assert "&#34;" in html or "&quot;" in html


@pytest.mark.parametrize("result", [{}, {"buckets": None},
                                     {"buckets": "two"}, None])
def test_a_histogram_body_of_the_wrong_shape_is_a_failure(
        histogram, result):
    histogram(result=result)
    body = flat(_hpost(_reader()).text)
    assert "No data for histogram" not in body, result
    assert "could not" in body.lower(), result


def test_an_empty_histogram_says_so(histogram):
    histogram(result={"buckets": [], "total": 0})
    body = flat(_hpost(_reader()).text)
    assert "No data for histogram" in body


def test_a_missing_total_is_not_printed_as_undefined(histogram):
    histogram(result={"buckets": [{"timestamp": "t", "count": 1}]})
    body = flat(_hpost(_reader()).text)
    assert "undefined" not in body
    assert "total unknown" in body


def test_the_histogram_reports_an_unconfigured_elasticsearch_distinctly(
        histogram):
    histogram(raises=HTTPException(status_code=400,
                                  detail="Elasticsearch is not configured"))
    body = flat(_hpost(_reader()).text)
    assert "not configured" in body
    assert "No data for histogram" not in body


def test_the_page_no_longer_draws_the_histogram():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction displayHistogram\(.*?\n\}", body, re.S)
    assert block, "the entry point is still there"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "style.display" not in block.group(0), (
        "the panel is shown by removing the hidden class")


# ---------------------------------------------------------------------------
# IOC hunt
# ---------------------------------------------------------------------------


IOC = "/ui/discover/ioc-hunt"
BULK = "/ui/discover/ioc-hunt/bulk"


@pytest.fixture
def hunt(monkeypatch):
    def set(result=None, raises=None, bulk=False):
        async def handler(request, current_user=None):
            if raises is not None:
                raise raises
            return result

        name = "ioc_hunt_bulk" if bulk else "ioc_hunt"
        monkeypatch.setattr("ion.web.elasticsearch_api." + name, handler)

    return set


def _ioc(user, url=IOC, **form):
    body = {"ioc_value": "203.0.113.9"} if url == IOC else {
        "ioc_values": "203.0.113.9"}
    body.update(form)
    with TestClient(_app(user)) as client:
        return client.post(url, data=body)


def test_the_details_column_emphasises_its_keys_rather_than_escaping_them(
        hunt):
    """The live bug. The page built `<strong>k:</strong> v` and then ran
    escapeHtml over the finished markup, so the analyst saw the literal
    text `<strong>host.name:</strong> web-01`."""
    hunt(result={"hits": [{"_index": "logs-1", "@timestamp": "t",
                           "host.name": "web-01"}],
                 "total": 1, "took_ms": 3, "ioc_value": "x",
                 "indices_found": []})
    html = _ioc(_reader()).text
    assert "<strong>host.name:</strong>" in html
    assert "&lt;strong&gt;" not in html


def test_an_index_name_carrying_markup_is_escaped(hunt):
    """`${i.index}` and `${hit._index}` went in unescaped, and index names
    come from Elasticsearch."""
    hunt(result={"hits": [{"_index": "<img src=x>", "@timestamp": "t"}],
                 "total": 1, "took_ms": 1, "ioc_value": "x",
                 "indices_found": [{"index": "<img src=y>", "count": 1}]})
    html = _ioc(_reader()).text
    assert "<img src=x>" not in html
    assert "<img src=y>" not in html
    assert "&lt;img src=x&gt;" in html


@pytest.mark.parametrize("result", [{}, {"hits": None}, {"hits": "two"}])
def test_an_ioc_body_of_the_wrong_shape_is_a_failure(hunt, result):
    hunt(result=result)
    body = flat(_ioc(_reader()).text)
    assert "No hits found" not in body, result
    assert "could not" in body.lower(), result


def test_an_empty_indicator_is_a_bad_request_not_an_empty_hunt(hunt):
    hunt(result={"hits": [], "total": 0})
    resp = _ioc(_reader(), ioc_value="   ")
    assert resp.status_code == 422
    assert "Enter an indicator" in flat(resp.text)


def test_a_missing_figure_is_not_printed_as_undefined(hunt):
    hunt(result={"hits": [], "ioc_value": "x", "indices_found": []})
    body = flat(_ioc(_reader()).text)
    assert "undefined" not in body
    assert "unknown" in body


# ---------------------------------------------------------------------------
# Bulk IOC hunt
# ---------------------------------------------------------------------------


def test_the_details_argument_survives_an_indicator_with_a_quote(hunt):
    """The fourth shape of one defect: escapeHtml turns " into &quot;,
    which inside a JSON string is six literal characters, so JSON.parse
    handed the dispatcher a different indicator than the one on screen."""
    import json as _json
    value = 'evil"\'value'
    hunt(bulk=True, result={"results": [
        {"ioc_value": value, "ioc_type": "ip", "found": True,
         "hit_count": 2, "indices": ["logs-1"]}],
        "total_searched": 1, "found_count": 1, "not_found_count": 0})
    html = _ioc(_reader(), url=BULK).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found, html
    assert _json.loads(unescape(found[0])) == [value]


def test_a_row_that_did_not_say_whether_it_was_found_is_not_not_found(hunt):
    """`r.found ? 'Found' : 'Not Found'` made a missing answer into a
    negative one."""
    hunt(bulk=True, result={"results": [
        {"ioc_value": "x", "ioc_type": "ip", "hit_count": 0,
         "indices": []}],
        "total_searched": 1, "found_count": 0, "not_found_count": 0})
    html = _ioc(_reader(), url=BULK).text
    # Scoped to the row: "Not Found" is also a stat label in the summary,
    # where it is a count rather than a verdict about this indicator.
    row = re.search(r"<tr>.*?</tr>", html, re.S)
    assert row, html
    assert "Not Found" not in row.group(0)
    assert "found-badge" not in row.group(0)
    assert "dsc-absent" in row.group(0)


def test_a_row_whose_indices_are_not_a_list_does_not_take_the_table_down(
        hunt):
    """`r.indices.slice(0, 3)` threw, and the caller's catch turned the
    whole table into a toast."""
    hunt(bulk=True, result={"results": [
        {"ioc_value": "x", "found": True, "hit_count": 1,
         "indices": "logs-1"}],
        "total_searched": 1, "found_count": 1, "not_found_count": 0})
    body = flat(_ioc(_reader(), url=BULK).text)
    assert "could not" not in body.lower()
    assert "x" in body


def test_bulk_with_no_indicators_is_a_bad_request(hunt):
    hunt(bulk=True, result={"results": []})
    resp = _ioc(_reader(), url=BULK, ioc_values="  \n  \n")
    assert resp.status_code == 422
    assert "at least one indicator" in flat(resp.text)


def test_the_page_no_longer_builds_either_ioc_table():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    for name in ("displayIOCHuntResults", "displayBulkIOCResults"):
        block = re.search(r"\bfunction " + name + r"\(.*?\n\}", body, re.S)
        assert block, name
        assert not re.search(r"\.innerHTML\s*=", block.group(0)), name
        assert "htmx.ajax" in block.group(0), name


def test_the_three_ioc_panels_share_one_visibility_mechanism():
    """Two of them carry class="hidden" in the markup and all three were
    shown with style.display, so an inline style and a class were both
    deciding the same thing."""
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    assert "function dscShowIOCPanel(" in body
    for ident in ("ioc-empty-state", "ioc-single-results",
                  "ioc-bulk-results"):
        assert ident + "').style.display" not in body, ident


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------


SAVED = "/ui/discover/saved-searches"


@pytest.fixture
def saved(monkeypatch):
    def set(rows=None, raises=None):
        def handler(search_type=None, favorites_only=False,
                    current_user=None, session=None):
            if raises is not None:
                raise raises
            return rows

        monkeypatch.setattr("ion.web.api.list_saved_searches", handler)

    return set


def _row(ident=1, **over):
    r = {"id": ident, "name": "my search", "created_by_id": 1,
         "created_by_username": "lyndon", "is_shared": False,
         "is_favorite": False, "execution_count": 3,
         "last_executed_at": "2026-09-01T10:30:00"}
    r.update(over)
    return r


def _saved_get(user):
    from ion.storage.database import get_db_session

    application = _app(user)
    application.dependency_overrides[get_db_session] = lambda: None
    with TestClient(application) as client:
        return client.get(SAVED)


def test_a_search_of_someone_elses_that_is_not_shared_is_in_no_list(saved):
    """The defect. `mine` was `s => !s.is_shared || s.created_by_id === me`,
    so an unshared search belonging to somebody else landed in My searches.
    The repository is not expected to return one, which is what let it
    survive."""
    saved(rows={"saved_searches": [
        _row(1, name="mine", created_by_id=1),
        _row(2, name="theirs", created_by_id=99, is_shared=False),
    ]})
    body = flat(_saved_get(_reader()).text)
    assert "mine" in body
    assert "theirs" not in body


def test_my_own_shared_search_is_mine_not_shared_with_me(saved):
    """getCurrentUserId read window.currentUser, set by an /api/auth/me
    fetch that resolved after DOMContentLoaded with its failure swallowed,
    so before it landed every owned search looked like somebody else's."""
    saved(rows={"saved_searches": [
        _row(1, name="my shared one", created_by_id=1, is_shared=True)]})
    html = _saved_get(_reader()).text
    # The favourites and shared lists come back as out-of-band blocks; the
    # fragment's own body is the "mine" list, because that is the target
    # the page swaps into.
    body = html.split('id="shared-searches-list"')[-1]
    mine = body.split("</div>", 1)[-1]
    assert "my shared one" in flat(mine), html
    assert "By:" not in flat(html)


def test_someone_elses_shared_search_is_attributed(saved):
    saved(rows={"saved_searches": [
        _row(2, name="theirs", created_by_id=99, is_shared=True,
             created_by_username="sam")]})
    body = flat(_saved_get(_reader()).text)
    assert "theirs" in body
    assert "By: sam" in body


def test_a_username_carrying_markup_is_escaped(saved):
    saved(rows={"saved_searches": [
        _row(2, created_by_id=99, is_shared=True,
             created_by_username="<img src=x>")]})
    html = _saved_get(_reader()).text
    assert "<img src=x>" not in html


def test_a_favourite_appears_in_the_favourites_list(saved):
    saved(rows={"saved_searches": [
        _row(1, name="starred", is_favorite=True)]})
    html = _saved_get(_reader()).text
    favourites = html.split('id="shared-searches-list"')[0]
    assert "starred" in flat(favourites)


@pytest.mark.parametrize("rows", [None, {}, {"saved_searches": None},
                                   {"saved_searches": "two"}])
def test_an_unreadable_list_says_unavailable_not_empty(saved, rows):
    saved(rows=rows)
    body = flat(_saved_get(_reader()).text)
    assert "Saved searches unavailable" in body, rows
    assert "No saved searches" not in body, rows


def test_a_read_that_raised_says_unavailable(saved):
    saved(raises=RuntimeError("the repository fell over"))
    assert "Saved searches unavailable" in flat(_saved_get(_reader()).text)


def test_no_searches_says_so_in_each_list(saved):
    saved(rows={"saved_searches": []})
    body = flat(_saved_get(_reader()).text)
    assert "No saved searches" in body
    assert "No favorites yet" in body
    assert "No shared searches" in body


def test_a_missing_run_count_is_not_printed_as_undefined(saved):
    saved(rows={"saved_searches": [_row(1, execution_count=None)]})
    body = flat(_saved_get(_reader()).text)
    assert "undefined" not in body
    assert "run count unknown" in body


def test_the_last_run_date_is_read_as_utc(saved):
    saved(rows={"saved_searches": [
        _row(1, last_executed_at="2026-09-01T10:30:00")]})
    assert "2026-09-01 10:30 UTC" in flat(_saved_get(_reader()).text)


def test_a_search_never_run_says_never(saved):
    saved(rows={"saved_searches": [_row(1, last_executed_at=None)]})
    assert "Never" in flat(_saved_get(_reader()).text)


def test_every_saved_search_data_args_is_parseable_json(saved):
    import json as _json
    saved(rows={"saved_searches": [_row(1), _row("not-a-number")]})
    html = _saved_get(_reader()).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found
    for raw in found:
        _json.loads(unescape(raw))


def test_the_page_no_longer_builds_the_saved_search_lists():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction displaySavedSearches\(.*?\n\}", body,
                      re.S)
    assert block, "the entry point is still there"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "function renderSavedSearchItem" not in body
    # The helper and the round trip it needed are gone.
    assert "function getCurrentUserId" not in body
    assert "window.currentUser" not in body
