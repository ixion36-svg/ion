"""The SOC toolbox's three server reads as fragments.

/tools is mostly a client-side page, and only three of its renders read
something ION holds: the single OpenCTI lookup, the bulk OpenCTI lookup,
and the translator's language list. Those are the ones tested here. The
fourteen renders that operate on text the analyst pasted into the browser
are tested in test_ui_page_tools_client_state.py, because they have no
route to drive.

Every route is driven through TestClient with the JSON endpoint's own
function stubbed, not by rendering the template. The IOC lookup is the
clearest case for insisting on that: the defect this conversion fixes is
not in the markup at all, it is that the request never carried a `type`.
A template test would have passed against it for ever.

The page is not licence-gated: /tools is alert:read in server.py and
neither OpenCTI route is under /api/de, so require_de_module is the wrong
gate and these tests fail if it appears.

WHAT WAS SHOWN TO FAIL

Run against the page as it stood, this whole file errors at collection:
ion.web.ui.tools does not exist.

Fourteen of the behavioural assertions were then driven against the module
carrying exactly their defect, one at a time, and each failed: a request
sent with a hard-coded type, an IPv6 address typed as a domain, any scheme
read as a URL, a `found` read by truthiness, a score read from the top
level only, a measured zero score collapsed by truthiness, labels
stringified rather than read as objects, an uncapped bulk list, a bulk
list not de-duplicated, a found tally counted from the rendered rows, the
related lists dropped, a JSONResponse 503 treated as no result, an empty
language list rendered as empty selects, and "auto" offered as a
translation target.
"""
from __future__ import annotations

import inspect

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from ion.web.ui.tools import (
    ALERT_READ,
    BULK_LIMIT,
    _bulk_values,
    ioc_type,
    router,
    type_label,
)


class _User:
    id = 1
    username = "alice"

    def has_permission(self, _name):
        return True


@pytest.fixture
def app():
    from ion.auth.dependencies import get_current_user

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def _enrich(monkeypatch, result):
    """Replace POST /api/opencti/enrich's own function."""
    async def fake(request_data, **kwargs):
        fake.asked.append({"type": request_data.type, "value": request_data.value})
        if isinstance(result, BaseException):
            raise result
        return result

    fake.asked = []
    monkeypatch.setattr("ion.web.api.enrich_observable", fake)
    return fake


def _batch(monkeypatch, result):
    """Replace POST /api/opencti/enrich/batch's own function."""
    async def fake(request_data, **kwargs):
        fake.asked.append(list(request_data.observables))
        if isinstance(result, BaseException):
            raise result
        # isfunction, not callable: a starlette Response is callable, so a
        # `callable(result)` check here invoked the 503 as an ASGI app and
        # the route reported a thrown read instead of a disabled OpenCTI.
        if inspect.isfunction(result):
            return result(request_data.observables)
        return result

    fake.asked = []
    monkeypatch.setattr("ion.web.api.enrich_batch", fake)
    return fake


def _languages(monkeypatch, result):
    def fake(**kwargs):
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr("ion.web.translator_api.get_languages", fake)
    return fake


def _hit(**extra):
    """The shape `enrich_observable` actually returns."""
    row = {
        "found": True,
        "type": "ipv4-addr",
        "value": "8.8.8.8",
        "observable": {"id": "x", "type": "IPv4-Addr", "value": "8.8.8.8",
                       "description": "resolver", "score": 80},
        "indicators": [],
        "threat_actors": [],
        "labels": [],
        "reports": [],
        "error": None,
    }
    row.update(extra)
    return row


def _route(path):
    for route in router.routes:
        if getattr(route, "path", None) == path:
            return route
    raise AssertionError(path)


def _dependency_names(route):
    names, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        stack.extend(dep.dependencies)
        if dep.call is not None:
            names.append(getattr(dep.call, "__qualname__", ""))
    return names


def _permissions_of(route):
    found = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        stack.extend(dep.dependencies)
        fn = dep.call
        if fn is None:
            continue
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(
            fn.__code__.co_freevars,
            (c.cell_contents for c in (fn.__closure__ or ())),
        ))
        name = cells.get("permission_name")
        if isinstance(name, str):
            found.add(name)
    return found


PATHS = ["/tools/ioc", "/tools/ioc-bulk", "/tools/translator-languages"]


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", PATHS)
def test_every_fragment_names_a_permission(path):
    """The language list copies its endpoint's alert:read. The two OpenCTI
    lookups have no named permission to copy, so they take the /tools
    page's own gate, which is stricter than the endpoint rather than
    softer. A fragment on bare authentication would have to be argued for
    in the registry's allow-list instead."""
    assert _permissions_of(_route(path)) == {ALERT_READ}


@pytest.mark.parametrize("path", PATHS)
def test_no_fragment_redirects_or_gates_on_a_licence(path):
    names = _dependency_names(_route(path))
    assert names, path
    for name in names:
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name
        assert "require_de_module" not in name


# ---------------------------------------------------------------------------
# Typing an indicator. This is the page's oldest defect.
# ---------------------------------------------------------------------------


def test_the_lookup_sends_a_type_which_the_page_never_did(client, monkeypatch):
    """`JSON.stringify({ value: ioc })` with no `type`. The endpoint's
    request model requires both, so every lookup this page ever made was
    rejected with a 422 before OpenCTI was asked, and the catch rendered
    the validation error as a failed fetch."""
    fake = _enrich(monkeypatch, _hit())
    client.post("/ui/tools/ioc", data={"value": "8.8.8.8"})
    client.post("/ui/tools/ioc", data={"value": "evil.example"})
    client.post("/ui/tools/ioc", data={"value": "d41d8cd98f00b204e9800998ecf8427e"})
    # Three values of three different types, so a hard-coded type passes
    # none of them. One value would have let `type="ipv4-addr"` through.
    assert fake.asked == [
        {"type": "ipv4-addr", "value": "8.8.8.8"},
        {"type": "domain-name", "value": "evil.example"},
        {"type": "file-md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
    ]


@pytest.mark.parametrize("value,expected", [
    ("d41d8cd98f00b204e9800998ecf8427e", "file-md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "file-sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     "file-sha256"),
    ("8.8.8.8", "ipv4-addr"),
    ("2001:4860:4860::8888", "ipv6-addr"),
    ("https://evil.example/x", "url"),
    ("abuse@evil.example", "email-addr"),
    ("evil.example", "domain-name"),
])
def test_every_type_it_sends_is_one_the_endpoint_accepts(value, expected):
    """Each of these is a key of OpenCTIService.TYPE_MAP, which is what the
    endpoint validates against. An IPv6 address went through a dotted-quad
    regex in the browser and came out as a domain."""
    from ion.services.opencti_service import OpenCTIService

    assert ioc_type(value) == expected
    assert expected in OpenCTIService.TYPE_MAP


def test_a_javascript_url_is_not_typed_as_a_url():
    """Only an http(s) scheme is a URL here. `javascript:alert(1)` has a
    colon and a scheme and is not a thing to look up as one."""
    assert ioc_type("javascript:alert(1)") == "domain-name"


def test_the_reader_facing_word_falls_back_to_the_type_itself():
    """detectIOCType was a second vocabulary built in the browser, and on
    this page the two always disagreed because the request carried no type
    at all. An unmapped type shows as itself rather than as a guess."""
    assert type_label("ipv4-addr") == "IPv4"
    assert type_label("autonomous-system") == "autonomous-system"


# ---------------------------------------------------------------------------
# The single lookup
# ---------------------------------------------------------------------------


def test_a_hit_is_rendered_as_a_hit(client, monkeypatch):
    """The render it replaces could not show one. Its branch was
    `data.found === false || !data.data || data.data.length === 0`, and the
    enrichment response has no `data` key, so a genuine hit always fell
    into "No threat intelligence found for this IOC" — a confident
    negative about an indicator OpenCTI knows."""
    _enrich(monkeypatch, _hit())
    body = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    assert "No record of this indicator" not in body
    assert "OpenCTI has no record" not in body
    assert "80" in body
    assert "resolver" in body


def test_the_score_is_read_from_where_the_service_puts_it(client, monkeypatch):
    """`data.score` is not a key of the response; the score is nested under
    `observable`, so the page showed nothing for a scored indicator."""
    _enrich(monkeypatch, _hit())
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["score"] == 80


def test_a_score_of_zero_is_a_finding_and_not_a_dash(client, monkeypatch):
    """Zero in OpenCTI means known and assessed as benign. `data.score ||
    '-'` printed a dash for it, which is what an unscored indicator looks
    like."""
    _enrich(monkeypatch, _hit(observable={"score": 0}))
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["score"] == 0
    assert "no score recorded" not in client.post(
        "/ui/tools/ioc", data={"value": "8.8.8.8"}).text


def test_an_unscored_hit_says_so_rather_than_showing_a_number(
        client, monkeypatch):
    _enrich(monkeypatch, _hit(observable={"value": "8.8.8.8"}))
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["score"] is None
    assert "no score recorded" in client.post(
        "/ui/tools/ioc", data={"value": "8.8.8.8"}).text


def test_a_label_is_an_object_and_its_value_is_what_is_shown(
        client, monkeypatch):
    """`data.labels.map(l => escapeHtml(l))` stringified each one, and a
    label is `{value, color}`, so a real label rendered as
    "[object Object]"."""
    _enrich(monkeypatch, _hit(labels=[{"value": "apt", "color": "#ff0000"}]))
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["labels"] == ["apt"]
    body = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    assert "object Object" not in body
    # The colour is OpenCTI's palette and does not belong in a view model.
    assert "#ff0000" not in body


def test_the_related_lists_are_the_ones_the_response_carries(
        client, monkeypatch):
    """The page rendered `data.relationships`, which the service never
    returns, so Related Entities was dead code while every real indicator,
    threat actor and report went unshown."""
    _enrich(monkeypatch, _hit(
        indicators=[{"name": "IPv4 8.8.8.8", "score": 50}],
        threat_actors=[{"name": "APT-Example"}],
        reports=[{"name": "Quarterly"}],
    ))
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert [r["name"] for r in data["indicators"]] == ["IPv4 8.8.8.8"]
    assert [r["name"] for r in data["threat_actors"]] == ["APT-Example"]
    assert [r["name"] for r in data["reports"]] == ["Quarterly"]
    body = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    for name in ("IPv4 8.8.8.8", "APT-Example", "Quarterly"):
        assert name in body


def test_a_found_flag_that_is_not_boolean_is_not_read_as_a_hit(
        client, monkeypatch):
    """Identity, not truthiness. `found: "no"` is a truthy string."""
    _enrich(monkeypatch, _hit(found="no"))
    data = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["found"] is None
    assert "without saying whether" in client.post(
        "/ui/tools/ioc", data={"value": "8.8.8.8"}).text


def test_a_miss_and_a_refusal_are_different_sentences(client, monkeypatch):
    _enrich(monkeypatch, _hit(found=False, observable=None))
    miss = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    assert "no record of this indicator" in miss

    _enrich(monkeypatch, _hit(found=False, error="Unsupported observable type"))
    refusal = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    assert "Unsupported observable type" in refusal
    assert "has not been checked" in refusal
    assert "no record of this indicator" not in refusal


def test_a_disabled_opencti_is_rendered_at_200_so_htmx_swaps_it(
        client, monkeypatch):
    """The endpoint answers JSONResponse 503 when OpenCTI is off. htmx does
    not swap a non-2xx response, so the reason has to arrive at 200 or the
    panel keeps whatever was there before."""
    _enrich(monkeypatch, JSONResponse(
        status_code=503,
        content={"found": False, "type": "ipv4-addr", "value": "8.8.8.8",
                 "error": "OpenCTI integration is not enabled"},
    ))
    response = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"})
    assert response.status_code == 200
    assert "not enabled" in response.text


def test_a_thrown_lookup_is_not_reported_as_a_miss(client, monkeypatch):
    _enrich(monkeypatch, RuntimeError("boom"))
    body = client.post("/ui/tools/ioc", data={"value": "8.8.8.8"}).text
    assert "did not run" in body
    assert "no record of this indicator" not in body


def test_an_empty_value_is_rejected_rather_than_looked_up(client, monkeypatch):
    """422, so htmx leaves the panel standing. Telling the reader a lookup
    failed when no lookup was asked for is the same conflation as the rest
    of this page."""
    fake = _enrich(monkeypatch, _hit())
    assert client.post("/ui/tools/ioc", data={"value": "   "}).status_code == 422
    assert fake.asked == []


# ---------------------------------------------------------------------------
# The bulk lookup
# ---------------------------------------------------------------------------


def _batch_payload(observables):
    return {
        "results": [
            {"found": True, "type": o["type"], "value": o["value"],
             "observable": {"score": 10}, "labels": [], "error": None}
            for o in observables
        ],
        "total": len(observables),
        "found": len(observables),
    }


def test_the_bulk_lookup_is_one_request_not_one_per_line(client, monkeypatch):
    """The page fetched /api/opencti/enrich once per pasted line,
    sequentially, from the browser."""
    fake = _batch(monkeypatch, _batch_payload)
    client.post("/ui/tools/ioc-bulk",
                data={"values": "8.8.8.8\nevil.example\n"})
    assert len(fake.asked) == 1
    assert fake.asked[0] == [
        {"type": "ipv4-addr", "value": "8.8.8.8"},
        {"type": "domain-name", "value": "evil.example"},
    ]


def test_a_repeated_line_is_looked_up_once(client, monkeypatch):
    """A pasted log extract repeats the same address on most of its lines,
    and the page spent one round trip on each."""
    fake = _batch(monkeypatch, _batch_payload)
    client.post("/ui/tools/ioc-bulk", data={"values": "8.8.8.8\n8.8.8.8\n 8.8.8.8 "})
    assert fake.asked[0] == [{"type": "ipv4-addr", "value": "8.8.8.8"}]


def test_a_list_longer_than_the_cap_says_what_was_not_checked(
        client, monkeypatch):
    """A truncated bulk run must not look like a clean one. The page had no
    cap at all, which is the other way of getting this wrong."""
    values = "\n".join(f"10.0.0.{i}" for i in range(BULK_LIMIT + 5))
    fake = _batch(monkeypatch, _batch_payload)
    data = client.post("/ui/tools/ioc-bulk", data={"values": values},
                       headers={"accept": "application/json"}).json()
    assert len(fake.asked[0]) == BULK_LIMIT
    assert data["submitted"] == BULK_LIMIT
    assert data["dropped"] == 5
    body = client.post("/ui/tools/ioc-bulk", data={"values": values}).text
    assert "5 not looked up" in body
    assert "unchecked rather than clean" in body


def test_the_found_tally_is_the_endpoints_own(client, monkeypatch):
    """`data.found !== false && data.data && data.data.length > 0` was
    never true, so every row in the old table read Not found however much
    OpenCTI knew."""
    # Two hits, and a third result this fragment cannot render as a row.
    # The tally has to be the endpoint's, so that a row the view model
    # dropped is still counted as checked: counting the rendered rows
    # instead would report 2 of 3 and read as one clean indicator.
    payload = {
        "results": [
            {"found": True, "type": "ipv4-addr", "value": "8.8.8.8",
             "observable": {"score": 90}},
            {"found": True, "type": "domain-name", "value": "bad.example"},
            "not a result object",
        ],
        "total": 3, "found": 3,
    }
    _batch(monkeypatch, payload)
    values = "8.8.8.8\nbad.example\nok.example"
    data = client.post("/ui/tools/ioc-bulk", data={"values": values},
                       headers={"accept": "application/json"}).json()
    assert len(data["rows"]) == 2
    assert data["found_count"] == 3
    body = client.post("/ui/tools/ioc-bulk", data={"values": values}).text
    assert "3 known to OpenCTI" in body
    assert "Found" in body


def test_a_bulk_miss_reads_as_a_miss_and_a_hit_as_a_hit(client, monkeypatch):
    _batch(monkeypatch, {
        "results": [
            {"found": True, "type": "ipv4-addr", "value": "8.8.8.8"},
            {"found": False, "type": "domain-name", "value": "ok.example"},
        ],
        "total": 2, "found": 1,
    })
    body = client.post("/ui/tools/ioc-bulk",
                       data={"values": "8.8.8.8\nok.example"}).text
    assert "Found" in body
    assert "Not found" in body


def test_a_bulk_row_with_a_measured_zero_score_shows_the_zero(
        client, monkeypatch):
    _batch(monkeypatch, {
        "results": [{"found": True, "type": "ipv4-addr", "value": "8.8.8.8",
                     "observable": {"score": 0}}],
        "total": 1, "found": 1,
    })
    data = client.post("/ui/tools/ioc-bulk", data={"values": "8.8.8.8"},
                       headers={"accept": "application/json"}).json()
    assert data["rows"][0]["score"] == 0


def test_a_row_that_errored_is_not_shown_as_not_found(client, monkeypatch):
    _batch(monkeypatch, {
        "results": [{"found": False, "type": "domain-name", "value": "x.example",
                     "error": "Unsupported observable type"}],
        "total": 1, "found": 0,
    })
    body = client.post("/ui/tools/ioc-bulk", data={"values": "x.example"}).text
    assert "not checked" in body
    assert "Not found" not in body


def test_a_disabled_opencti_in_bulk_explains_itself_at_200(client, monkeypatch):
    _batch(monkeypatch, JSONResponse(
        status_code=503,
        content={"results": [], "error": "OpenCTI is not configured"},
    ))
    response = client.post("/ui/tools/ioc-bulk", data={"values": "8.8.8.8"})
    assert response.status_code == 200
    assert "OpenCTI is not configured" in response.text
    assert "Nothing here has been checked" in response.text


def test_a_thrown_bulk_lookup_is_not_a_set_of_clean_results(
        client, monkeypatch):
    _batch(monkeypatch, RuntimeError("boom"))
    body = client.post("/ui/tools/ioc-bulk", data={"values": "8.8.8.8"}).text
    assert "did not run" in body
    assert "not a set of clean results" in body


def test_an_empty_bulk_paste_is_rejected(client, monkeypatch):
    fake = _batch(monkeypatch, _batch_payload)
    assert client.post("/ui/tools/ioc-bulk",
                       data={"values": "\n  \n"}).status_code == 422
    assert fake.asked == []


def test_the_bulk_splitter_reports_what_it_kept_and_dropped():
    values, submitted, dropped = _bulk_values("a\n\nb\n a \n")
    assert values == ["a", "b"]
    assert submitted == 2
    assert dropped == 0


# ---------------------------------------------------------------------------
# The translator's language pickers
# ---------------------------------------------------------------------------


def test_both_pickers_come_from_the_one_list(client, monkeypatch):
    _languages(monkeypatch, {"languages": [
        {"code": "auto", "label": "Auto-detect"},
        {"code": "en", "label": "English"},
        {"code": "ru", "label": "Russian"},
    ]})
    body = client.get("/ui/tools/translator-languages").text
    assert 'id="t-source"' in body
    assert 'id="t-target"' in body


def test_auto_detect_is_a_source_and_never_a_target(client, monkeypatch):
    """Asking Ollama to translate into "whatever you detect" is not a
    request. In the browser this was an early `return` inside the loop
    that built both selects."""
    _languages(monkeypatch, {"languages": [
        {"code": "auto", "label": "Auto-detect"},
        {"code": "en", "label": "English"},
    ]})
    body = client.get("/ui/tools/translator-languages").text
    source = body[body.index('id="t-source"'):body.index('id="t-target"')]
    target = body[body.index('id="t-target"'):]
    assert 'value="auto"' in source
    assert 'value="auto"' not in target
    assert 'value="en" selected' in target


def test_a_failed_language_read_renders_no_pickers_at_all(client, monkeypatch):
    """`if (!r.ok) return` left two empty selects beside a live Translate
    button, which posts the empty string as a language and gets a 400."""
    _languages(monkeypatch, RuntimeError("boom"))
    body = client.get("/ui/tools/translator-languages").text
    assert "could not be read" in body
    assert 'id="t-source"' not in body
    assert 'id="t-target"' not in body


def test_an_empty_language_list_is_treated_as_a_failed_read(
        client, monkeypatch):
    """A translator with no languages configured is not a thing this
    deployment can be in. An empty list means the read did not give us one,
    and two empty dropdowns are worse than a sentence saying so."""
    _languages(monkeypatch, {"languages": []})
    assert 'id="t-source"' not in client.get(
        "/ui/tools/translator-languages").text


def test_a_payload_without_a_language_list_is_a_failed_read(
        client, monkeypatch):
    _languages(monkeypatch, {"languages": "en,ru"})
    assert "could not be read" in client.get(
        "/ui/tools/translator-languages").text
