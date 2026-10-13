"""The SOC Command Centre as server-rendered fragments.

analyst.html built the queue, the case list, four KPI tiles, the IOC result
and the knowledge-base panel by concatenating strings into innerHTML. Each
test below names the defect that version had, and the arrangement is one
the defect would still produce: a zero that truthiness swallows, a ninth
row a slice drops, a bool that is also an int, a read that threw.

The page is not licence-gated. /analyst is alert:read in server.py and the
JSON routes it calls are not under /api/de, so require_de_module is the
wrong gate and these tests fail if it appears.
"""
from __future__ import annotations

import importlib
import re
import shutil
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import ion.models  # noqa: F401  (register every table before create_all)
from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.document import Document
from ion.models.template import Collection
from ion.models.user import User
from ion.services.opencti_service import OpenCTIService
from ion.web.ui.analyst import (
    ALERT_READ,
    CASE_READ,
    DOCUMENT_READ,
    OBSERVABLE_READ,
    _ioc_type,
    _topic_chips,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src" / "ion" / "web" / "templates" / "analyst.html"
SERVER = ROOT / "src" / "ion" / "web" / "server.py"


class _User:
    def __init__(self, id=1, username="alice"):
        self.id = id
        self.username = username

    def has_permission(self, _name):
        return True


class _Denied:
    id = 1
    username = "nobody"

    def has_permission(self, _name):
        return False


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app):
    with TestClient(app) as test_client:
        yield test_client


def _page() -> str:
    """The template with comments removed.

    A whole-file substring match is true of a comment that describes the
    thing the test thinks it is looking at. Tags are read from this.
    """
    src = PAGE.read_text(encoding="utf-8")
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return src


def _script() -> str:
    src = PAGE.read_text(encoding="utf-8")
    return "".join(re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S))


def _tag(src: str, element_id: str) -> str:
    match = re.search(rf'<[^>]*\bid="{element_id}"[^>]*>', src, re.S)
    assert match, element_id
    return match.group(0)


def inner(html: str, element_id: str) -> str:
    match = re.search(rf'id="{element_id}"[^>]*>(.*?)</', html, re.S)
    assert match, element_id
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _dependency_names(route) -> list[str]:
    return [getattr(d.call, "__qualname__", "") for d in route.dependant.dependencies]


def _permission_of(route) -> str | None:
    for dep in route.dependant.dependencies:
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(
                fn.__code__.co_freevars,
                (c.cell_contents for c in (fn.__closure__ or ())),
            ))
            return cells.get("permission_name")
    return None


def _route_of(owner, fn):
    for route in owner.routes:
        if getattr(route, "endpoint", None) is fn:
            return route
    raise AssertionError(getattr(fn, "__name__", fn))


def _fragment(path: str):
    for route in router.routes:
        if getattr(route, "path", None) == path:
            return route
    raise AssertionError(path)


def _alerts(monkeypatch, payload):
    async def fake(**kwargs):
        fake.kwargs = kwargs
        return payload

    fake.kwargs = {}
    monkeypatch.setattr("ion.web.elasticsearch_api.get_es_alerts", fake)
    return fake


def _alert(title, severity="low", minute=0, **extra):
    row = {
        "rule_name": title,
        "severity": severity,
        "timestamp": f"2026-10-12T00:{minute:02d}:00Z",
        "host": "web01",
        "user": "alice",
    }
    row.update(extra)
    return row


def _user(session, username) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="x",
    )
    session.add(user)
    session.flush()
    return user


# ---------------------------------------------------------------------------
# Gates. Read from the JSON routes, not restated.
# ---------------------------------------------------------------------------


def test_the_page_permission_is_alert_read_and_the_fragment_does_not_guess():
    """tools/fragment_plan.py reports this. Pinned against server.py so a
    rename of the permission fails here rather than by someone retyping it."""
    src = SERVER.read_text(encoding="utf-8")
    assert re.search(r'\("/analyst",\s+"analyst.html",\s+"alert:read"\)', src)


def test_each_fragment_uses_its_json_routes_permission_and_not_the_module_gate():
    """A fragment softer than the endpoint it mirrors is a second door.
    analyst is not a de_* module, and none of these JSON routes carry
    require_de_module: adding it would 404 the command centre wherever
    detection engineering is unlicensed."""
    from ion.web.api import (
        enrich_observable,
        get_analyst_knowledge_base,
        get_team_metrics,
        router as api_router,
        search_analyst_knowledge_base,
    )
    from ion.web.case_lifecycle_api import list_cases, router as case_router
    from ion.web.elasticsearch_api import get_es_alerts, router as es_router
    from ion.web.observable_api import get_observable_stats, router as obs_router

    pairs = [
        ("/analyst/alerts", _route_of(es_router, get_es_alerts), ALERT_READ),
        ("/analyst/mttr", _route_of(api_router, get_team_metrics), ALERT_READ),
        ("/analyst/cases", _route_of(case_router, list_cases), CASE_READ),
        ("/analyst/watched", _route_of(obs_router, get_observable_stats), OBSERVABLE_READ),
        ("/analyst/kb", _route_of(api_router, get_analyst_knowledge_base), DOCUMENT_READ),
    ]
    for path, json_route, permission in pairs:
        assert _permission_of(json_route) == permission, path
        assert _permission_of(_fragment(path)) == permission, path

    search_route = _route_of(api_router, search_analyst_knowledge_base)
    assert _permission_of(search_route) == DOCUMENT_READ
    assert _permission_of(_fragment("/analyst/kb")) == DOCUMENT_READ

    # The JSON lookup is bare authentication. The fragment is the page's
    # alert:read, which is stricter, because the bare-auth allow-list is
    # not editable from this conversion and a softer door is the failure.
    enrich_route = _route_of(api_router, enrich_observable)
    assert _permission_of(enrich_route) is None
    assert any(
        name.startswith("get_current_user") for name in _dependency_names(enrich_route)
    )
    assert _permission_of(_fragment("/analyst/ioc")) == ALERT_READ

    for route in router.routes:
        names = _dependency_names(route)
        assert not any("require_de_module" in name for name in names), route.path
        assert not any("require_page_permission" in name for name in names)


def test_a_viewer_without_the_permission_is_refused_rather_than_shown_an_empty_queue(
    session,
):
    """The dependency has to be the one that runs. A route that only
    mentions alert:read in a comment still renders."""
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _Denied()
    application.dependency_overrides[get_db_session] = lambda: session
    with TestClient(application) as denied:
        resp = denied.get("/ui/analyst/alerts")
    assert resp.status_code == 403
    assert "No alerts in the last 24 hours" not in resp.text
    assert "could not be read" not in resp.text


def test_the_module_is_discovered_and_its_routes_mount():
    ui = importlib.import_module("ion.web.ui")
    assert "analyst" in ui._page_modules()
    paths = {getattr(route, "path", "") for route in ui.router.routes}
    for path in (
        "/ui/analyst/alerts",
        "/ui/analyst/cases",
        "/ui/analyst/mttr",
        "/ui/analyst/watched",
        "/ui/analyst/ioc",
        "/ui/analyst/kb",
    ):
        assert path in paths


# ---------------------------------------------------------------------------
# Priority queue. Slice-then-sort, missing severity, and zero.
# ---------------------------------------------------------------------------


def test_the_queue_sorts_before_it_caps_so_a_ninth_critical_is_not_dropped(
    client, monkeypatch
):
    """Defect: `alerts.slice(0, 8)` and only then the severity sort. The
    critical row is the ninth element on purpose."""
    lows = [_alert(f"low-{i}", "low", i) for i in range(8)]
    payload = {
        "alerts": lows + [_alert("critical-last", "critical", 0)],
        "total": 9,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    resp = client.get("/ui/analyst/alerts")
    assert resp.status_code == 200
    assert "critical-last" in resp.text
    assert "low-0" not in resp.text


def test_nine_lows_keep_the_newest_and_drop_the_oldest(client, monkeypatch):
    """Same slice, the other way. Input is oldest-first, which is what the
    slice keeps and what a newest-first sort drops."""
    payload = {
        "alerts": [_alert(f"low-{i}", "low", i) for i in range(9)],
        "total": 9,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    resp = client.get("/ui/analyst/alerts")
    assert "low-8" in resp.text
    assert "low-0" not in resp.text


def test_critical_and_high_are_counted_before_the_cap(client, monkeypatch):
    """Defect: the tiles counted the eight rows on screen. Nine critical
    alerts would read 8, and a high count of zero would disappear if the
    tile were gated on truthiness while critical was non-zero."""
    payload = {
        "alerts": [_alert(f"c-{i}", "critical", i) for i in range(9)],
        "total": 9,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    resp = client.get("/ui/analyst/alerts")
    assert inner(resp.text, "kpi-critical") == "9"
    assert inner(resp.text, "kpi-high") == "0"
    assert resp.text.count("c-") == 8


def test_a_missing_severity_is_unknown_and_sorts_after_low(client, monkeypatch):
    """Defect: `(sev || 'low')`. A row nobody classified rendered as low and
    sorted with the lows. The unknown row is the newer of the two, so a
    rank that treats it as low puts it first."""
    payload = {
        "alerts": [
            _alert("unknown-row", None, 2),
            _alert("low-row", "low", 1),
        ],
        "total": 2,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    resp = client.get("/ui/analyst/alerts")
    assert ">unknown<" in resp.text
    assert resp.text.index("low-row") < resp.text.index("unknown-row")


def test_an_unrecognised_severity_is_shown_as_itself(client, monkeypatch):
    payload = {
        "alerts": [_alert("odd", "severe", 1)],
        "total": 1,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    text = client.get("/ui/analyst/alerts").text
    assert ">severe<" in text
    assert "bg-slate-500/15 text-slate-400" in text


def test_a_title_of_zero_is_kept_and_markup_is_escaped(client, monkeypatch):
    """Defect: a hand-rolled esc(), and `rule_name || title || 'Untitled'`,
    which treats no string as empty but would also drop a title the
    truthiness check considered blank if someone wrote `or 'Untitled'`."""
    payload = {
        "alerts": [
            _alert("0", "low", 1, host="0", user=None),
            _alert("<script>alert(1)</script>", "low", 2),
        ],
        "total": 2,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    text = client.get("/ui/analyst/alerts").text
    assert "Untitled" not in text
    assert ">None<" not in text
    assert "<script>" not in text
    assert "&lt;script&gt;" in text


def test_a_missing_timestamp_is_not_the_epoch(client, monkeypatch):
    """Defect: `new Date(b.timestamp || 0)` sorts and can render the epoch.
    An unparseable value is still shown; it is not replaced with 1970."""
    payload = {
        "alerts": [
            _alert("dated", "low", 1),
            {"rule_name": "undated", "severity": "low", "timestamp": None},
            {"rule_name": "garbage", "severity": "low", "timestamp": "not-a-date"},
        ],
        "total": 3,
        "enabled": True,
        "configured": True,
    }
    _alerts(monkeypatch, payload)
    text = client.get("/ui/analyst/alerts").text
    assert "<time" in text
    assert "2026-10-12" in text
    assert "not-a-date" in text
    assert "1970" not in text
    assert "—" in text


def test_a_total_of_zero_is_not_the_length_of_the_page(client, monkeypatch):
    """Defect: `alertsRes.total || 0`, and a missing total falling through
    to the rows in hand. Two alerts with a reported total of 0 must read 0.
    A bool is not a number even though True == 1."""
    rows = [_alert("a-one", "low", 1), _alert("a-two", "low", 2)]
    _alerts(monkeypatch, {
        "alerts": rows, "total": 0, "enabled": True, "configured": True,
    })
    resp = client.get("/ui/analyst/alerts")
    assert inner(resp.text, "kpi-open-alerts") == "0"
    assert "Last 24h" in resp.text

    _alerts(monkeypatch, {"alerts": rows, "enabled": True, "configured": True})
    missing = client.get("/ui/analyst/alerts")
    assert inner(missing.text, "kpi-open-alerts") == "—"
    assert "count was not returned" in missing.text

    _alerts(monkeypatch, {
        "alerts": rows, "total": True, "enabled": True, "configured": True,
    })
    flagged = client.get("/ui/analyst/alerts")
    assert inner(flagged.text, "kpi-open-alerts") == "—"
    assert inner(flagged.text, "kpi-open-alerts") != "1"


def test_a_payload_that_is_not_a_list_is_a_failed_read_not_an_empty_queue(
    client, monkeypatch
):
    """Defect: `alertsRes.alerts || []` turns a non-list into the empty
    state, and a total of 0 then says the queue was empty."""
    _alerts(monkeypatch, {"alerts": "nope", "total": 0, "enabled": True, "configured": True})
    resp = client.get("/ui/analyst/alerts")
    assert resp.status_code == 200
    assert "Alerts could not be read. This is not an empty queue" in resp.text
    assert "No alerts in the last 24 hours" not in resp.text
    assert inner(resp.text, "kpi-open-alerts") == "unavailable"
    assert ">0</span>" not in resp.text


def test_a_thrown_read_is_not_rendered_as_zero_alerts(client, monkeypatch):
    async def boom(**_kwargs):
        raise RuntimeError("elasticsearch down")

    monkeypatch.setattr("ion.web.elasticsearch_api.get_es_alerts", boom)
    resp = client.get("/ui/analyst/alerts")
    assert resp.status_code == 200
    assert "Alerts could not be read. This is not an empty queue" in resp.text
    assert "No alerts in the last 24 hours" not in resp.text
    assert "unavailable" in resp.text
    assert ">0</span>" not in resp.text
    assert "ES unknown" in resp.text
    assert "ES Connected" not in resp.text
    assert "ES Degraded" not in resp.text


def test_the_alerts_route_calls_the_json_endpoint_with_the_pages_window(
    client, monkeypatch
):
    """The service default limit is 50. The page asked for 500. Omitting
    the argument is a different queue, and the mock only sees what the
    route actually passed."""
    fake = _alerts(monkeypatch, {
        "alerts": [], "total": 0, "enabled": True, "configured": True,
    })
    resp = client.get("/ui/analyst/alerts")
    assert fake.kwargs["hours"] == 24
    assert fake.kwargs["limit"] == 500
    assert "No alerts in the last 24 hours" in resp.text
    assert inner(resp.text, "kpi-critical") == "0"
    assert inner(resp.text, "kpi-high") == "0"
    assert "ES Connected" in resp.text


@pytest.mark.parametrize("payload,label,css", [
    (
        {"alerts": [], "total": 0, "connection_error": True, "configured": True, "enabled": True},
        "ES Degraded",
        "bg-red-500/15 text-red-400",
    ),
    (
        {"alerts": [], "total": 0, "enabled": False},
        "ES Degraded",
        "bg-red-500/15 text-red-400",
    ),
    (
        {"alerts": [], "total": 0, "configured": False, "enabled": True},
        "ES Degraded",
        "bg-red-500/15 text-red-400",
    ),
    (
        {"alerts": [], "total": 0, "configured": "false", "enabled": "true", "connection_error": "yes"},
        "ES unknown",
        "bg-slate-500/15 text-slate-400",
    ),
    (
        {"alerts": [], "total": 0},
        "ES unknown",
        "bg-slate-500/15 text-slate-400",
    ),
])
def test_the_es_pill_keeps_three_states(client, monkeypatch, payload, label, css):
    """Defect: anything other than a clean payload, including a failed
    fetch, was 'ES Degraded'. A non-boolean flag is not a measurement.
    'Connected' must not be a substring of the other two labels."""
    _alerts(monkeypatch, payload)
    text = client.get("/ui/analyst/alerts").text
    assert label in text
    assert css in text
    assert 'id="es-status-pill"' in text
    if label != "ES Connected":
        assert "ES Connected" not in text
    if label != "ES Degraded":
        assert "ES Degraded" not in text


# ---------------------------------------------------------------------------
# Cases. The count is the query's, and zero alerts is a measurement.
# ---------------------------------------------------------------------------


def test_my_cases_are_the_callers_open_page_and_the_real_total(
    client, session, monkeypatch
):
    """Defect: the browser filtered the first page of every open case and
    used that filtered length as the KPI. Six of mine, the newest belonging
    to someone else, an acknowledged one of mine newer than all of them.
    Limit 5 drops the oldest of mine. The tile must say 6."""
    import ion.services.case_query_service as cq

    alice = _user(session, "alice")
    bob = _user(session, "bob")
    assert alice.id == 1
    base = datetime(2026, 1, 1)
    titles = {
        0: "OLDEST-DROPPED",
        1: "kept-1",
        2: "kept-2",
        3: "<script>alert(1)</script>",
        4: "kept-4",
        5: "NEWEST-KEPT",
    }
    for hour, title in titles.items():
        session.add(AlertCase(
            case_number=f"C-{hour}",
            title=title,
            status=AlertCaseStatus.OPEN,
            severity=None if hour == 5 else "high",
            created_by_id=alice.id,
            assigned_to_id=alice.id,
            created_at=base + timedelta(hours=hour),
        ))
    session.add(AlertCase(
        case_number="C-OTHER",
        title="OTHER-USER",
        status=AlertCaseStatus.OPEN,
        severity="high",
        created_by_id=alice.id,
        assigned_to_id=bob.id,
        created_at=base + timedelta(hours=100),
    ))
    session.add(AlertCase(
        case_number="C-ACK",
        title="ACK-MINE",
        status=AlertCaseStatus.ACKNOWLEDGED,
        severity="high",
        created_by_id=alice.id,
        assigned_to_id=alice.id,
        created_at=base + timedelta(hours=200),
    ))
    session.commit()

    seen = []
    real = cq.list_cases_page

    def wrapped(db, **kwargs):
        seen.append(kwargs)
        return real(db, **kwargs)

    monkeypatch.setattr(cq, "list_cases_page", wrapped)
    resp = client.get("/ui/analyst/cases")
    assert resp.status_code == 200
    assert seen and seen[0]["status"] == "open"
    assert seen[0]["assigned_to_id"] == alice.id
    assert seen[0]["limit"] == 5
    text = resp.text
    assert "OLDEST-DROPPED" not in text
    assert "OTHER-USER" not in text
    assert "ACK-MINE" not in text
    assert "kept-1" in text
    assert "NEWEST-KEPT" in text
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "AlertCaseStatus" not in text
    assert "acknowledged" not in text
    assert ">unknown<" in text
    assert "low" not in text
    assert "0 alerts" in text
    assert inner(text, "kpi-my-cases") == "6"
    assert "Open / Investigating" in text
    assert "<time" in text
    assert "1970" not in text


def test_a_missing_case_number_uses_the_id_and_a_missing_count_is_not_zero(
    client, monkeypatch
):
    """Defect: `c.alert_count || 0` and `c.case_number || '#' + c.id`. A
    count of None rendered as zero alerts. The service itself coerces None
    to 0, so only a direct stand-in can still produce None."""
    import ion.services.case_query_service as cq

    def page(_session, **_kwargs):
        return {"cases": [{
            "id": 9,
            "case_number": None,
            "title": "numbered",
            "severity": AlertCaseStatus.OPEN,
            "updated_at": None,
            "alert_count": None,
        }], "total": 1}

    monkeypatch.setattr(cq, "list_cases_page", page)
    text = client.get("/ui/analyst/cases").text
    assert "#9" in text
    assert "0 alerts" not in text
    assert "AlertCaseStatus" not in text
    assert ">open<" in text
    assert "1970" not in text
    assert "—" in text


def test_a_case_read_that_throws_is_not_an_empty_list(client, monkeypatch):
    import ion.services.case_query_service as cq

    def boom(_session, **_kwargs):
        raise RuntimeError("cases down")

    monkeypatch.setattr(cq, "list_cases_page", boom)
    resp = client.get("/ui/analyst/cases")
    assert resp.status_code == 200
    assert "Cases could not be read. This is not an empty list" in resp.text
    assert "No open cases assigned to you" not in resp.text
    assert inner(resp.text, "kpi-my-cases") == "unavailable"
    assert ">0</span>" not in resp.text


# ---------------------------------------------------------------------------
# MTTR and watched IOCs. Zero, none, and a thrown read.
# ---------------------------------------------------------------------------


def test_mttr_none_comes_from_the_metrics_function_and_is_not_zero_hours(
    client, monkeypatch
):
    """Defect: a missing mttr and a thrown read both became a blank, and a
    truthy check on the text '0h' cannot see that 0 was the input. An empty
    database has no closures, which is None. The spy fails a reimplementation
    that computes its own zero."""
    import ion.web.api as api

    calls = []
    real = api.team_metrics_payload

    def wrapped(db):
        calls.append(True)
        return real(db)

    monkeypatch.setattr(api, "team_metrics_payload", wrapped)
    resp = client.get("/ui/analyst/mttr")
    assert resp.status_code == 200
    assert calls
    assert "no closures in 30 days, so there is no average" in resp.text
    assert "0h" not in resp.text
    assert "unavailable" not in resp.text


def test_an_mttr_of_zero_is_zero_hours(client, monkeypatch):
    import ion.web.api as api

    monkeypatch.setattr(api, "team_metrics_payload", lambda _session: {"mttr_hours": 0})
    text = client.get("/ui/analyst/mttr").text
    assert "0h" in text
    assert "no closures" not in text
    assert "Avg hours (30d)" in text


def test_a_thrown_mttr_read_is_not_zero_hours(client, monkeypatch):
    import ion.web.api as api

    def boom(_session):
        raise RuntimeError("metrics down")

    monkeypatch.setattr(api, "team_metrics_payload", boom)
    resp = client.get("/ui/analyst/mttr")
    assert resp.status_code == 200
    assert "unavailable" in resp.text
    assert "could not be read, not zero hours" in resp.text
    assert "0h" not in resp.text
    assert "Avg hours (30d)" not in resp.text


def test_watched_is_the_stats_total_including_zero(client, monkeypatch):
    """Defect: `obsRes.watched || obsRes.total || 0`. The stats payload has
    no watched key, and calling the watched-list query would be a different
    number. A total of 0 from an empty database must render 0."""
    from ion.services.observable_service import ObservableService

    calls = []
    import ion.web.observable_api as obs_api

    real = obs_api.get_observable_stats

    def wrapped(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    def boom(self, *_args, **_kwargs):
        raise AssertionError("the watched list is not the stats total")

    monkeypatch.setattr(obs_api, "get_observable_stats", wrapped)
    monkeypatch.setattr(ObservableService, "get_watched_observables", boom)
    resp = client.get("/ui/analyst/watched")
    assert resp.status_code == 200
    assert calls
    assert ">0<" in resp.text
    assert "Observables tracked" in resp.text
    assert "count unknown" not in resp.text
    assert "unavailable" not in resp.text


def test_a_missing_or_boolean_observable_total_is_not_zero(client, monkeypatch):
    """True is an int. `total or 0` turns a missing key into 0 and would
    turn True into 1 if it were merely truthy."""
    import ion.web.observable_api as obs_api

    monkeypatch.setattr(obs_api, "get_observable_stats", lambda **_k: {})
    missing = client.get("/ui/analyst/watched")
    assert "count unknown" in missing.text
    assert ">0<" not in missing.text
    assert "unavailable" not in missing.text

    monkeypatch.setattr(
        obs_api, "get_observable_stats", lambda **_k: {"total": True}
    )
    flagged = client.get("/ui/analyst/watched")
    assert "count unknown" in flagged.text
    assert ">1<" not in flagged.text
    assert ">0<" not in flagged.text


def test_a_thrown_observable_read_is_not_zero(client, monkeypatch):
    import ion.web.observable_api as obs_api

    def boom(**_kwargs):
        raise RuntimeError("observables down")

    monkeypatch.setattr(obs_api, "get_observable_stats", boom)
    resp = client.get("/ui/analyst/watched")
    assert resp.status_code == 200
    assert "unavailable" in resp.text
    assert "could not be read, not zero" in resp.text
    assert ">0<" not in resp.text
    assert "Observables tracked" not in resp.text


# ---------------------------------------------------------------------------
# IOC lookup. Type, shape, three-state found, score bands.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,kind", [
    ("1.2.3.4", "ipv4-addr"),
    ("  1.2.3.4  ", "ipv4-addr"),
    ("2001:db8::1", "ipv6-addr"),
    ("a" * 64, "file-sha256"),
    ("A" * 40, "file-sha1"),
    ("ab" * 16, "file-md5"),
    ("https://example.com/a", "url"),
    ("http://example.com", "url"),
    ("a@b.c", "email-addr"),
    ("evil.example", "domain-name"),
    ("javascript:alert(1)", "domain-name"),
    ("1.2.3.4:80", "domain-name"),
])
def test_ioc_type_matches_the_opencti_map(value, kind):
    """The old lookup posted no type, so the endpoint 422d. javascript: is
    not a URL. Every inferred name has to be one the service will accept."""
    assert _ioc_type(value) == kind
    assert kind in OpenCTIService.TYPE_MAP


def test_the_lookup_sends_the_inferred_type_and_a_score_of_zero(client, monkeypatch):
    """Defect: the flat `data.score` missed the nested observable, and a
    truthy score hid zero. Labels are objects; stringifying them is
    '[object Object]'."""
    import ion.web.api as api

    seen = []

    async def fake(request_data, current_user=None):
        seen.append(request_data)
        return {
            "found": True,
            "observable": {"score": 0, "description": "nested"},
            "score": 71,
            "labels": [{"value": "apt29", "color": "#fff"}],
        }

    monkeypatch.setattr(api, "enrich_observable", fake)
    resp = client.post("/ui/analyst/ioc", data={"value": "1.2.3.4"})
    assert resp.status_code == 200
    assert seen[0].type == "ipv4-addr"
    assert seen[0].value == "1.2.3.4"
    assert "text-emerald-400\">0<" in resp.text
    assert "text-red-400" not in resp.text
    assert "apt29" in resp.text
    assert "[object Object]" not in resp.text
    assert "nested" in resp.text
    assert 'href="/observables?search=1.2.3.4"' in resp.text


@pytest.mark.parametrize("score,css", [
    (0, "text-emerald-400"),
    (40, "text-emerald-400"),
    (41, "text-amber-400"),
    (70, "text-amber-400"),
    (71, "text-red-400"),
])
def test_score_bands_are_strict(client, monkeypatch, score, css):
    """Defect: the bands are `> 70` and `> 40`. 40 and 70 sit on the lower
    side of each cut. A `>=` would colour both of them up a band."""
    import ion.web.api as api

    async def fake(request_data, current_user=None):
        return {"found": True, "score": score}

    monkeypatch.setattr(api, "enrich_observable", fake)
    text = client.post("/ui/analyst/ioc", data={"value": "evil.example"}).text
    assert f'{css}">{score}<' in text


def test_found_false_does_not_print_a_score_and_a_non_boolean_is_neither(
    client, monkeypatch
):
    """Three states. `found == false` was the old check, which is right,
    and a string "no" must not take the not-found branch or the hit branch.
    None alone would not catch a truthiness check: "no" is truthy."""
    import ion.web.api as api

    async def not_found(request_data, current_user=None):
        return {"found": False, "score": 80}

    monkeypatch.setattr(api, "enrich_observable", not_found)
    text = client.post("/ui/analyst/ioc", data={"value": "evil.example"}).text
    assert "No threat intelligence found for this indicator." in text
    assert "text-red-400" not in text
    assert ">80<" not in text

    async def murky(request_data, current_user=None):
        return {"found": "no", "score": 10}

    monkeypatch.setattr(api, "enrich_observable", murky)
    text = client.post("/ui/analyst/ioc", data={"value": "evil.example"}).text
    assert "The lookup did not say whether this indicator is known." in text
    assert "No threat intelligence found" not in text
    assert ">10<" not in text


def test_an_integration_error_is_the_error_not_a_failed_lookup(client, monkeypatch):
    """The JSON route returns 503 with a body when OpenCTI is off. htmx
    would not swap that status, so the fragment is 200 and says what the
    body said. 'Lookup failed' would claim the check did not run."""
    import ion.web.api as api

    async def disabled(request_data, current_user=None):
        return JSONResponse(
            status_code=503,
            content={"found": False, "error": "OpenCTI integration is not enabled"},
        )

    monkeypatch.setattr(api, "enrich_observable", disabled)
    resp = client.post("/ui/analyst/ioc", data={"value": "evil.example"})
    assert resp.status_code == 200
    assert "OpenCTI integration is not enabled" in resp.text
    assert "Lookup failed" not in resp.text
    assert "No threat intelligence found" not in resp.text


def test_a_thrown_lookup_names_itself_and_does_not_invent_a_score(client, monkeypatch):
    import ion.web.api as api

    async def boom(request_data, current_user=None):
        raise RuntimeError("opencti down")

    monkeypatch.setattr(api, "enrich_observable", boom)
    resp = client.post("/ui/analyst/ioc", data={"value": "evil.example"})
    assert resp.status_code == 200
    assert "Lookup failed. The check did not run, so there is no risk score rather than a score of zero." in resp.text
    assert ">0<" not in resp.text


def test_an_empty_value_is_a_bad_request_and_does_not_call_the_lookup(
    client, monkeypatch
):
    import ion.web.api as api

    called = []

    async def fake(request_data, current_user=None):
        called.append(True)
        return {"found": False}

    monkeypatch.setattr(api, "enrich_observable", fake)
    resp = client.post("/ui/analyst/ioc", data={"value": "   "})
    assert resp.status_code == 422
    assert called == []
    assert "Lookup failed" not in resp.text


def test_description_truncates_only_past_200_characters(client, monkeypatch):
    import ion.web.api as api

    async def exact(request_data, current_user=None):
        return {"found": True, "description": "a" * 200}

    monkeypatch.setattr(api, "enrich_observable", exact)
    exact_text = client.post("/ui/analyst/ioc", data={"value": "evil.example"}).text
    assert "a" * 200 in exact_text
    assert "..." not in exact_text

    async def over(request_data, current_user=None):
        return {"found": True, "description": "b" * 201}

    monkeypatch.setattr(api, "enrich_observable", over)
    over_text = client.post("/ui/analyst/ioc", data={"value": "evil.example"}).text
    assert "b" * 200 + "..." in over_text
    assert "b" * 201 not in over_text


def test_a_stored_observable_link_cannot_be_a_script_url(client, monkeypatch):
    """safe_url drops javascript: and protocol-relative URLs. The link is
    built as one value and then filtered, so the query is percent-encoded
    rather than spliced into the markup."""
    import ion.web.api as api

    async def hit(request_data, current_user=None):
        return {"found": True}

    monkeypatch.setattr(api, "enrich_observable", hit)
    script = client.post("/ui/analyst/ioc", data={"value": "<script>"})
    assert 'href="/observables?search=%3Cscript%3E"' in script.text
    assert "<script>" not in script.text

    js = client.post("/ui/analyst/ioc", data={"value": "javascript:alert(1)"})
    assert 'href="javascript:' not in js.text
    assert "javascript%3Aalert%281%29" in js.text

    proto = client.post("/ui/analyst/ioc", data={"value": "//evil.example"})
    assert 'href="//' not in proto.text
    assert "%2F%2Fevil.example" in proto.text


# ---------------------------------------------------------------------------
# Knowledge base. Browse, search, and a shelf are three claims.
# ---------------------------------------------------------------------------


def _collection(session, name, parent_id=None) -> Collection:
    row = Collection(name=name, parent_id=parent_id)
    session.add(row)
    session.flush()
    return row


def _doc(session, name, collection_id, body, **extra) -> Document:
    row = Document(
        name=name,
        collection_id=collection_id,
        rendered_content=body,
        output_format="markdown",
        **extra,
    )
    session.add(row)
    session.flush()
    return row


def test_topic_chips_ignore_zero_none_bools_and_numeric_strings():
    """Defect: `c.article_count > 0` is true for True, because bool is an
    int. A string count is not a count. Zero is an empty shelf, not a chip."""
    shown, hidden = _topic_chips([
        {"id": 1, "name": "nope-none", "article_count": None},
        {"id": 2, "name": "nope-zero", "article_count": 0},
        {"id": 3, "name": "nope-bool", "article_count": True},
        {"id": 4, "name": "nope-str", "article_count": "3"},
        {"id": 5, "name": "yes", "article_count": 2},
    ])
    assert [row["name"] for row in shown] == ["yes"]
    assert hidden == 0


def test_browse_uses_counts_and_six_recent_and_escapes_the_shelf_name(
    client, session, monkeypatch
):
    import ion.web.api as api

    parent = _collection(session, "Knowledge Base")
    shelf = _collection(session, "Alpha", parent.id)
    _doc(session, "Alpha article", shelf.id, "alpha body")
    _collection(session, "ZERO-COUNT", parent.id)
    _collection(session, "<script>alert(1)</script>", parent.id)
    # The script-named shelf needs an article or it is not a chip.
    script_shelf = session.query(Collection).filter_by(name="<script>alert(1)</script>").one()
    _doc(session, "script shelf article", script_shelf.id, "x")
    outsider = _collection(session, "Elsewhere")
    _doc(session, "SECRET-OUTSIDER", outsider.id, "SECRET-OUTSIDER body")
    session.commit()

    seen = []
    real = api.get_analyst_knowledge_base

    def wrapped(**kwargs):
        seen.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(api, "get_analyst_knowledge_base", wrapped)
    text = client.get("/ui/analyst/kb").text
    assert seen[0]["include_articles"] is False
    assert seen[0]["recent"] == 6
    assert "Alpha" in text
    assert "ZERO-COUNT" not in text
    assert "SECRET-OUTSIDER" not in text
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "Alpha article" in text
    assert "Knowledge Base not configured" not in text


def test_the_biggest_shelf_is_kept_when_thirteen_do_not_fit(client, session):
    """Defect: slicing the name-sorted list to 12 drops whichever shelf
    sorts last, which is the largest one when it is named last."""
    parent = _collection(session, "Knowledge Base")
    for i in range(1, 13):
        shelf = _collection(session, f"a{i:02d}", parent.id)
        # a12 is the shelf a name-sort would keep and a count-sort drops.
        # Its article is old so the recent list cannot smuggle the name
        # back in after the chip has been cut.
        when = datetime(2020, 1, 1) if i == 12 else datetime(2026, 6, i)
        _doc(
            session, f"doc-{i}", shelf.id, "body",
            created_at=when, updated_at=when,
        )
    big = _collection(session, "zzz-big", parent.id)
    # Two articles, so this shelf outranks every aNN shelf (one article)
    # even though its name sorts last.
    _doc(session, "big doc", big.id, "body")
    _doc(session, "big doc 2", big.id, "body")
    session.commit()
    text = client.get("/ui/analyst/kb").text
    assert "zzz-big" in text
    assert "a12" not in text
    assert "+1 more" in text
    assert 'href="/documents"' in text


def test_twelve_shelves_have_no_overflow_link(client, session):
    parent = _collection(session, "Knowledge Base")
    for i in range(1, 13):
        shelf = _collection(session, f"b{i:02d}", parent.id)
        _doc(session, f"doc-{i}", shelf.id, "body")
    session.commit()
    text = client.get("/ui/analyst/kb").text
    assert "b12" in text
    assert "+1 more" not in text


def test_an_unconfigured_library_is_not_an_empty_one(client, session):
    text = client.get("/ui/analyst/kb").text
    assert "Knowledge Base not configured" in text
    assert "No articles yet" not in text
    assert "Nothing updated yet" not in text


def test_an_empty_library_says_both_halves_are_empty(client, session):
    _collection(session, "Knowledge Base")
    session.commit()
    text = client.get("/ui/analyst/kb").text
    assert "No articles yet" in text
    assert "Nothing updated yet" in text
    assert "Knowledge Base not configured" not in text


def test_only_the_exact_not_found_status_means_unconfigured(client, monkeypatch):
    """Defect: any truthy status, or rendering the collections of a
    not_found payload. 'missing' is not 'not_found'. A shelf smuggled into
    a not_found payload is not a shelf."""
    import ion.web.api as api

    monkeypatch.setattr(
        api, "get_analyst_knowledge_base",
        lambda **_k: {"status": "missing", "collections": []},
    )
    missing = client.get("/ui/analyst/kb").text
    assert "Knowledge Base not configured" not in missing
    assert "No articles yet" in missing

    monkeypatch.setattr(
        api, "get_analyst_knowledge_base",
        lambda **_k: {
            "status": "not_found",
            "collections": [{"id": 1, "name": "SECRET-SHELF", "article_count": 4}],
        },
    )
    absent = client.get("/ui/analyst/kb").text
    assert "Knowledge Base not configured" in absent
    assert "SECRET-SHELF" not in absent


def test_a_short_query_browses_and_a_real_query_searches(client, session, monkeypatch):
    import ion.web.api as api

    parent = _collection(session, "Knowledge Base")
    shelf = _collection(session, "Alpha", parent.id)
    _doc(session, "Alpha article", shelf.id, "alpha body")
    session.commit()

    browses, searches = [], []
    real_browse = api.get_analyst_knowledge_base
    real_search = api.search_analyst_knowledge_base

    def browse(**kwargs):
        browses.append(kwargs)
        return real_browse(**kwargs)

    def search(**kwargs):
        searches.append(kwargs)
        return real_search(**kwargs)

    monkeypatch.setattr(api, "get_analyst_knowledge_base", browse)
    monkeypatch.setattr(api, "search_analyst_knowledge_base", search)

    short = client.get("/ui/analyst/kb", params={"q": " a "})
    assert "Alpha" in short.text
    assert "No articles found" not in short.text
    assert browses and not searches

    searches.clear()
    browses.clear()
    miss = client.get("/ui/analyst/kb", params={"q": "  ab "})
    assert miss.status_code == 200
    assert "No articles found" in miss.text
    assert "No articles yet" not in miss.text
    assert "Knowledge Base not configured" not in miss.text
    assert searches[0]["q"] == "ab"
    assert searches[0]["limit"] == 8
    assert searches[0]["collection_id"] is None
    assert not browses


def test_a_content_match_shows_its_snippet_and_a_title_match_does_not(
    client, session
):
    """Defect: every row rendered `a.snippet` whenever it was present. A
    title match whose body also contains the word would show the body, and
    the marker next to that word is how this fails."""
    parent = _collection(session, "Knowledge Base")
    shelf = _collection(session, "Shelf", parent.id)
    _doc(
        session, "ZebraTitle is the name", shelf.id,
        "prefix ZebraTitle UNIQUEBODYMARKER suffix",
    )
    _doc(
        session, "Ordinary title", shelf.id,
        "ContentNeedle UNIQUECONTENTMARKER",
    )
    session.commit()

    title = client.get("/ui/analyst/kb", params={"q": "ZebraTitle"}).text
    assert "ZebraTitle is the name" in title
    assert "UNIQUEBODYMARKER" not in title

    content = client.get("/ui/analyst/kb", params={"q": "ContentNeedle"}).text
    assert "UNIQUECONTENTMARKER" in content
    assert "Ordinary title" in content


def test_an_empty_shelf_is_204_and_an_outside_collection_is_not_listed(
    client, session, monkeypatch
):
    """Defect: a topic chip searched for the collection's name, and an
    empty result replaced the browse view. 204 leaves it standing. A
    collection id outside the knowledge base must not list that collection:
    the service falls back to the knowledge base's own children."""
    import ion.web.api as api

    parent = _collection(session, "Knowledge Base")
    empty = _collection(session, "Empty shelf", parent.id)
    outsider = _collection(session, "Elsewhere")
    _doc(session, "SECRET-OUTSIDER", outsider.id, "SECRET-OUTSIDER")
    session.commit()

    searches = []
    real = api.search_analyst_knowledge_base

    def wrapped(**kwargs):
        searches.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(api, "search_analyst_knowledge_base", wrapped)
    resp = client.get("/ui/analyst/kb", params={"collection_id": empty.id})
    assert resp.status_code == 204
    assert resp.text == ""
    assert searches[0]["q"] == ""
    assert searches[0]["collection_id"] == empty.id
    assert searches[0]["limit"] == 12

    leaked = client.get("/ui/analyst/kb", params={"collection_id": outsider.id})
    assert "SECRET-OUTSIDER" not in leaked.text

    found = client.get("/ui/analyst/kb", params={"q": "SECRET-OUTSIDER"})
    assert "No articles found" in found.text
    assert "SECRET-OUTSIDER" not in found.text


def test_a_knowledge_base_read_that_throws_is_not_an_empty_library(
    client, monkeypatch
):
    import ion.web.api as api

    def boom(**_kwargs):
        raise RuntimeError("library down")

    monkeypatch.setattr(api, "get_analyst_knowledge_base", boom)
    resp = client.get("/ui/analyst/kb")
    assert resp.status_code == 200
    assert "Knowledge base could not be read. This is not an empty library." in resp.text
    assert "No articles yet" not in resp.text
    assert "Knowledge Base not configured" not in resp.text


def test_an_unparseable_collection_id_is_a_bad_request(client):
    resp = client.get("/ui/analyst/kb", params={"collection_id": "abc"})
    assert resp.status_code == 422
    assert "could not be read" not in resp.text


# ---------------------------------------------------------------------------
# The page. Controls stay outside the swap, and the script builds no markup.
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    js = _script()
    assert js.strip(), "no inline script, so this proves nothing"
    assert "updateClock" in js
    assert "function analystRefresh(" in js
    assert "function kbBack(" in js
    assert not re.findall(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js)
    assert "function esc(" not in js
    assert "function loadWorkspace(" not in js
    assert "function doIOCLookup(" not in js
    assert "function loadKBBrowse(" not in js


def test_the_remaining_script_parses():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    completed = subprocess.run(
        [node, "--check", "-"],
        input=_script(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_controls_stay_outside_the_swap_target_and_the_initial_tiles_are_not_zero():
    """A control inside the fragment is removed by any render that omits it.
    Critical and high used to start at 0, which is a count, before anything
    had been read."""
    src = _page()
    assert src.index('id="analyst-refresh"') < src.index('id="priority-queue"')
    assert src.index('id="ioc-input"') < src.index('id="ioc-result"')
    assert src.index('id="kb-search"') < src.index('id="kb-content"')
    assert 'hx-post="/ui/analyst/ioc"' in src
    assert "doIOCLookup" not in src
    assert "data-enter-key-action" not in src
    refresh = _tag(src, "analyst-refresh")
    assert 'type="button"' in refresh
    assert 'data-click-action="analystRefresh"' in refresh
    result = _tag(src, "ioc-result")
    assert "hx-post" not in result
    for element_id in ("kpi-critical", "kpi-high"):
        tag_and_body = re.search(
            rf'id="{element_id}"[^>]*>\s*(.*?)\s*</span>', src, re.S
        )
        assert tag_and_body, element_id
        assert tag_and_body.group(1) != "0"
        assert ">0<" not in tag_and_body.group(0)


def test_the_knowledge_base_panel_includes_the_query_once():
    """hx-include is inherited. The panel needs it, or a reload sends no
    query; its children must not inherit it, or a topic chip sends the
    query as well as its collection id. Removing either half still leaves
    a substring the other test would pass."""
    src = _page()
    panel = _tag(src, "kb-content")
    assert 'hx-include="#kb-search"' in panel
    assert 'hx-disinherit="hx-include"' in panel
    box = _tag(src, "kb-search")
    assert 'name="q"' in box
    assert 'hx-trigger="input changed delay:250ms"' in box
    assert "[" not in box
    assert "hx-on" not in src
    assert "[key==" not in src
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_each_region_requests_its_own_fragment():
    src = _page()
    for path in (
        'hx-get="/ui/analyst/alerts"',
        'hx-get="/ui/analyst/cases"',
        'hx-get="/ui/analyst/mttr"',
        'hx-get="/ui/analyst/watched"',
        'hx-get="/ui/analyst/kb"',
        'hx-post="/ui/analyst/ioc"',
    ):
        assert path in src
    assert 'hx-trigger="load"' in _tag(src, "priority-queue")
    assert 'hx-trigger="load"' in _tag(src, "kpi-mttr")
    # The tile title is outside the swap, so a failed MTTR render cannot
    # remove the word MTTR. The swap target is the inner wrapper.
    assert src.index(">MTTR<") < src.index('id="kpi-mttr"')
    assert src.index(">Watched IOCs<") < src.index('id="kpi-watched"')
