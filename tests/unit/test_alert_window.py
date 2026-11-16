"""The alert window: an alert on /alerts opens in the workspace window a case
opens in, and has an address of its own.

Before this, /alerts opened an alert in a 1180px modal, and /alerts/{row_id}
redirected to /alerts?selected=<id>, a parameter nothing on the page read, so
a link to an alert opened the queue and no alert.

Three things are pinned here:

  * GET /api/elasticsearch/alerts/{id}/detail returns one alert in the shape
    the queue returns it, because an alert opened by URL need not be inside
    the time window the queue loaded.
  * /alerts/{alert_id} renders the page with that alert named for the script,
    and /alerts/{row_id} redirects to it.
  * The page opens an alert through the shared workspace chrome and no longer
    carries the modal.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

import ion.web.elasticsearch_api as es_api
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.services.elasticsearch_service import ElasticsearchError

ROOT = Path(__file__).resolve().parents[2]
PAGE = (ROOT / "src/ion/web/templates/alerts.html").read_text(encoding="utf-8")
WINDOW_JS = (ROOT / "src/ion/web/static/js/alerts-window.js").read_text(encoding="utf-8")
PAGE_CSS = (ROOT / "src/ion/web/static/css/alerts-page.css").read_text(encoding="utf-8")


class _User:
    id = 1
    username = "window-tester"

    def __init__(self, *permissions: str):
        self.permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self.permissions


class _Alert:
    """What the service returns: only the parts _alert_dicts reads."""

    def __init__(self, alert_id: str, raw: dict | None = None, source_system: str | None = None):
        self.id = alert_id
        self.raw_data = raw or {}
        self.source_system = source_system

    def to_dict(self, include_raw: bool = True) -> dict:
        out: dict[str, Any] = {"id": self.id, "title": "Encoded PowerShell", "severity": "high"}
        if include_raw:
            out["raw_data"] = self.raw_data
        return out


@pytest.fixture
def service(monkeypatch):
    class Stub:
        is_configured = True
        alerts: list = []
        raise_: Exception | None = None
        asked: list = []

        async def get_alerts_by_ids(self, ids):
            Stub.asked.append(list(ids))
            if Stub.raise_:
                raise Stub.raise_
            return Stub.alerts

    Stub.alerts, Stub.raise_, Stub.asked, Stub.is_configured = [], None, [], True
    monkeypatch.setattr(es_api, "get_elasticsearch_service", lambda: Stub())
    monkeypatch.setattr(es_api, "get_elasticsearch_config", lambda: {"enabled": True})
    return Stub


def _detail(alert_id: str, session) -> dict:
    return asyncio.run(es_api.get_alert_detail(alert_id, current_user=_User("alert:read"), session=session))


# ---------------------------------------------------------------------------
# GET /api/elasticsearch/alerts/{id}/detail
# ---------------------------------------------------------------------------

def test_one_alert_is_returned_in_the_queue_shape_without_its_raw_document(session, service):
    service.alerts = [_Alert("abc", raw={"source": {"ip": "10.0.0.5"}})]
    alert = _detail("abc", session)["alert"]
    assert service.asked == [["abc"]]
    assert alert["id"] == "abc" and alert["title"] == "Encoded PowerShell"
    # The queue drops raw_data and extracts observables from it first; an
    # alert opened by URL has to match, or its window would differ from the
    # same alert opened from the queue.
    assert "raw_data" not in alert
    assert isinstance(alert["observables"], list)


def test_the_queue_and_the_single_read_build_the_dict_with_one_function(session, service):
    """One alert through the list helper equals the single read, so the two
    cannot drift into two definitions of an alert."""
    service.alerts = [_Alert("abc", raw={"host": {"name": "ws-01"}})]
    single = _detail("abc", session)["alert"]
    listed = es_api._alert_dicts(session, service.alerts)
    es_api._annotate_alert_dicts(session, listed)
    assert single == listed[0]


def test_an_id_that_matches_nothing_is_a_404_not_an_empty_alert(session, service):
    with pytest.raises(HTTPException) as caught:
        _detail("missing", session)
    assert caught.value.status_code == 404


def test_an_unreachable_elasticsearch_is_not_reported_as_a_missing_alert(session, service):
    service.raise_ = ElasticsearchError("Connection refused")
    with pytest.raises(HTTPException) as caught:
        _detail("abc", session)
    assert caught.value.status_code == 502


def test_an_unconfigured_elasticsearch_is_a_503(session, service):
    service.is_configured = False
    with pytest.raises(HTTPException) as caught:
        _detail("abc", session)
    assert caught.value.status_code == 503
    assert service.asked == []


def test_a_lab_fixture_is_answered_from_its_triage_row_without_elasticsearch(session, service):
    """Lab fixtures have no Elasticsearch document by design, and a closed
    one is still an alert someone can be linked to."""
    service.is_configured = False
    session.add(AlertTriage(es_alert_id="lab-fixture-7", rule_name="Lab rule",
                            status=AlertTriageStatus.CLOSED))
    session.commit()
    alert = _detail("lab-fixture-7", session)["alert"]
    assert alert["id"] == "lab-fixture-7" and alert["is_lab_fixture"] is True
    assert service.asked == []


def test_an_unknown_lab_fixture_is_a_404(session, service):
    with pytest.raises(HTTPException) as caught:
        _detail("lab-fixture-nope", session)
    assert caught.value.status_code == 404


def test_the_single_read_is_registered_and_gated_on_alert_read():
    route = next(r for r in es_api.router.routes
                 if getattr(r, "path", "") == "/elasticsearch/alerts/{alert_id}/detail")
    assert route.methods == {"GET"}
    # /elasticsearch/alerts/cases is another router's path. A bare
    # /elasticsearch/alerts/{alert_id} would have answered it.
    assert not any(getattr(r, "path", "") == "/elasticsearch/alerts/{alert_id}"
                   for r in es_api.router.routes)


# ---------------------------------------------------------------------------
# /alerts/{alert_id} and /alerts/{row_id}
# ---------------------------------------------------------------------------

@pytest.fixture
def rendered(monkeypatch):
    import ion.web.server as server

    calls: list = []

    def template_response(request, name, context):
        calls.append({"name": name, "context": context})
        return calls[-1]

    monkeypatch.setattr(server, "templates", SimpleNamespace(TemplateResponse=template_response))
    monkeypatch.setattr(server, "get_config", lambda: SimpleNamespace(
        alert_detail_v2=True, alert_field_pins=False, bob_custom_templates=True))
    return calls


def test_the_alert_page_renders_the_alerts_template_naming_the_alert(rendered):
    import ion.web.server as server

    asyncio.run(server.alert_page("abc123", request=object(), user=_User("alert:read", "case:create")))
    (call,) = rendered
    assert call["name"] == "alerts.html"
    assert call["context"]["initial_alert_id"] == "abc123"
    # The same facts about the viewer the queue page passes, or the window at
    # its own address would offer a create-case form the queue page withholds.
    assert call["context"]["can_create_case"] is True
    assert call["context"]["can_read_playbooks"] is False
    assert call["context"]["alert_detail_v2"] is True


def test_the_queue_page_names_no_alert(rendered):
    import ion.web.server as server

    asyncio.run(server.alerts_page(request=object(), user=_User("alert:read", "playbook:read")))
    (call,) = rendered
    assert "initial_alert_id" not in call["context"]
    assert call["context"]["can_read_playbooks"] is True
    assert call["context"]["can_create_case"] is False


def test_a_triage_row_link_redirects_to_the_alerts_own_page(session, monkeypatch):
    import ion.storage.database as database
    import ion.web.server as server

    row = AlertTriage(es_alert_id="abc/1 2", status=AlertTriageStatus.OPEN)
    session.add(row)
    session.commit()
    monkeypatch.setattr(database, "get_session", lambda: iter([session]))

    found = asyncio.run(server.alert_deeplink(row.id, user=_User("alert:read")))
    assert found.status_code == 303
    # Quoted, so an id with a slash stays one path segment.
    assert found.headers["location"] == "/alerts/abc%2F1%202"

    monkeypatch.setattr(database, "get_session", lambda: iter([session]))
    absent = asyncio.run(server.alert_deeplink(row.id + 999, user=_User("alert:read")))
    assert absent.headers["location"] == "/alerts"


def test_the_integer_route_is_registered_before_the_string_route():
    """Starlette takes the first match, and {alert_id} matches digits too."""
    import ion.web.server as server

    paths = [getattr(r, "path", "") for r in server.app.routes]
    assert paths.index("/alerts/{row_id:int}") < paths.index("/alerts/{alert_id}")


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

def _window_markup() -> str:
    start = PAGE.index('id="alert-window"')
    start = PAGE.rindex("<div", 0, start)
    return PAGE[start:PAGE.index("</div><!-- /ion-tw inner wrapper -->")]


def test_the_alert_opens_in_the_shared_workspace_chrome_not_a_modal():
    assert "alert-detail-modal" not in PAGE
    markup = _window_markup()
    for cls in ("ion-ws-panel", "ion-ws-header", "ion-ws-eyebrow", "ion-ws-title",
                "ion-ws-close", "ion-ws-body"):
        assert cls in markup, cls
    assert 'class="ion-ws-overlay" id="alert-window-overlay"' in PAGE
    # The component mounts into this id on /alerts; it did before too.
    assert 'class="ion-ws-body" id="alert-detail-body"' in markup


def test_the_window_has_prev_and_next_bound_to_the_step_action():
    markup = _window_markup()
    prev = re.search(r'<button[^>]*id="alert-window-prev"[^>]*>', markup).group(0)
    nxt = re.search(r'<button[^>]*id="alert-window-next"[^>]*>', markup).group(0)
    assert 'data-click-action="alertWindowStep"' in prev and 'data-args="[-1]"' in prev
    assert 'data-click-action="alertWindowStep"' in nxt and 'data-args="[1]"' in nxt
    # Disabled until the script knows where the alert sits in the queue.
    assert " disabled" in prev and " disabled" in nxt
    assert "window.alertWindowStep = step" in WINDOW_JS


def test_page_mode_is_decided_by_the_server_and_carried_as_data():
    markup = _window_markup()
    assert "{% if initial_alert_id %} page-mode open{% endif %}" in markup
    assert 'data-initial-alert-id="{{ initial_alert_id or \'\' }}"' in markup
    assert "{% if initial_alert_id %} alerts-single{% endif %}" in PAGE
    assert re.search(r"\.alerts-single\s*>\s*:not\(#alert-window\)\s*\{\s*display:\s*none", PAGE_CSS)
    # No Jinja inside the script block: the id is read from the attribute.
    assert "dataset.initialAlertId" in PAGE


def test_the_window_script_loads_before_the_inline_script_that_mounts_it():
    assert PAGE.index("/static/js/alerts-window.js") < PAGE.index("ionAlertWindow.mount(")


def test_an_alert_outside_the_loaded_queue_is_read_on_its_own():
    fn = PAGE[PAGE.index("async function showAlertDetail"):]
    fn = fn[:fn.index("\n}")]
    assert "findAlert(alertId) || await fetchAlertById(alertId)" in fn
    assert "ionAlertWindow.show(alert)" in fn
    fetcher = PAGE[PAGE.index("async function fetchAlertById"):]
    fetcher = fetcher[:fetcher.index("\n}")]
    assert "/detail`" in fetcher and "encodeURIComponent(alertId)" in fetcher
    # A failed read is said in the window rather than doing nothing.
    assert "ionAlertWindow.fail(reason)" in fetcher


def test_the_queue_keyboard_stands_down_while_the_window_is_open():
    blocked = PAGE[PAGE.index("isBlocked: () =>"):]
    blocked = blocked[:blocked.index("),") + 2]
    assert "#alert-window.open" in blocked


def test_the_window_script_keeps_the_address_and_the_position_in_step():
    assert "'/alerts/' + encodeURIComponent(alert.id)" in WINDOW_JS
    # Closing over the queue restores its address; at /alerts/{id} it leaves.
    hide = WINDOW_JS[WINDOW_JS.index("function hide()"):]
    hide = hide[:hide.index("\n  }")]
    assert "window.location.assign('/alerts')" in hide and "setAddress('/alerts')" in hide
    assert "if (!isOpen()) return;" in hide
    # No page globals: everything comes through the mounted host.
    for name in ("allAlerts", "filteredAlerts", "currentDetailAlert"):
        assert name not in WINDOW_JS, name
