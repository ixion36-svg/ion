import importlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.storage.database import get_db_session
from ion.web import api, case_lifecycle_api


@pytest.fixture
def client(monkeypatch):
    try:
        ui = importlib.import_module("ion.web.ui._cases_board")
    except ModuleNotFoundError as error:
        if error.name != "ion.web.ui._cases_board":
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    user = SimpleNamespace(has_permission=lambda permission: permission == "case:read")
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), ui, user


@pytest.mark.parametrize(
    "payload,state", [(None, "failed"), ({}, "failed"), ({"cases": [], "total": 0, "has_more": False}, "empty"), ({"cases": [{"id": 1, "title": "<unsafe>"}], "total": 1, "has_more": False}, "data")]
)
def test_board_read_outcomes(client, monkeypatch, payload, state):
    c, _, _ = client

    async def read(**kwargs):
        return payload

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    response = c.get("/ui/cases/board", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == state
    html = c.get("/ui/cases/board").text
    assert "<unsafe>" not in html
    if state == "failed":
        assert "could not be read" in html
        assert "No cases match" not in html


@pytest.mark.parametrize("mode,sort,order", [("newest", "created_at", "desc"), ("oldest", "created_at", "asc"), ("severity", "severity", "desc"), ("alerts", "created_at", "desc")])
def test_board_forwards_filters_and_bounded_page(client, monkeypatch, mode, sort, order):
    c, _, _ = client
    calls = []

    async def read(**kwargs):
        calls.append(kwargs)
        return {"cases": [], "total": 0, "has_more": False}

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    response = c.get("/ui/cases/board", params={"status": "open", "severity": "high", "assigned_to_id": 9, "q": 'quoted " title', "mode": mode, "limit": 12, "offset": 24})
    assert response.status_code == 200
    assert len(calls) == 1
    assert {key: calls[0][key] for key in ["status", "severity", "assigned_to_id", "q", "sort", "order", "limit", "offset"]} == {
        "status": "open",
        "severity": "high",
        "assigned_to_id": 9,
        "q": 'quoted " title',
        "sort": sort,
        "order": order,
        "limit": 12,
        "offset": 24,
    }
    if mode == "alerts":
        assert "Newest first" in response.text


@pytest.mark.parametrize("field", ["alert_count", "affected_hosts", "affected_users", "observables_count"])
@pytest.mark.parametrize("value", [None, 0, [], ["one", "two"]])
def test_counts_preserve_missing_and_zero(client, monkeypatch, field, value):
    c, _, _ = client

    async def read(**kwargs):
        return {"cases": [{"id": 1, field: value}], "total": 1, "has_more": False}

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    response = c.get("/ui/cases/board", headers={"Accept": "application/json"})
    assert response.status_code == 200
    expected = None if value is None else len(value) if isinstance(value, list) else value
    assert response.json()["cards"][0]["counts"][field] == expected
    html = c.get("/ui/cases/board").text
    assert ('data-count="' + field + '">' + ("—" if expected is None else str(expected))) in html


@pytest.mark.parametrize("hours,band", [(23, "fresh"), (24, "normal"), (72, "stale"), (168, "old")])
def test_age_band_reads_zoneless_utc(client, monkeypatch, hours, band):
    c, ui, _ = client
    now = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)
    if hasattr(ui, "utc_now"):
        monkeypatch.setattr(ui, "utc_now", lambda: now)

    async def read(**kwargs):
        return {"cases": [{"id": 1, "created_at": (now - timedelta(hours=hours)).replace(tzinfo=None).isoformat()}], "total": 1, "has_more": False}

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    response = c.get("/ui/cases/board", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["cards"][0]["age_band"] == band
    assert response.json()["cards"][0]["created_label"].endswith(" UTC")


@pytest.mark.parametrize("value", [None, "not a date"])
def test_unknown_dates_are_not_old(client, monkeypatch, value):
    c, _, _ = client

    async def read(**kwargs):
        return {"cases": [{"id": 1, "created_at": value}], "total": 1, "has_more": False}

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    response = c.get("/ui/cases/board", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["cards"][0]["age_band"] == "unknown"
    assert response.json()["cards"][0]["age"] is None


def test_case_reader_cannot_read_assignees_without_alert_read(client, monkeypatch):
    c, _, _ = client

    async def forbidden(**kwargs):
        pytest.fail("picker source called without alert:read")

    monkeypatch.setattr(api, "list_assignable_users", forbidden)
    response = c.get("/ui/cases/assignees", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert response.json()["state"] == "withheld"
    assert response.json()["users"] is None
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(c.get("/ui/cases/assignees").text, "html.parser")
    assert soup.select_one("#filter-assignee").has_attr("disabled")
    assert soup.select_one("#filter-assignee option")["value"] == ""


def test_assignee_option_values_are_ids(client, monkeypatch):
    from bs4 import BeautifulSoup

    c, _, user = client
    user.has_permission = lambda permission: True

    async def read(**kwargs):
        return {"users": [{"id": 9, "username": 'name"quoted', "display_name": "Person <safe>", "has_elastic_profile": False}]}

    monkeypatch.setattr(api, "list_assignable_users", read)
    response = c.get("/ui/cases/assignees")
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one('#filter-assignee option[value="9"]').text == "Person <safe>"
    assert soup.select_one('#new-case-assignee option[value="9"]') is not None


def test_board_permission_and_write_controls(client, monkeypatch):
    c, ui, user = client

    async def read(**kwargs):
        return {"cases": [{"id": 1, "status": "open"}], "total": 1, "has_more": False}

    monkeypatch.setattr(case_lifecycle_api, "list_cases", read)
    assert "panelUpdateField" not in c.get("/ui/cases/board").text
    user.has_permission = lambda permission: True
    assert "panelUpdateField" in c.get("/ui/cases/board").text
    if hasattr(ui, "READ"):

        def denied():
            raise HTTPException(403, "Forbidden")

        c.app.dependency_overrides[ui.READ] = denied
    assert c.get("/ui/cases/board").status_code == 403
