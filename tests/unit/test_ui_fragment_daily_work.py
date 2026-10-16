"""Personal and team worklogs must distinguish failed reads from quiet days."""
import re
from datetime import date, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from ion.auth.dependencies import get_current_user
from ion.services import worklog_service
from ion.web.templating import make_templates
from ion.web.ui import daily_work as page


def user(*permissions):
    return SimpleNamespace(id=12, username="analyst", has_permission=lambda p: p in permissions)


def payload(**overrides):
    return dict({"user": {"name": "Analyst"}, "date": "2026-10-12", "items": [],
                 "summary": {"triaged": 0, "closed": None, "logged": 0, "cases_touched": 0,
                             "active_span": "0h 00m"}}, **overrides)


def entry(**overrides):
    return dict({"id": 1, "source": "logged", "type": "note", "time": "00:00",
                 "timestamp": datetime(2026, 10, 12), "text": "A note"}, **overrides)


def render(data):
    return make_templates().env.get_template("_fragments/daily_work.html").render(payload=page.day_view(data, []))


def request():
    return Request({"type": "http", "path": "/ui/daily-work", "headers": []})


def test_zero_counts_missing_counts_and_zero_duration_stay_distinct():
    html = render(payload())
    assert '>0</div>' in html
    assert '>Unknown</div>' in html
    assert '>0h 00m</div>' in html
    assert "No activity logged for this day" in html


def test_auto_entries_cannot_be_edited_and_midnight_is_valid():
    html = render(payload(items=[entry(), entry(id=2, source="auto", text="Automatic")]))
    assert html.count('data-entry-id="1"') == 1
    assert 'data-ts-local="no"' in html
    assert 'datetime="2026-10-12T00:00:00"' in html
    assert len(re.findall(r'class="dw-cal-item dw-editable"', html)) == 1


def test_unknown_time_is_not_silently_midnight():
    result = page.day_view(payload(items=[entry(time=None, timestamp=None)]), [])
    assert not any(result["hours"].values())
    assert len(result["items"]) == 1
    assert "Time unknown" in render(payload(items=[entry(time=None, timestamp=None)]))


def test_stored_text_is_escaped_in_markup_and_edit_attributes():
    html = render(payload(items=[entry(text='<script>alert(1)</script>')]))
    assert '<script>alert(1)</script>' not in html
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html


def test_day_route_reuses_user_scoped_reader_and_filter(monkeypatch):
    reader = Mock(return_value=payload())
    monkeypatch.setattr(page, "get_my_day", reader)
    monkeypatch.setattr(worklog_service, "get_task_types", lambda s: [])
    caller, session = user("alert:read"), object()
    response = page.day(request(), date="2026-10-12", user=caller, session=session)
    reader.assert_called_once_with(date="2026-10-12", current_user=caller, session=session)
    assert response.status_code == 200


def test_failed_day_route_prints_no_measurements(monkeypatch, caplog):
    monkeypatch.setattr(page, "get_my_day", Mock(side_effect=RuntimeError("offline")))
    html = page.day(request(), user=user("alert:read"), session=object()).body.decode()
    assert "worklog could not be read" in html
    assert "No activity logged" not in html and "stat-value" not in html
    assert any(r.exc_info for r in caplog.records)


def test_team_controls_are_withheld_without_security_read(monkeypatch):
    monkeypatch.setattr(worklog_service, "get_task_types", lambda s: [])
    for permissions, expected in [(('alert:read',), False), (('alert:read', 'security:read'), True)]:
        html = page.controls(request(), user=user(*permissions), session=object()).body.decode()
        assert ('data-view="team"' in html) is expected


def test_team_failure_is_not_an_empty_board(monkeypatch, caplog):
    monkeypatch.setattr(worklog_service, "get_team_today", Mock(side_effect=RuntimeError("offline")))
    html = page.team(request(), user=user("security:read"), session=object()).body.decode()
    assert "team worklog could not be read" in html
    assert "No analyst activity" not in html
    assert any(r.exc_info for r in caplog.records)


def test_task_type_failure_has_no_add_controls(monkeypatch):
    monkeypatch.setattr(worklog_service, "get_task_types", Mock(side_effect=RuntimeError("offline")))
    html = page.controls(request(), user=user("alert:read"), session=object()).body.decode()
    assert "Task types could not be read" in html
    assert 'id="dw-add"' not in html


@pytest.mark.parametrize("reader", ["_manual_items", "_case_items", "_investigation_items", "_audit_items"])
def test_source_query_failures_propagate_instead_of_faking_quiet_days(reader):
    session = Mock()
    session.query.side_effect = RuntimeError("source offline")
    with pytest.raises(RuntimeError, match="source offline"):
        getattr(worklog_service, reader)(session, 12, datetime(2026, 10, 12), datetime(2026, 10, 13))


def test_team_user_query_failure_propagates():
    session = Mock()
    session.query.side_effect = RuntimeError("users offline")
    with pytest.raises(RuntimeError, match="users offline"):
        worklog_service.get_team_today(session, date(2026, 10, 12))


def test_service_preserves_timestamp_instead_of_only_wall_clock(monkeypatch):
    stamp = datetime(2026, 10, 12)
    monkeypatch.setattr(worklog_service, "_manual_items", lambda *a: [dict(entry(), ts=stamp, ref=None)])
    for name in ("_case_items", "_investigation_items", "_audit_items"):
        monkeypatch.setattr(worklog_service, name, lambda *a: [])
    result = worklog_service.get_day_activity(object(), 12, date(2026, 10, 12))
    assert result['items'][0]['timestamp'] == stamp
    assert 'ts' not in result['items'][0]


def test_team_current_assignment_failure_propagates(monkeypatch):
    session = Mock()
    session.query.return_value.filter.return_value.all.return_value = [SimpleNamespace(id=12)]
    session.query.return_value.filter.return_value.filter.return_value.order_by.return_value.first.side_effect = RuntimeError("assignment offline")
    monkeypatch.setattr(worklog_service, "get_day_activity", lambda *a: {"items": [entry()], "summary": {}})
    with pytest.raises(RuntimeError, match="assignment offline"):
        worklog_service.get_team_today(session, date(2026, 10, 12))


def test_team_permission_is_harder_than_personal_read(monkeypatch):
    app = FastAPI()
    app.include_router(page.router, prefix="/ui")
    client = TestClient(app)
    for path in ('/ui/daily-work', '/ui/daily-work/controls', '/ui/daily-work/team'):
        assert client.get(path).status_code == 401
    app.dependency_overrides[get_current_user] = lambda: user("alert:read")
    assert client.get('/ui/daily-work/team').status_code == 403
    monkeypatch.setattr(worklog_service, "get_task_types", lambda s: [])
    assert client.get('/ui/daily-work/controls').status_code == 200


def test_retry_date_and_modes_are_outside_swapped_day():
    source = (Path(__file__).parents[2] / 'src/ion/web/templates/daily_work.html').read_text(encoding='utf-8')
    source = re.sub(r'<!--.*?-->|\{#.*?#\}', '', source, flags=re.S)
    before, after = source.split('<div id="dw-day-content"', 1)
    assert 'id="dw-refresh"' in before and 'id="dw-date"' in before
    assert 'hx-include="#dw-date"' in after.split('>', 1)[0]
    assert '.innerHTML' not in source and 'function esc(' not in source
    assert '"dayRequested"' in source and '"teamRequested"' in source
