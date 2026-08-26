"""v0.87.0 — analyst tuning requests (DE intake) + GitLab mirroring.

Covers:
- any analyst (alert:read) can raise a request; queue actions need de:propose,
- the DB row is authoritative: created even when GitLab is unconfigured,
- GitLab mirror: issue created with labels + iid/url stored; close comments
  and closes the issue; link-proposal comments,
- status flow open → triaged → linked → closed with invalid transitions 409,
- reason validation.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.tuning_request import TuningRequest
from ion.models.user import User
from ion.web.api import get_db_session
from ion.web.server import app


def _client(session, perms):
    user = User(id=1, username="analyst", email="a@x", password_hash="x",
                display_name="Analyst", is_active=True)
    user.has_permission = lambda p: p in perms  # type: ignore[method-assign]
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: session
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


class _FakeGitLab:
    def __init__(self, configured=True):
        self.is_configured = configured
        self.created = []
        self.comments = []
        self.closed = []
        self.create_issue = AsyncMock(side_effect=self._create)
        self.add_issue_comment = AsyncMock(side_effect=self._comment)
        self.close_issue = AsyncMock(side_effect=self._close)

    async def _create(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(iid=147, web_url="https://gitlab.local/soc/detections/-/issues/147")

    async def _comment(self, iid, body):
        self.comments.append((iid, body))

    async def _close(self, iid):
        self.closed.append(iid)


@pytest.fixture
def gitlab(monkeypatch):
    fake = _FakeGitLab()
    monkeypatch.setattr("ion.services.gitlab_service.get_gitlab_service", lambda: fake)
    return fake


def _create_payload(**over):
    payload = {
        "rule_name": "Suspicious PowerShell EncodedCommand",
        "reason": "false_positive",
        "details": "SCCM health script fires hourly on every host.",
        "example_alert_ids": ["es-alert-1"],
    }
    payload.update(over)
    return payload


def test_create_request_mirrors_to_gitlab(session, gitlab):
    r = _client(session, {"alert:read"}).post("/api/de/tuning-requests", json=_create_payload())
    assert r.status_code == 200, r.text
    req = r.json()["request"]
    assert req["status"] == "open"
    assert req["gitlab_issue_iid"] == 147
    assert "issues/147" in req["gitlab_issue_url"]
    assert req["example_alert_ids"] == ["es-alert-1"]
    # Issue carried the labels + the analyst's description.
    issue = gitlab.created[0]
    assert issue["labels"] == ["ion", "tuning-request", "false_positive"]
    assert "SCCM health script" in issue["description"]
    assert "Suspicious PowerShell EncodedCommand" in issue["title"]


def test_create_request_survives_gitlab_down(session, monkeypatch):
    monkeypatch.setattr(
        "ion.services.gitlab_service.get_gitlab_service",
        lambda: _FakeGitLab(configured=False),
    )
    r = _client(session, {"alert:read"}).post("/api/de/tuning-requests", json=_create_payload())
    assert r.status_code == 200
    req = r.json()["request"]
    assert req["gitlab_issue_iid"] is None
    assert session.get(TuningRequest, req["id"]) is not None


def test_create_request_invalid_reason(session, gitlab):
    r = _client(session, {"alert:read"}).post(
        "/api/de/tuning-requests", json=_create_payload(reason="because")
    )
    assert r.status_code == 400


def test_queue_actions_need_de_propose(session, gitlab):
    analyst = _client(session, {"alert:read"})
    req_id = analyst.post("/api/de/tuning-requests", json=_create_payload()).json()["request"]["id"]
    # Raising is open to analysts; working the queue is not.
    assert analyst.get("/api/de/tuning-requests").status_code == 403
    assert analyst.post(f"/api/de/tuning-requests/{req_id}/triage").status_code == 403
    assert analyst.post(
        f"/api/de/tuning-requests/{req_id}/close", json={"resolution": "x"}
    ).status_code == 403


def test_status_flow_and_gitlab_close(session, gitlab):
    de = _client(session, {"alert:read", "de:read", "de:propose"})
    req_id = de.post("/api/de/tuning-requests", json=_create_payload()).json()["request"]["id"]

    r = de.post(f"/api/de/tuning-requests/{req_id}/triage")
    assert r.status_code == 200 and r.json()["request"]["status"] == "triaged"
    # Re-triage is a 409, not a silent no-op.
    assert de.post(f"/api/de/tuning-requests/{req_id}/triage").status_code == 409

    r = de.post(
        f"/api/de/tuning-requests/{req_id}/close",
        json={"resolution": "excluded sccm-hc.ps1 signed script"},
    )
    assert r.status_code == 200 and r.json()["request"]["status"] == "closed"
    assert gitlab.closed == [147]
    assert any("excluded sccm-hc.ps1" in body for (_iid, body) in gitlab.comments)
    # Closing twice is a 409.
    assert de.post(
        f"/api/de/tuning-requests/{req_id}/close", json={"resolution": "again"}
    ).status_code == 409


def test_link_proposal_flow(session, gitlab):
    from ion.models.detection_proposal import DetectionProposal

    proposal = DetectionProposal(
        rule_name="Suspicious PowerShell EncodedCommand",
        change_type="exclusion", title="Exclude SCCM health script",
        suggested_change="exclude process.name sccm-hc.ps1", status="draft",
    )
    session.add(proposal)
    session.commit()

    de = _client(session, {"alert:read", "de:read", "de:propose"})
    req_id = de.post("/api/de/tuning-requests", json=_create_payload()).json()["request"]["id"]

    r = de.post(
        f"/api/de/tuning-requests/{req_id}/link-proposal",
        json={"proposal_id": proposal.id},
    )
    assert r.status_code == 200
    body = r.json()["request"]
    assert body["status"] == "linked" and body["proposal_id"] == proposal.id
    assert any(f"DP-{proposal.id:04d}" in c for (_iid, c) in gitlab.comments)
    # Unknown proposal → 404.
    assert de.post(
        f"/api/de/tuning-requests/{req_id}/link-proposal", json={"proposal_id": 99999}
    ).status_code == 404
    # Listing shows the request with evidence snapshot present.
    listed = de.get("/api/de/tuning-requests").json()["requests"]
    assert listed and listed[0]["id"] == req_id
