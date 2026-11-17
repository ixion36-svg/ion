"""GET /api/external/v1/rule-outcomes: what TIDE may read, and who may read it.

New attack surface reachable by a machine token, so these run the real
authentication path: tokens minted by AuthService, no get_current_user
override.
"""

import base64
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from ion.auth.service import AuthService
from ion.models.alert_triage import AlertCase, AlertCaseStatus, AlertTriage, AlertTriageStatus
from ion.models.user import User
from ion.services.rule_outcome_service import utcnow
from ion.storage.database import get_db_session
from ion.web.server import app

URL = "/api/external/v1/rule-outcomes"

ITEM_FIELDS = {
    "rule_id", "rule_name", "rule_uuids", "alerts", "closed", "outcomes",
    "fp_rate_pct", "tp_yield_pct", "median_seconds_to_close", "last_closed_at", "noisy",
}


@pytest.fixture
def auth(session):
    User.metadata.create_all(session.get_bind())
    svc = AuthService(session)
    svc.seed_permissions()
    svc.seed_roles()
    session.commit()
    app.dependency_overrides[get_db_session] = lambda: session
    yield svc
    app.dependency_overrides.clear()


def _service_token(svc, session, username, role_name):
    user = svc.seed_service_user(username, f"{username}@ion.local", username, role_name)
    session.commit()
    token = svc.mint_service_account_token(user.id, ttl_days=1)
    session.commit()
    return token


@pytest.fixture
def tide_token(auth, session):
    tide = auth.seed_tide_user()
    session.commit()
    token = auth.mint_service_account_token(tide.id, ttl_days=1)
    session.commit()
    return token


@pytest.fixture
def client():
    return TestClient(app)


def _get(client, token=None, **params):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get(URL, params=params, headers=headers)


def _close(session, n, rule_name, reason, *, rule_id=None, analyst=None, notes=None):
    case = AlertCase(case_number=f"C-{n}", title=f"case {n}", created_by_id=1,
                     status=AlertCaseStatus.CLOSED, closure_reason=reason,
                     closure_notes=notes, severity="high",
                     closed_by_id=analyst.id if analyst else None)
    case.closed_at = utcnow() - timedelta(days=1)
    session.add(case)
    session.flush()
    triage = AlertTriage(es_alert_id=f"alert-{n}", rule_name=rule_name, rule_id=rule_id,
                         rule_uuid=f"uuid-{rule_id}" if rule_id else None,
                         status=AlertTriageStatus.CLOSED, case_id=case.id,
                         analyst_notes=notes,
                         assigned_to_id=analyst.id if analyst else None)
    triage.created_at = case.closed_at - timedelta(hours=1)
    session.add(triage)
    session.commit()


# ── who may read ────────────────────────────────────────────────────────────


def test_no_key_is_refused(auth, client):
    assert _get(client).status_code == 401


def test_a_wrong_key_is_refused(auth, client, tide_token):
    assert _get(client, "not-" + tide_token).status_code == 401


def test_a_service_key_without_the_permission_is_refused(auth, client, session):
    metis = _service_token(auth, session, "metis", "metis")
    assert _get(client, metis).status_code == 403


def test_a_human_holding_the_permission_is_refused(auth, client, session):
    """Admins hold every permission; this surface is for integrations."""
    admin = auth.seed_admin_user(password="An-Adm1n-Pw-For-Tests-Only-77")
    admin.must_change_password = False
    auth.session_repo.create(user_id=admin.id, session_token="human-token",
                             expires_at=utcnow() + timedelta(hours=1))
    session.commit()
    assert admin.has_permission("rule_outcomes:read")

    resp = _get(client, "human-token")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Permission denied"


def test_the_tide_role_can_read_and_do_nothing_else(auth, client, tide_token):
    assert _get(client, tide_token).status_code == 200
    headers = {"Authorization": f"Bearer {tide_token}"}
    assert client.get("/api/de/metrics", headers=headers).status_code == 403
    assert client.get("/api/elasticsearch/alerts", headers=headers).status_code == 403


# ── what it returns ─────────────────────────────────────────────────────────


def test_a_rule_is_returned_keyed_on_its_id(auth, client, tide_token, session):
    for n in range(3):
        _close(session, n, "Brute Force", "false_positive", rule_id="r-bf")
    _close(session, 3, "Brute Force", "true_positive", rule_id="r-bf")

    body = _get(client, tide_token, rule_id="r-bf").json()

    assert body["schema_version"] == "ion.rule_outcomes.v1"
    [item] = body["items"]
    assert item["rule_id"] == "r-bf"
    assert item["closed"] == 4
    assert item["outcomes"]["false_positive"] == 3
    assert item["fp_rate_pct"] == 75.0
    assert item["rule_uuids"] == ["uuid-r-bf"]
    assert item["median_seconds_to_close"] == 3600


def test_a_rule_without_an_id_is_returned_by_name(auth, client, tide_token, session):
    _close(session, 1, "Custom Watcher", "false_positive")
    [item] = _get(client, tide_token).json()["items"]
    assert item["rule_id"] is None and item["rule_name"] == "Custom Watcher"


def test_no_analyst_name_or_note_leaves(auth, client, tide_token, session):
    analyst = User(username="alice.analyst", email="alice@corp.example",
                   display_name="Alice Analyst", password_hash="x")
    session.add(analyst)
    session.commit()
    _close(session, 1, "Brute Force", "false_positive", rule_id="r-bf",
           analyst=analyst, notes="SECRET-NOTE host srv-db-01 user bob")

    resp = _get(client, tide_token)
    assert resp.status_code == 200
    text = resp.text
    for leak in ("alice", "Alice", "corp.example", "SECRET-NOTE", "srv-db-01", "alert-1", "C-1"):
        assert leak not in text
    for item in resp.json()["items"]:
        assert set(item) == ITEM_FIELDS


def test_pagination_visits_every_rule_once_in_a_stable_order(auth, client, tide_token, session):
    for n, rule in enumerate(["r-c", "r-a", "r-e", "r-b", "r-d"]):
        _close(session, n, f"Rule {rule}", "false_positive", rule_id=rule)
    _close(session, 9, "Named Only", "true_positive")

    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 2}
        if cursor:
            params["cursor"] = cursor
        body = _get(client, tide_token, **params).json()
        seen += [i["rule_id"] or i["rule_name"] for i in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    whole = [i["rule_id"] or i["rule_name"] for i in _get(client, tide_token, limit=500).json()["items"]]
    assert seen == whole == ["r-a", "r-b", "r-c", "r-d", "r-e", "Named Only"]
    assert pages == 3


# ── bounds ──────────────────────────────────────────────────────────────────


def test_a_window_over_365_days_is_refused(auth, client, tide_token):
    resp = _get(client, tide_token, since="2025-01-01T00:00:00Z", until="2026-06-01T00:00:00Z")
    assert resp.status_code == 400


def test_the_window_is_applied(auth, client, tide_token, session):
    _close(session, 1, "Brute Force", "false_positive", rule_id="r-bf")
    before = (utcnow() - timedelta(days=30)).isoformat() + "Z"
    two_days_ago = (utcnow() - timedelta(days=2)).isoformat() + "Z"
    assert _get(client, tide_token, since=before, until=two_days_ago).json()["items"] == []
    assert len(_get(client, tide_token, since=before).json()["items"]) == 1


def test_a_forged_cursor_is_refused(auth, client, tide_token):
    assert _get(client, tide_token, cursor="%%%not-base64").status_code == 400
    bad_utf8 = base64.urlsafe_b64encode(b"\xff\xfe").decode()
    assert _get(client, tide_token, cursor=bad_utf8).status_code == 400


def test_a_limit_over_the_cap_is_refused(auth, client, tide_token):
    assert _get(client, tide_token, limit=501).status_code == 422
