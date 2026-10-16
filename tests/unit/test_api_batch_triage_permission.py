"""The batch triage endpoint's write, and who is allowed to cause it.

POST /api/elasticsearch/alerts-triage/batch reads triage rows for a list of
alert ids. When the caller also sends `es_statuses` it does something else:
it reconciles Kibana's view of each alert's status into ION, updating
AlertTriage rows and inserting new ones. That is a write, and the endpoint
is gated on `alert:read`.

Two seeded roles hold `alert:read` without `alert:triage`:

  forensic   Forensic Investigator
  metis      the METIS service account, whose own comment in
             auth/service.py says it is "scoped to read + propose only"
             with approval "reserved for human reviewers"

So a token deliberately denied triage could set any alert's triage status,
and create triage rows that did not exist, by naming them in es_statuses.

The read is not the problem and must keep working: alerts.html's
loadTriageBatch sends es_statuses on every page load for every viewer, and
answering a read-only viewer with a 403 would take the triage map away from
the queue. The sync is skipped for them instead, and the response says so
rather than leaving a requested reconciliation silently undone.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.models.alert_triage import AlertTriage, AlertTriageStatus

READ = "alert:read"
TRIAGE = "alert:triage"
PATH = "/api/elasticsearch/alerts-triage/batch"


class _User:
    id = 1
    username = "batch-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions

    def has_any_permission(self, names):
        return any(n in self.permissions for n in names)


def _app(session, user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web.api import router

    application = FastAPI()
    application.include_router(router, prefix="/api")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: session
    return application


def client(session, *permissions):
    return TestClient(_app(session, _User(*permissions)))


def seed(session, alert_id, status=AlertTriageStatus.OPEN):
    row = AlertTriage(es_alert_id=alert_id, status=status)
    session.add(row)
    session.commit()
    return row


def status_of(session, alert_id):
    row = (session.query(AlertTriage)
           .filter(AlertTriage.es_alert_id == alert_id).one_or_none())
    if row is None:
        return None
    return row.status.value if hasattr(row.status, "value") else str(row.status)


def post(cli, **body):
    return cli.post(PATH, json=body)


# ---------------------------------------------------------------------------
# A reader must not be able to write
# ---------------------------------------------------------------------------


def test_a_reader_cannot_change_an_alerts_triage_status(session):
    """The escalation. alert:read is "View and search alerts"; moving an
    alert to closed is triage."""
    seed(session, "a1", AlertTriageStatus.OPEN)
    with client(session, READ) as cli:
        res = post(cli, alert_ids=["a1"], es_statuses={"a1": "closed"})
    assert res.status_code == 200
    session.expire_all()
    assert status_of(session, "a1") == "open"


def test_a_reader_cannot_create_a_triage_row_that_did_not_exist(session):
    """The other half of the sync inserts. A reader naming an unknown alert
    id with a non-open status wrote a new AlertTriage row."""
    with client(session, READ) as cli:
        post(cli, alert_ids=["new1"], es_statuses={"new1": "acknowledged"})
    session.expire_all()
    assert status_of(session, "new1") is None


def test_the_reader_still_gets_the_triage_map(session):
    """The fix must not answer 403. loadTriageBatch sends es_statuses for
    every viewer and drops the whole response on a non-ok status, so a 403
    would silently empty the queue's triage column for a forensic user."""
    seed(session, "a1", AlertTriageStatus.ACKNOWLEDGED)
    with client(session, READ) as cli:
        res = post(cli, alert_ids=["a1"], es_statuses={"a1": "closed"})
    assert res.status_code == 200
    assert res.json()["triage"]["a1"]["status"] == "acknowledged"


def test_a_skipped_sync_is_reported_rather_than_silent(session):
    """A caller that asked for a reconciliation and did not get one is told,
    instead of being left to assume ION now agrees with Kibana."""
    seed(session, "a1")
    with client(session, READ) as cli:
        body = post(cli, alert_ids=["a1"], es_statuses={"a1": "closed"}).json()
    assert body["synced"] is False


# ---------------------------------------------------------------------------
# A triager must still be able to
# ---------------------------------------------------------------------------


def test_a_triager_syncs_an_existing_row(session):
    seed(session, "a1", AlertTriageStatus.OPEN)
    with client(session, READ, TRIAGE) as cli:
        body = post(cli, alert_ids=["a1"], es_statuses={"a1": "closed"}).json()
    session.expire_all()
    assert status_of(session, "a1") == "closed"
    assert body["synced"] is True


def test_a_triager_creates_the_row_a_non_open_status_implies(session):
    with client(session, READ, TRIAGE) as cli:
        post(cli, alert_ids=["new1"], es_statuses={"new1": "acknowledged"})
    session.expire_all()
    assert status_of(session, "new1") == "acknowledged"


def test_an_open_status_still_creates_nothing(session):
    """Pre-existing and kept: ION's default is open, so an alert Kibana also
    calls open needs no row. Only a divergence is worth recording."""
    with client(session, READ, TRIAGE) as cli:
        post(cli, alert_ids=["new1"], es_statuses={"new1": "open"})
    session.expire_all()
    assert status_of(session, "new1") is None


@pytest.mark.parametrize("bad", ["deleted", "", "OPEN; DROP", "resolved"])
def test_a_status_outside_the_three_is_ignored(session, bad):
    """Pre-existing and kept. AlertTriageStatus(bad) would raise, and the
    whole batch would fail on one bad value from Kibana."""
    seed(session, "a1", AlertTriageStatus.OPEN)
    with client(session, READ, TRIAGE) as cli:
        res = post(cli, alert_ids=["a1"], es_statuses={"a1": bad})
    assert res.status_code == 200
    session.expire_all()
    assert status_of(session, "a1") == "open"


# ---------------------------------------------------------------------------
# A read with no es_statuses is a read for anyone who may read
# ---------------------------------------------------------------------------


def test_a_read_without_statuses_needs_only_alert_read(session):
    """What the queue fragment's _triage_map does, deliberately passing no
    es_statuses so that rendering the page never writes."""
    seed(session, "a1", AlertTriageStatus.ACKNOWLEDGED)
    with client(session, READ) as cli:
        body = post(cli, alert_ids=["a1"]).json()
    assert body["triage"]["a1"]["status"] == "acknowledged"


def test_a_read_without_statuses_does_not_claim_to_have_synced(session):
    """Nothing was asked for, so `synced` must not read as a completed
    reconciliation."""
    seed(session, "a1")
    with client(session, READ, TRIAGE) as cli:
        body = post(cli, alert_ids=["a1"]).json()
    assert body["synced"] is False


def test_an_empty_id_list_short_circuits_for_either_role(session):
    for perms in ((READ,), (READ, TRIAGE)):
        with client(session, *perms) as cli:
            res = post(cli, alert_ids=[], es_statuses={"a1": "closed"})
        assert res.status_code == 200
        assert res.json()["triage"] == {}
    session.expire_all()
    assert status_of(session, "a1") is None


def test_someone_with_neither_permission_is_refused(session):
    with client(session) as cli:
        res = post(cli, alert_ids=["a1"])
    assert res.status_code in (401, 403)


# ---------------------------------------------------------------------------
# The alias
# ---------------------------------------------------------------------------


def test_the_canonical_alias_shares_this_endpoint(session):
    """server.py registers /api/alerts/triage/batch as a second path for the
    same endpoint object, which is what alerts.html actually calls. A fix
    applied to one path has to reach the other, and it does because there is
    only one function."""
    from ion.web.api import get_batch_triage
    from ion.web.server import app

    for route in app.routes:
        if getattr(route, "path", None) == "/api/alerts/triage/batch":
            assert route.endpoint is get_batch_triage
            break
    else:
        pytest.fail("the canonical alias /api/alerts/triage/batch is gone")
