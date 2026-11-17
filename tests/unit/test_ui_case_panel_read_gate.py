"""The case panel needs only case:read, so it must not widen what that grants.

Stored enrichments are observable:read data and Bob's investigations are
alert:read data on every other ION surface. A case:read-only reader must not
see either through the case window.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui._cases_window import alert_bob, observable_cards, read_case_extras
from ion.web.ui.cases import router

URL = "/ui/cases/7/panel"
SECRET_ACTOR = "FIN7-should-not-leak"
SECRET_SUMMARY = "Bob summary that needs alert:read"


class _User:
    id = 1
    username = "gate-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _case():
    return {
        "id": 7, "case_number": "CASE-7", "title": "A case", "severity": "high",
        "status": "open", "assigned_to_id": None, "created_at": "2026-10-13T09:00:00",
        "description": "d", "evidence_summary": None, "affected_hosts": [],
        "affected_users": [], "triggered_rules": [],
        "observables": [{"type": "ip", "value": "203.0.113.9"}],
        "alerts": [{"es_alert_id": "a1", "rule_name": "R", "priority": "high",
                    "status": "open", "observables": [], "mitre_techniques": []}],
        "notes": [], "kibana_assignees": [], "kibana_case_id": None, "kibana_url": None,
        "dfir_iris_case_id": None,
    }


def _panel(monkeypatch, user):
    """Render the panel with a read stub that honours the gates like the real one."""
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    calls = []

    def fake_extras(session, case_id, alert_ids, values, *, read_investigations=True,
                    read_enrichments=True):
        calls.append((read_investigations, read_enrichments))
        withheld = set()
        out = {"triage": {}, "withheld": withheld,
               "investigations": {"a1": {"status": "completed", "verdict": "true_positive",
                                         "confidence_int": 90, "summary_text": SECRET_SUMMARY,
                                         "recommended_actions_json": "[]"}},
               "enrichments": {"203.0.113.9": [{"source": "opencti", "enriched_at": None,
                                                "is_malicious": True, "score": 80, "labels": [],
                                                "threat_actors": [{"name": SECRET_ACTOR}],
                                                "indicators": []}]}}
        if not read_investigations:
            out["investigations"] = None
            withheld.add("investigations")
        if not read_enrichments:
            out["enrichments"] = None
            withheld.add("enrichments")
        return out

    async def detail(case_id, current_user=None, session=None):
        return _case()

    async def users(session=None):
        return {"users": []}

    monkeypatch.setattr("ion.web.ui.cases.read_case_extras", fake_extras)
    monkeypatch.setattr("ion.web.ui.cases.read_case_detail", detail, raising=False)
    monkeypatch.setattr("ion.web.api.list_assignable_users", users)

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: None
    with TestClient(app) as client:
        response = client.get(URL)
    return response, calls


def test_a_case_reader_gets_no_stored_enrichment_or_bob_rows(monkeypatch):
    from ion.web.ui.cases import PERMISSION

    response, calls = _panel(monkeypatch, _User(PERMISSION))
    assert response.status_code == 200
    assert calls == [(False, False)]
    assert SECRET_ACTOR not in response.text
    assert SECRET_SUMMARY not in response.text
    assert "Stored enrichments need the observable:read permission" in response.text


def test_holders_of_observable_and_alert_read_still_get_them(monkeypatch):
    from ion.web.ui.cases import PERMISSION

    response, calls = _panel(monkeypatch, _User(PERMISSION, "alert:read", "observable:read"))
    assert response.status_code == 200
    assert calls == [(True, True)]
    assert "observable:read permission" not in response.text


def test_withheld_parts_are_not_reported_as_unreadable():
    extras = {"withheld": {"investigations", "enrichments"}, "triage": {},
              "investigations": None, "enrichments": None}
    card = observable_cards([{"value": "203.0.113.9", "kind": "ipv4"}], extras)[0]
    assert card["stored_withheld"] is True and card["stored_unknown"] is False
    assert alert_bob("a1", extras)["state"] == "withheld"


class _Session:
    def __init__(self):
        self.statements = []

    def execute(self, statement):
        self.statements.append(str(statement))

        class _Result:
            def all(self):
                return []

            def scalars(self):
                return self
        return _Result()

    def rollback(self):
        pass


def test_the_read_does_not_query_what_it_withholds():
    session = _Session()
    extras = read_case_extras(session, 7, ["a1"], ["203.0.113.9"],
                              read_investigations=False, read_enrichments=False)
    assert extras["withheld"] == {"investigations", "enrichments"}
    queried = " ".join(session.statements).lower()
    assert "observable_enrichments" not in queried
    assert "investigations" not in queried
