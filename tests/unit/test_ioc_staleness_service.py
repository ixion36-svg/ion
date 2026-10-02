"""Tests for ioc_staleness_service — observables needing re-enrichment.

This module was at 0% when the coverage ratchet first measured the tree. It
answers "which indicators are we trusting on out-of-date intelligence", so
the failures that cost something are omissions: an observable that should
have surfaced and did not, or one that is live in an open case and is not
flagged as such.

It is also written defensively — the models are imported in a try/except
because the tables may not exist — so the degraded paths are part of the
contract and are pinned here too.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.models.observable import (
    Observable,
    ObservableEnrichment,
    ObservableType,
    ThreatLevel,
)
from ion.models.user import User
from ion.services import ioc_staleness_service as svc


def _naive_ago(days):
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)


def _obs(session, value="1.2.3.4", *, otype=ObservableType.IPV4,
         threat=ThreatLevel.UNKNOWN, whitelisted=False, created_days_ago=None,
         sightings=1):
    o = Observable(type=otype, value=value, normalized_value=value,
                   threat_level=threat, is_whitelisted=whitelisted,
                   sighting_count=sightings)
    session.add(o)
    session.flush()
    if created_days_ago is not None:
        o.created_at = _naive_ago(created_days_ago)
        session.flush()
    return o


def _enrich(session, obs, days_ago, source="virustotal"):
    e = ObservableEnrichment(observable_id=obs.id, source=source,
                             enriched_at=_naive_ago(days_ago))
    session.add(e)
    session.flush()
    return e


def _case(session, creator, number, observables, status=AlertCaseStatus.OPEN):
    c = AlertCase(case_number=number, title="t", created_by_id=creator.id,
                  status=status, observables=observables)
    session.add(c)
    session.flush()
    return c


@pytest.fixture
def creator(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


class TestWhatCountsAsStale:
    def test_an_observable_never_enriched_is_stale(self, session):
        _obs(session, "1.1.1.1", created_days_ago=5)

        out = svc.get_stale_iocs(session, stale_days=30)

        assert out["stale_count"] == 1
        assert out["never_enriched_count"] == 1
        assert out["stale_iocs"][0]["last_enriched"] is None

    def test_an_enrichment_older_than_the_window_is_stale(self, session):
        o = _obs(session, "2.2.2.2")
        _enrich(session, o, days_ago=90)

        out = svc.get_stale_iocs(session, stale_days=30)

        assert out["stale_count"] == 1
        assert out["never_enriched_count"] == 0
        assert out["stale_iocs"][0]["days_stale"] >= 89

    def test_a_recent_enrichment_is_not_stale(self, session):
        o = _obs(session, "3.3.3.3")
        _enrich(session, o, days_ago=2)

        assert svc.get_stale_iocs(session, stale_days=30)["stale_count"] == 0

    def test_only_the_latest_enrichment_counts(self, session):
        """An old record alongside a fresh one must not make it look stale."""
        o = _obs(session, "4.4.4.4")
        _enrich(session, o, days_ago=200, source="old")
        _enrich(session, o, days_ago=1, source="new")

        assert svc.get_stale_iocs(session, stale_days=30)["stale_count"] == 0

    def test_whitelisted_observables_are_never_chased(self, session):
        _obs(session, "5.5.5.5", whitelisted=True, created_days_ago=400)

        out = svc.get_stale_iocs(session, stale_days=30)

        assert out["stale_count"] == 0
        assert out["total_observables"] == 0

    def test_the_window_is_configurable(self, session):
        o = _obs(session, "6.6.6.6")
        _enrich(session, o, days_ago=10)

        assert svc.get_stale_iocs(session, stale_days=30)["stale_count"] == 0
        assert svc.get_stale_iocs(session, stale_days=5)["stale_count"] == 1


class TestOrderingAndLimits:
    def test_the_stalest_is_reported_first(self, session):
        a = _obs(session, "10.0.0.1")
        _enrich(session, a, days_ago=40)
        b = _obs(session, "10.0.0.2")
        _enrich(session, b, days_ago=200)

        values = [i["value"] for i in svc.get_stale_iocs(session)["stale_iocs"]]

        assert values == ["10.0.0.2", "10.0.0.1"]

    def test_the_limit_is_respected(self, session):
        for i in range(8):
            _obs(session, f"10.1.0.{i}", created_days_ago=100)

        out = svc.get_stale_iocs(session, limit=3)

        assert out["stale_count"] == 3
        assert out["total_observables"] == 8


class TestGrouping:
    def test_counted_by_type_and_threat_level(self, session):
        _obs(session, "1.1.1.1", otype=ObservableType.IPV4,
             threat=ThreatLevel.HIGH, created_days_ago=99)
        _obs(session, "2.2.2.2", otype=ObservableType.IPV4,
             threat=ThreatLevel.LOW, created_days_ago=99)
        _obs(session, "evil.test", otype=ObservableType.DOMAIN,
             threat=ThreatLevel.HIGH, created_days_ago=99)

        out = svc.get_stale_iocs(session)

        assert out["by_type"] == {"ipv4": 2, "domain": 1}
        assert out["by_threat_level"] == {"high": 2, "low": 1}

    def test_the_sighting_count_is_carried_through(self, session):
        _obs(session, "9.9.9.9", sightings=17, created_days_ago=99)
        assert svc.get_stale_iocs(session)["stale_iocs"][0]["sighting_count"] == 17


class TestOpenCaseLinkage:
    """Whether a stale indicator is live in an investigation right now."""

    def test_an_observable_in_an_open_case_is_flagged(self, session, creator):
        o = _obs(session, "1.1.1.1", created_days_ago=99)
        _case(session, creator, "C1", [{"id": o.id, "value": "1.1.1.1"}])

        assert svc.get_stale_iocs(session)["stale_iocs"][0]["in_open_case"] is True

    def test_a_bare_id_list_is_understood_too(self, session, creator):
        o = _obs(session, "1.1.1.1", created_days_ago=99)
        _case(session, creator, "C1", [o.id])

        assert svc.get_stale_iocs(session)["stale_iocs"][0]["in_open_case"] is True

    def test_an_acknowledged_case_still_counts_as_open(self, session, creator):
        o = _obs(session, "1.1.1.1", created_days_ago=99)
        _case(session, creator, "C1", [o.id], status=AlertCaseStatus.ACKNOWLEDGED)

        assert svc.get_stale_iocs(session)["stale_iocs"][0]["in_open_case"] is True

    def test_a_closed_case_does_not_flag_it(self, session, creator):
        o = _obs(session, "1.1.1.1", created_days_ago=99)
        _case(session, creator, "C1", [o.id], status=AlertCaseStatus.CLOSED)

        assert svc.get_stale_iocs(session)["stale_iocs"][0]["in_open_case"] is False

    def test_an_observable_in_no_case_is_not_flagged(self, session):
        _obs(session, "1.1.1.1", created_days_ago=99)
        assert svc.get_stale_iocs(session)["stale_iocs"][0]["in_open_case"] is False

    def test_malformed_case_observables_are_skipped_quietly(self, session, creator):
        """Stray shapes in the JSON column must not lose the whole report."""
        o = _obs(session, "1.1.1.1", created_days_ago=99)
        _case(session, creator, "C1", ["a string", {"no_id": 1}, None])

        out = svc.get_stale_iocs(session)

        assert out["stale_count"] == 1
        assert out["stale_iocs"][0]["in_open_case"] is False


class TestDegradedPaths:
    def test_missing_models_return_the_empty_shape(self, session, monkeypatch):
        """The module imports its models defensively; honour that contract."""
        monkeypatch.setattr(svc, "Observable", None)

        out = svc.get_stale_iocs(session)

        assert out == {
            "total_observables": 0, "stale_count": 0, "never_enriched_count": 0,
            "stale_iocs": [], "by_type": {}, "by_threat_level": {},
        }

    def test_a_query_failure_returns_the_empty_shape(self, session, monkeypatch):
        def boom(*a, **k):
            raise RuntimeError("db gone")

        monkeypatch.setattr(session, "query", boom)

        assert svc.get_stale_iocs(session)["stale_count"] == 0

    def test_an_open_case_lookup_failure_does_not_lose_the_report(
        self, session, monkeypatch
    ):
        """The case linkage is a nicety; the staleness list is the point."""
        _obs(session, "1.1.1.1", created_days_ago=99)
        monkeypatch.setattr(svc, "AlertCase", None)

        out = svc.get_stale_iocs(session)

        assert out["stale_count"] == 1
        assert out["stale_iocs"][0]["in_open_case"] is False

    def test_an_empty_estate_reports_zeroes(self, session):
        out = svc.get_stale_iocs(session)
        assert out["total_observables"] == 0
        assert out["stale_iocs"] == []

    def test_an_open_case_query_failure_is_swallowed(self, session, monkeypatch):
        """A broken case query must degrade the linkage, not the report."""
        _obs(session, "1.1.1.1", created_days_ago=99)

        class _Boom:
            def __getattr__(self, name):
                raise RuntimeError("case table is wrong")

        monkeypatch.setattr(svc, "AlertCase", _Boom())

        out = svc.get_stale_iocs(session)

        assert out["stale_count"] == 1
        assert out["stale_iocs"][0]["in_open_case"] is False
