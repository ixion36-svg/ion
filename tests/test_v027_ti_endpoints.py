"""Tests for the v0.27.0 unified threat-intel endpoints.

Two new endpoints landed in ``src/ion/web/threat_intel_api.py``:

- ``GET /api/threat-intel/unified-search?q=<term>`` — fans out to
  OpenCTI (actors + campaigns) and the local case DB (cases +
  observables) and returns a typed bundle.
- ``GET /api/threat-intel/recently-active?days=N`` — aggregates
  observables (from ``AlertCase.observables`` JSON) and MITRE
  techniques (from ``AlertTriage.mitre_techniques`` JSON) over the
  trailing N days; returns the top-N by frequency for each.

These tests exercise the pure-Python aggregation + JSON-parsing
behaviour against an in-process SQLite DB. The OpenCTI sub-call in
unified-search is monkeypatched to a fake service so the tests don't
need a configured OpenCTI deployment.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.base import Base
from ion.models.observable import Observable, ObservableType
from ion.models.user import User
from ion.storage.database import _run_migrations


@pytest.fixture(scope="function")
def engine(tmp_path):
    db_path = tmp_path / "v027_ti.db"
    eng = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(eng)
    _run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    yield s
    s.rollback()
    s.close()


@pytest.fixture()
def user(db: Session) -> User:
    u = User(
        username="ti_user", email="ti@test.ion",
        password_hash="x", is_active=True, display_name="TI User",
    )
    db.add(u)
    db.flush()
    return u


# ── recently_active ──────────────────────────────────────────────────────


class TestRecentlyActive:
    def test_empty_db_returns_empty_lists(self, db, user):
        from ion.web.threat_intel_api import recently_active
        out = recently_active(days=30, top_n=10, session=db, user=user)
        assert out["time_window_days"] == 30
        assert out["observables"] == []
        assert out["techniques"] == []

    def test_aggregates_observables_from_recent_cases(self, db, user):
        from ion.web.threat_intel_api import recently_active

        # Two recent cases, same IP appears in both → count=2.
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        for i in range(2):
            c = AlertCase(
                case_number=f"AGG-{i}", title=f"recent {i}",
                status="open", severity="high",
                created_by_id=user.id, created_at=recent,
                observables=[
                    {"type": "ip", "value": "10.0.0.1"},
                    {"type": "domain", "value": f"evil-{i}.test"},
                ],
            )
            db.add(c)
        db.commit()

        out = recently_active(days=30, top_n=10, session=db, user=user)
        observable_counts = {
            (o["type"], o["value"]): o["count"] for o in out["observables"]
        }
        assert observable_counts[("ip", "10.0.0.1")] == 2
        assert observable_counts[("domain", "evil-0.test")] == 1
        assert observable_counts[("domain", "evil-1.test")] == 1

    def test_excludes_cases_older_than_window(self, db, user):
        from ion.web.threat_intel_api import recently_active

        # One old case, one fresh — only the fresh one should count.
        old = datetime.now(timezone.utc) - timedelta(days=90)
        fresh = datetime.now(timezone.utc) - timedelta(days=2)
        db.add(AlertCase(
            case_number="OLD", title="old", status="open", severity="low",
            created_by_id=user.id, created_at=old,
            observables=[{"type": "ip", "value": "1.1.1.1"}],
        ))
        db.add(AlertCase(
            case_number="FRESH", title="fresh", status="open", severity="low",
            created_by_id=user.id, created_at=fresh,
            observables=[{"type": "ip", "value": "2.2.2.2"}],
        ))
        db.commit()

        out = recently_active(days=30, top_n=10, session=db, user=user)
        seen = {(o["type"], o["value"]) for o in out["observables"]}
        assert ("ip", "2.2.2.2") in seen
        assert ("ip", "1.1.1.1") not in seen

    def test_aggregates_mitre_techniques_from_triage(self, db, user):
        from ion.web.threat_intel_api import recently_active

        recent = datetime.now(timezone.utc) - timedelta(days=1)
        for i in range(3):
            t = AlertTriage(
                es_alert_id=f"tech-{i}",
                status="open",
                mitre_techniques=["T1003.001", "T1059.001"]
                if i < 2 else ["T1003.001"],
                created_at=recent,
            )
            db.add(t)
        db.commit()

        out = recently_active(days=30, top_n=10, session=db, user=user)
        tech_by_id = {t["id"]: t["count"] for t in out["techniques"]}
        assert tech_by_id["T1003.001"] == 3
        assert tech_by_id["T1059.001"] == 2

    def test_top_n_cap_is_respected(self, db, user):
        from ion.web.threat_intel_api import recently_active

        recent = datetime.now(timezone.utc) - timedelta(days=1)
        # 15 cases each with a unique observable.
        for i in range(15):
            c = AlertCase(
                case_number=f"CAP-{i}", title=f"c{i}",
                status="open", severity="low",
                created_by_id=user.id, created_at=recent,
                observables=[{"type": "ip", "value": f"10.0.0.{i}"}],
            )
            db.add(c)
        db.commit()

        out = recently_active(days=30, top_n=5, session=db, user=user)
        assert len(out["observables"]) == 5

    def test_non_dict_observable_entries_skipped(self, db, user):
        """JSON observable list with non-dict entries (e.g. legacy
        string-only IOC list) shouldn't crash the aggregator. Exercises
        the inner ``if isinstance(o, dict)`` guard."""
        from ion.web.threat_intel_api import recently_active

        recent = datetime.now(timezone.utc) - timedelta(days=1)
        db.add(AlertCase(
            case_number="MIXED", title="mixed",
            status="open", severity="low",
            created_by_id=user.id, created_at=recent,
            observables=[
                {"type": "ip", "value": "8.8.8.8"},
                "legacy-string-ioc",  # malformed entry — must be skipped
                {"type": "domain", "value": "good.example"},
                None,                  # null entry — must be skipped
            ],
        ))
        db.commit()

        out = recently_active(days=30, top_n=10, session=db, user=user)
        seen = {(o["type"], o["value"]) for o in out["observables"]}
        assert ("ip", "8.8.8.8") in seen
        assert ("domain", "good.example") in seen
        # Only two valid entries — no stray rows.
        assert len(out["observables"]) == 2


# ── unified_search ────────────────────────────────────────────────────────


class TestUnifiedSearch:
    def test_returns_typed_bundle_with_zero_external_deps(
        self, db, user, monkeypatch
    ):
        """OpenCTI not configured → actors/campaigns stay empty; cases +
        IOCs come from the local DB."""
        from ion.web import threat_intel_api as ti_api

        class FakeOpenCTIService:
            is_configured = False

        monkeypatch.setattr(
            ti_api, "get_opencti_service", lambda: FakeOpenCTIService()
        )

        # Seed a case + an observable that match the query.
        db.add(AlertCase(
            case_number="HIT", title="phishing campaign on evil.test",
            status="open", severity="high",
            created_by_id=user.id,
            observables=[{"type": "domain", "value": "evil.test"}],
        ))
        db.add(Observable(
            type=ObservableType.DOMAIN,
            value="evil.test",
            normalized_value="evil.test",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ))
        db.commit()

        import asyncio
        out = asyncio.run(
            ti_api.unified_search(
                q="evil.test", limit_per_kind=8,
                session=db, user=user,
            )
        )
        assert out["q"] == "evil.test"
        assert out["actors"] == []
        assert out["campaigns"] == []
        case_titles = [c["title"] for c in out["cases"]]
        assert any("phishing" in t for t in case_titles)
        ioc_values = [i["value"] for i in out["iocs"]]
        assert "evil.test" in ioc_values
        assert out["total"] >= 2

    def test_opencti_failure_does_not_crash_local_search(
        self, db, user, monkeypatch
    ):
        """If OpenCTI raises mid-fetch, local case + IOC results still
        come back."""
        from ion.web import threat_intel_api as ti_api

        class BoomOpenCTIService:
            is_configured = True

            async def search_threat_actors(self, **kw):
                raise RuntimeError("opencti down")

            async def search_campaigns(self, **kw):
                raise RuntimeError("opencti down")

        monkeypatch.setattr(
            ti_api, "get_opencti_service", lambda: BoomOpenCTIService()
        )

        db.add(Observable(
            type=ObservableType.IPV4,
            value="10.0.0.99",
            normalized_value="10.0.0.99",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        ))
        db.commit()

        import asyncio
        out = asyncio.run(
            ti_api.unified_search(
                q="10.0.0.99", limit_per_kind=8,
                session=db, user=user,
            )
        )
        # Actors empty (OpenCTI raised), IOCs populated from local DB.
        assert out["actors"] == []
        assert out["campaigns"] == []
        assert "10.0.0.99" in [i["value"] for i in out["iocs"]]
