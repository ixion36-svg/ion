"""Smoke test suite for MITRE ATT&CK coverage heatmap (Feature A, v0.22.0).

Eight cases per spec §6.1. By default runs against an ephemeral SQLite
DB (Python-side unnesting path). If ION_TEST_DATABASE_URL is set in the
environment, the suite runs against that DSN instead — typically a
Postgres instance, which exercises the LATERAL-join service path.

v0.22.1 (OQ5): the previous version of this fixture was hard-coded to
SQLite, so the Postgres LATERAL path went untested in CI. Operators
with a Postgres handy can now run:
    ION_TEST_DATABASE_URL=postgresql://... pytest tests/test_mitre_heatmap.py
to exercise the dialect-specific service path.

Test layout:
  1. GET /api/cyab/attack-heatmap unauthenticated  → 401
  2. GET authenticated with alert:read             → 200, correct shape
  3. No MITRE-tagged alerts in DB                  → alert_case_count = 0 for all
  4. AlertTriage + catalogue shipped               → covered_exercised
  5. CaseEvidencePin, T1078 not in catalogue       → not_covered_seen, pin_count ≥ 1
  6. Catalogue has T1046 shipped, no observations  → covered_not_exercised
  7. ForensicCasePin with T1003.001               → pin_count ≥ 1
  8. Dismissed pin not counted                    → pin_count unchanged
"""

from __future__ import annotations

import json
import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

import ion.web.api as _web_api
from ion.auth.dependencies import get_current_user, get_db_session, require_permission
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import reset_engine

# cyab_api.py imports get_db_session from ion.web.api (a separate function).
# The test must override BOTH to wire the test DB end-to-end.
_api_get_db_session = _web_api.get_db_session


# ---------------------------------------------------------------------------
# Module-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def db_engine(tmp_path_factory):
    """Module-scoped engine — Postgres if ION_TEST_DATABASE_URL is set, else SQLite.

    v0.22.1 (OQ5): honour an opt-in env var so the Postgres LATERAL service
    path is exercisable without restructuring the whole suite. When pointed
    at Postgres, schema setup uses create_all on a clean DB; the test is
    self-contained and drops nothing it didn't create, so use a throwaway DB.
    """
    dsn = os.environ.get("ION_TEST_DATABASE_URL")
    if dsn:
        engine = create_engine(dsn, future=True)
    else:
        db_path = tmp_path_factory.mktemp("hm") / "test_heatmap.db"
        engine = create_engine(
            f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
        )
    import ion.models  # noqa: F401 — side-effect import registers all models
    Base.metadata.create_all(engine)
    yield engine
    if dsn:
        # Leave the throwaway DB schema in place — operators run pytest against
        # disposable instances. Cleaning up would risk dropping shared data.
        Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(db_engine) -> Generator[Session, None, None]:
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture(scope="module")
def heatmap_user(db_session: Session) -> User:
    """Create a user with alert:read permission."""
    p = Permission(name="alert:read", resource="alert", action="read")
    db_session.add(p)
    role = Role(name="hm_reader")
    db_session.add(role)
    db_session.flush()
    db_session.execute(
        role_permissions.insert().values(role_id=role.id, permission_id=p.id)
    )
    user = User(
        username="hm_analyst",
        email="hm@localhost",
        password_hash="x",
        display_name="HM Analyst",
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    db_session.execute(
        user_roles.insert().values(user_id=user.id, role_id=role.id)
    )
    db_session.commit()
    return user


@pytest.fixture(scope="module")
def unauth_client(db_engine) -> Generator[TestClient, None, None]:
    """TestClient with DB wired but NO auth override (unauthenticated)."""
    from ion.web.server import app

    test_sf = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _session() -> Generator[Session, None, None]:
        s = test_sf()
        try:
            yield s
        finally:
            s.close()

    # Override both session providers (auth.dependencies + web.api).
    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[_api_get_db_session] = _session
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
    app.dependency_overrides.clear()
    reset_engine()


@pytest.fixture(scope="module")
def auth_client(db_engine, heatmap_user: User) -> Generator[TestClient, None, None]:
    """TestClient with DB wired and alert:read user injected."""
    from ion.web.server import app

    test_sf = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _session() -> Generator[Session, None, None]:
        s = test_sf()
        try:
            yield s
        finally:
            s.close()

    def _user() -> User:
        return heatmap_user

    # Override both session providers (auth.dependencies + web.api).
    app.dependency_overrides[get_db_session] = _session
    app.dependency_overrides[_api_get_db_session] = _session
    app.dependency_overrides[get_current_user] = _user
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client
    app.dependency_overrides.clear()
    reset_engine()


# ---------------------------------------------------------------------------
# Helpers for direct DB seeding (bypass API so tests remain self-contained)
# ---------------------------------------------------------------------------


def _seed_alert_case(session: Session, user_id: int) -> int:
    """Insert an AlertCase and return its id."""
    from datetime import datetime, timezone
    import uuid
    from ion.models.alert_triage import AlertCase

    case = AlertCase(
        case_number=f"HM-{user_id}-{uuid.uuid4().hex[:8]}",
        title="Heatmap Test Case",
        status="open",
        created_by_id=user_id,
    )
    session.add(case)
    session.commit()
    return case.id


def _seed_alert_triage(
    session: Session, case_id: int, techniques: list, user_id: int
) -> None:
    """Insert an AlertTriage row linked to a case."""
    import uuid
    from ion.models.alert_triage import AlertTriage

    triage = AlertTriage(
        es_alert_id=f"es-{uuid.uuid4()}",
        status="closed",
        case_id=case_id,
        mitre_techniques=techniques,
    )
    session.add(triage)
    session.commit()


def _seed_cyab_subprofile(session: Session, sub_id: str, uc_id: str, tid: str) -> None:
    """Insert a pillar + subprofile with one shipped detection use case."""
    from ion.models.cyab_subprofile import CyabPillar, CyabSubProfile

    if not session.get(CyabPillar, "test_pillar"):
        session.add(
            CyabPillar(id="test_pillar", label="Test", icon="cpu", priority=99)
        )
        session.flush()

    cat = json.dumps(
        {
            "detection_use_cases": [
                {"id": uc_id, "title": f"Detect {tid}", "mitre_ids": [tid]}
            ]
        }
    )
    if not session.get(CyabSubProfile, sub_id):
        session.add(
            CyabSubProfile(
                id=sub_id,
                pillar_id="test_pillar",
                label=f"Test {sub_id}",
                icon="cpu",
                catalogue_json=cat,
            )
        )
    else:
        sp = session.get(CyabSubProfile, sub_id)
        sp.catalogue_json = cat
    session.commit()


def _seed_cyab_data_source(
    session: Session, user_id: int, sub_id: str, uc_id: str
) -> None:
    """Insert a CyabSystem + CyabDataSource with uc_id=shipped."""
    from ion.models.cyab import CyabDataSource, CyabSystem

    sys = CyabSystem(
        name=f"HM Sys {sub_id}",
        department="Test",
        created_by=user_id,
    )
    session.add(sys)
    session.flush()
    ds = CyabDataSource(
        system_id=sys.id,
        name="TestDS",
        subprofile_id=sub_id,
        use_case_status=json.dumps({uc_id: "shipped"}),
    )
    session.add(ds)
    session.commit()


def _seed_case_evidence_pin(
    session: Session, case_id: int, user_id: int, techniques: list, status: str = "confirmed"
) -> int:
    """Insert a CaseEvidencePin and return its id."""
    import uuid
    from ion.models.case_evidence import CaseEvidencePin

    pin = CaseEvidencePin(
        alert_case_id=case_id,
        source_type="obs",
        source_ref=f"obs:{uuid.uuid4().hex[:8]}",
        title="Test Pin",
        finding_status=status,
        pinned_by_id=user_id,
        mitre_techniques=techniques,
    )
    session.add(pin)
    session.commit()
    return pin.id


def _seed_forensic_case_pin(
    session: Session, forensic_case_id: int, user_id: int, techniques: list, status: str = "confirmed"
) -> int:
    """Insert a ForensicCasePin and return its id."""
    import uuid
    from ion.models.forensic_workbench import ForensicCasePin

    pin = ForensicCasePin(
        forensic_case_id=forensic_case_id,
        source_type="obs",
        source_ref=f"fobs:{uuid.uuid4().hex[:8]}",
        title="FP Test",
        finding_status=status,
        pinned_by_id=user_id,
        mitre_techniques=techniques,
    )
    session.add(pin)
    session.commit()
    return pin.id


def _seed_forensic_case(session: Session, user_id: int) -> int:
    """Insert a ForensicCase and return its id."""
    import uuid
    from ion.models.forensics import ForensicCase

    fc = ForensicCase(
        case_number=f"FC-HM-{uuid.uuid4().hex[:6].upper()}",
        title="HM Forensic Case",
        investigation_type="malware_analysis",
        status="open",
        lead_investigator_id=user_id,
    )
    session.add(fc)
    session.commit()
    return fc.id


def _find_cell(cells: list, tid: str) -> dict | None:
    for c in cells:
        if c["technique_id"] == tid:
            return c
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMitreHeatmap:
    """8 cases per spec §6.1."""

    def test_01_unauthenticated_returns_401(self, unauth_client: TestClient):
        """GET /api/cyab/attack-heatmap without auth → 401."""
        r = unauth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 401, r.text

    def test_02_authenticated_returns_correct_shape(
        self, auth_client: TestClient
    ):
        """GET with alert:read → 200, cells list, summary with required keys."""
        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data["cells"], list)
        assert "technique_count" in data
        assert "generated_at" in data
        summary = data["summary"]
        assert "covered_exercised" in summary
        assert "covered_not_exercised" in summary
        assert "not_covered_seen" in summary

    def test_03_no_mitre_tagged_alerts_all_zero(
        self, auth_client: TestClient, db_session: Session
    ):
        """When no alert_triage rows have mitre_techniques, all alert_case_count = 0."""
        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        for cell in data["cells"]:
            assert cell["alert_case_count"] == 0, (
                f"{cell['technique_id']} had unexpected alert_case_count"
            )

    def test_04_alert_triage_with_technique_in_catalogue_is_covered_exercised(
        self, auth_client: TestClient, db_session: Session, heatmap_user: User
    ):
        """T1558.003 in alert triage + catalogue shipped → covered_exercised."""
        tid = "T1558.003"
        sub_id = "test_kerberoast"
        uc_id = "uc_kerberoast"

        _seed_cyab_subprofile(db_session, sub_id, uc_id, tid)
        _seed_cyab_data_source(db_session, heatmap_user.id, sub_id, uc_id)
        case_id = _seed_alert_case(db_session, heatmap_user.id)
        _seed_alert_triage(db_session, case_id, [tid], heatmap_user.id)

        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        cell = _find_cell(data["cells"], tid)
        assert cell is not None, f"No cell for {tid}"
        assert cell["cell_state"] == "covered_exercised", cell
        assert cell["alert_case_count"] >= 1

    def test_05_case_evidence_pin_not_in_catalogue_is_not_covered_seen(
        self, auth_client: TestClient, db_session: Session, heatmap_user: User
    ):
        """T1078 in pin but NOT in catalogue → not_covered_seen, pin_count ≥ 1."""
        tid = "T1078"
        case_id = _seed_alert_case(db_session, heatmap_user.id)
        _seed_case_evidence_pin(db_session, case_id, heatmap_user.id, [tid])

        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        cell = _find_cell(data["cells"], tid)
        assert cell is not None, f"No cell for {tid}"
        assert cell["cell_state"] == "not_covered_seen", cell
        assert cell["pin_count"] >= 1

    def test_06_catalogue_shipped_no_observations_is_covered_not_exercised(
        self, auth_client: TestClient, db_session: Session, heatmap_user: User
    ):
        """T1046 in catalogue as shipped, no alert/pin rows → covered_not_exercised."""
        tid = "T1046"
        sub_id = "test_netscan"
        uc_id = "uc_netscan"

        _seed_cyab_subprofile(db_session, sub_id, uc_id, tid)
        _seed_cyab_data_source(db_session, heatmap_user.id, sub_id, uc_id)

        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        cell = _find_cell(data["cells"], tid)
        assert cell is not None, f"No cell for {tid}"
        assert cell["cell_state"] == "covered_not_exercised", cell

    def test_07_forensic_case_pin_is_counted(
        self, auth_client: TestClient, db_session: Session, heatmap_user: User
    ):
        """ForensicCasePin with T1003.001 contributes pin_count."""
        tid = "T1003.001"
        fc_id = _seed_forensic_case(db_session, heatmap_user.id)
        _seed_forensic_case_pin(db_session, fc_id, heatmap_user.id, [tid])

        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        cell = _find_cell(data["cells"], tid)
        assert cell is not None, f"No cell for {tid}"
        assert cell["pin_count"] >= 1

    def test_08_dismissed_pin_not_counted(
        self, auth_client: TestClient, db_session: Session, heatmap_user: User
    ):
        """A dismissed CaseEvidencePin must NOT increment pin_count."""
        tid = "T1021.001"  # choose a technique with no prior pins in this suite
        case_id = _seed_alert_case(db_session, heatmap_user.id)

        # First get baseline (no active pins for this technique).
        r0 = auth_client.get("/api/cyab/attack-heatmap")
        data0 = r0.json()
        baseline = (_find_cell(data0["cells"], tid) or {}).get("pin_count", 0)

        # Seed a dismissed pin.
        _seed_case_evidence_pin(
            db_session, case_id, heatmap_user.id, [tid], status="dismissed"
        )

        r = auth_client.get("/api/cyab/attack-heatmap")
        assert r.status_code == 200, r.text
        data = r.json()
        cell = _find_cell(data["cells"], tid)
        pin_count = (cell or {}).get("pin_count", 0)
        assert pin_count == baseline, (
            f"Dismissed pin was counted; pin_count went {baseline} → {pin_count}"
        )
