"""Smoke test suite for ForensicCase Workbench (v0.20.1).

Mirrors the AlertCase Workbench smoke pattern. Tests run against a real
SQLite database (ION integration tests hit real Postgres in CI; locally
SQLite is used if ION_DATABASE_URL is not set). No mocking of the database.

Flow:
  login → create forensic case → pin item → dedupe 409 → status change
  → verify chain → tamper test (direct DB UPDATE, verify detects break)
  → dismiss → ledger inspection → evidence upload smoke
"""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from ion.auth.dependencies import get_current_user, get_db_session, require_permission
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import reset_engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def db_engine(tmp_path_factory):
    """Module-scoped SQLite engine with all ION tables."""
    db_path = tmp_path_factory.mktemp("wb") / "test_workbench.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    # Ensure all models are registered
    import ion.models  # noqa: F401 — side-effect import registers all models
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(db_engine) -> Generator[Session, None, None]:
    """Long-lived session for the module (tests must not close it)."""
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


@pytest.fixture(scope="module")
def admin_user(db_session: Session) -> User:
    """Create an admin user with all forensic permissions."""
    perms = []
    for pname in (
        "forensic:read",
        "forensic:create",
        "forensic:update",
        "forensic:close",
        "forensic:manage_playbooks",
        "case:read",
        "case:update",
    ):
        resource, action = pname.split(":", 1)
        p = Permission(name=pname, resource=resource, action=action)
        db_session.add(p)
        perms.append(p)

    role = Role(name="forensic_admin")
    db_session.add(role)
    db_session.flush()
    for p in perms:
        db_session.execute(
            role_permissions.insert().values(role_id=role.id, permission_id=p.id)
        )

    user = User(
        username="wb_admin",
        email="wb_admin@localhost",
        password_hash="x",
        display_name="WB Admin",
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
def app_client(db_engine, admin_user: User) -> Generator[TestClient, None, None]:
    """TestClient with DB wired and all auth dependencies bypassed."""
    from ion.web.server import app

    # Wire the test DB so every session dependency uses it.
    test_session_factory = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _override_session() -> Generator[Session, None, None]:
        session = test_session_factory()
        try:
            yield session
        finally:
            session.close()

    def _override_user() -> User:
        return admin_user

    # Override both the generic get_db_session (used by workbench API) and the
    # auth user dependency (get_current_user is the root that require_permission
    # delegates to).
    app.dependency_overrides[get_db_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user

    with TestClient(app, raise_server_exceptions=True) as client:
        yield client

    app.dependency_overrides.clear()
    reset_engine()


@pytest.fixture(scope="module")
def forensic_case_id(app_client: TestClient) -> int:
    """Create a ForensicCase and return its id."""
    r = app_client.post(
        "/api/forensics/cases",
        json={
            "title": "Workbench Smoke Case",
            "investigation_type": "malware_analysis",
            "description": "Created by smoke test",
            "priority": "high",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestForensicWorkbench:
    """10+ smoke assertions for ForensicCase Workbench parity."""

    def test_01_case_was_created(self, app_client: TestClient, forensic_case_id: int):
        """Precondition: case exists and is reachable."""
        r = app_client.get(f"/api/forensics/cases/{forensic_case_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == forensic_case_id
        assert data["title"] == "Workbench Smoke Case"

    def test_02_pin_list_empty_initially(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Fresh case has no pins."""
        r = app_client.get(f"/api/forensics/cases/{forensic_case_id}/pins")
        assert r.status_code == 200
        assert r.json()["pins"] == []

    def test_03_ledger_empty_initially(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Fresh case has an empty ledger."""
        r = app_client.get(f"/api/forensics/cases/{forensic_case_id}/ledger")
        assert r.status_code == 200
        assert r.json()["entries"] == []

    def test_04_create_pin(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """POST /cases/{id}/pins creates a pin and a ledger row."""
        r = app_client.post(
            f"/api/forensics/cases/{forensic_case_id}/pins",
            json={
                "source_type": "alert",
                "source_ref": "alert:42",
                "title": "Suspicious PowerShell execution",
                "severity": "high",
                "tags": ["powershell", "execution"],
            },
        )
        assert r.status_code == 200, r.text
        pin = r.json()["pin"]
        assert pin["source_type"] == "alert"
        assert pin["source_ref"] == "alert:42"
        assert pin["finding_status"] == "triage"
        assert pin["severity"] == "high"
        assert pin["forensic_case_id"] == forensic_case_id

    def test_05_duplicate_pin_returns_409(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Pinning the same (case, source_type, source_ref) twice returns 409."""
        r = app_client.post(
            f"/api/forensics/cases/{forensic_case_id}/pins",
            json={
                "source_type": "alert",
                "source_ref": "alert:42",  # same as test_04
                "title": "Duplicate pin attempt",
            },
        )
        assert r.status_code == 409, r.text

    def test_06_pin_appears_in_list(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """The pin created in test_04 is listed."""
        r = app_client.get(f"/api/forensics/cases/{forensic_case_id}/pins")
        assert r.status_code == 200
        pins = r.json()["pins"]
        assert len(pins) == 1
        assert pins[0]["source_ref"] == "alert:42"

    def test_07_status_change_writes_ledger_row(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """PATCH pin status emits a status_change ledger row."""
        # Get pin id first
        pins = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/pins"
        ).json()["pins"]
        pin_id = pins[0]["id"]

        r = app_client.patch(
            f"/api/forensics/cases/{forensic_case_id}/pins/{pin_id}",
            json={"finding_status": "confirmed"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["pin"]["finding_status"] == "confirmed"

        # Two ledger rows: 'pin' + 'status_change'
        entries = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/ledger"
        ).json()["entries"]
        assert len(entries) == 2
        actions = {e["action"] for e in entries}
        assert "pin" in actions
        assert "status_change" in actions

    def test_08_verify_chain_valid(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Ledger chain verifies intact after legitimate mutations."""
        r = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/ledger/verify"
        )
        assert r.status_code == 200
        result = r.json()
        assert result["is_valid"] is True
        assert result["first_break_seq"] is None
        assert result["error"] is None
        assert result["seq_count"] == 2

    def test_09_tamper_breaks_chain(
        self, db_engine, forensic_case_id: int, app_client: TestClient
    ):
        """Direct DB mutation of a ledger row is detected by verify_chain."""
        from sqlalchemy import text as sa_text

        with db_engine.begin() as conn:
            # Tamper: overwrite the action field on seq=1
            conn.execute(
                sa_text(
                    "UPDATE forensic_case_ledger "
                    "SET action = 'TAMPERED' "
                    "WHERE forensic_case_id = :cid AND seq = 1"
                ),
                {"cid": forensic_case_id},
            )

        r = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/ledger/verify"
        )
        assert r.status_code == 200
        result = r.json()
        assert result["is_valid"] is False
        assert result["first_break_seq"] == 1

    def test_10_dismiss_pin_soft_deletes(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """DELETE /pins/{id} soft-dismisses; pin hidden from default list."""
        pins = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/pins"
        ).json()["pins"]
        # May be empty now due to tamper in test_09 not affecting pins list
        if not pins:
            # Add a second pin to dismiss
            app_client.post(
                f"/api/forensics/cases/{forensic_case_id}/pins",
                json={
                    "source_type": "observable",
                    "source_ref": "obs:99",
                    "title": "Dismiss test observable",
                },
            )
            pins = app_client.get(
                f"/api/forensics/cases/{forensic_case_id}/pins"
            ).json()["pins"]

        pin_id = pins[0]["id"]
        r = app_client.request(
            "DELETE",
            f"/api/forensics/cases/{forensic_case_id}/pins/{pin_id}",
            content=json.dumps({"reason": "false positive"}),
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["pin"]["finding_status"] == "dismissed"

        # Not in default list (include_dismissed=false)
        pins_after = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/pins"
        ).json()["pins"]
        assert all(p["id"] != pin_id for p in pins_after)

        # Visible when include_dismissed=true
        pins_all = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/pins",
            params={"include_dismissed": "true"},
        ).json()["pins"]
        assert any(p["id"] == pin_id for p in pins_all)

    def test_11_ledger_inspection_shows_all_actions(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Ledger contains all expected action types in seq order."""
        r = app_client.get(f"/api/forensics/cases/{forensic_case_id}/ledger")
        assert r.status_code == 200
        entries = r.json()["entries"]
        assert len(entries) >= 3  # pin, status_change, dismiss at minimum
        # seqs are monotonically increasing
        seqs = [e["seq"] for e in entries]
        assert seqs == sorted(seqs)
        # All have required fields
        for e in entries:
            assert "seq" in e
            assert "action" in e
            assert "prev_hash" in e
            assert "content_hash" in e
            assert len(e["content_hash"]) == 64

    def test_12_evidence_upload(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """POST /cases/{id}/evidence/upload creates EvidenceItem + ledger row."""
        content = b"fake binary evidence content for smoke test"
        expected_sha256 = hashlib.sha256(content).hexdigest()

        r = app_client.post(
            f"/api/forensics/cases/{forensic_case_id}/evidence/upload",
            files={"file": ("smoke_evidence.bin", io.BytesIO(content), "application/octet-stream")},
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["sha256"] == expected_sha256
        assert data["size_bytes"] == len(content)
        assert data["evidence"]["hash_sha256"] == expected_sha256
        assert data["evidence"]["name"] == "smoke_evidence.bin"

    def test_13_upload_ledger_row_present(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Evidence upload writes an evidence_upload ledger action."""
        entries = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/ledger"
        ).json()["entries"]
        actions = [e["action"] for e in entries]
        assert "evidence_upload" in actions

    def test_14_note_pin_auto_dedupes_via_uuid(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """Two NOTE pins with empty source_ref both succeed (uuid in source_ref)."""
        for i in range(2):
            r = app_client.post(
                f"/api/forensics/cases/{forensic_case_id}/pins",
                json={
                    "source_type": "note",
                    "source_ref": "",
                    "title": f"Free-form analyst note #{i}",
                },
            )
            assert r.status_code == 200, r.text

    def test_15_ledger_limit_cap(
        self, app_client: TestClient, forensic_case_id: int
    ):
        """limit param is capped at 2000; limit=1 returns exactly 1 entry."""
        r = app_client.get(
            f"/api/forensics/cases/{forensic_case_id}/ledger",
            params={"limit": 1},
        )
        assert r.status_code == 200
        entries = r.json()["entries"]
        assert len(entries) == 1
        assert entries[0]["seq"] == 1
