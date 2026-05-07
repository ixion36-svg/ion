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

    def test_16_cross_case_patch_rejected(self, app_client: TestClient):
        """PATCH a pin using a different case's id in the URL returns 404.

        The mutation must not be committed: the pin's title is unchanged.
        """
        # Create case-A and case-B
        r_a = app_client.post(
            "/api/forensics/cases",
            json={
                "title": "TOCTOU Case A",
                "investigation_type": "malware_analysis",
                "description": "",
                "priority": "low",
            },
        )
        assert r_a.status_code == 200, r_a.text
        case_a_id = r_a.json()["id"]

        r_b = app_client.post(
            "/api/forensics/cases",
            json={
                "title": "TOCTOU Case B",
                "investigation_type": "malware_analysis",
                "description": "",
                "priority": "low",
            },
        )
        assert r_b.status_code == 200, r_b.text
        case_b_id = r_b.json()["id"]

        # Create a pin on case-A
        r_pin = app_client.post(
            f"/api/forensics/cases/{case_a_id}/pins",
            json={"source_type": "note", "source_ref": "", "title": "Original Title"},
        )
        assert r_pin.status_code == 200, r_pin.text
        pin_id = r_pin.json()["pin"]["id"]

        # Attempt to PATCH using case-B's id in the URL
        r_bad = app_client.patch(
            f"/api/forensics/cases/{case_b_id}/pins/{pin_id}",
            json={"title": "Mutated by B"},
        )
        assert r_bad.status_code == 404

        # The pin must be unchanged
        pins = app_client.get(
            f"/api/forensics/cases/{case_a_id}/pins"
        ).json()["pins"]
        pin = next(p for p in pins if p["id"] == pin_id)
        assert pin["title"] == "Original Title"

    def test_17_cross_case_dismiss_rejected(self, app_client: TestClient):
        """DELETE a pin using a different case's id in the URL returns 404.

        The pin must remain non-dismissed (mutation not committed).
        """
        r_a = app_client.post(
            "/api/forensics/cases",
            json={
                "title": "TOCTOU Dismiss A",
                "investigation_type": "malware_analysis",
                "description": "",
                "priority": "low",
            },
        )
        case_a_id = r_a.json()["id"]

        r_b = app_client.post(
            "/api/forensics/cases",
            json={
                "title": "TOCTOU Dismiss B",
                "investigation_type": "malware_analysis",
                "description": "",
                "priority": "low",
            },
        )
        case_b_id = r_b.json()["id"]

        r_pin = app_client.post(
            f"/api/forensics/cases/{case_a_id}/pins",
            json={"source_type": "note", "source_ref": "", "title": "Must Survive"},
        )
        pin_id = r_pin.json()["pin"]["id"]

        import json as _json
        r_bad = app_client.request(
            "DELETE",
            f"/api/forensics/cases/{case_b_id}/pins/{pin_id}",
            content=_json.dumps({"reason": "cross-case attack"}),
            headers={"Content-Type": "application/json"},
        )
        assert r_bad.status_code == 404

        pins = app_client.get(
            f"/api/forensics/cases/{case_a_id}/pins"
        ).json()["pins"]
        pin = next(p for p in pins if p["id"] == pin_id)
        assert pin["finding_status"] != "dismissed"




# =============================================================================
# v0.22.0 ForensicCase Annotation Tests (spec §6.2 mirrored to forensic)
# =============================================================================


class TestForensicCaseAnnotations:
    """11 annotation smoke tests mirroring spec §6.2 for ForensicCase."""

    @pytest.fixture(scope="class")
    def ann_case_id(self, app_client: TestClient) -> int:
        """Create a dedicated ForensicCase for annotation tests."""
        r = app_client.post(
            "/api/forensics/cases",
            json={
                "title": "Annotation Forensic Smoke Case",
                "investigation_type": "malware_analysis",
                "description": "Annotation tests",
                "priority": "medium",
            },
        )
        assert r.status_code == 200, r.text
        return r.json()["id"]

    def test_ann_01_create_annotation(self, app_client: TestClient, ann_case_id: int):
        """POST annotation with valid body and timeline_ts returns 201 with id."""
        r = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T14:35:00", "body": "C2 beacon observed post-containment."},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert "id" in data
        assert data["body"] == "C2 beacon observed post-containment."
        assert data["case_id"] == ann_case_id
        assert "deleted_at" not in data

    def test_ann_02_list_annotations(self, app_client: TestClient, ann_case_id: int):
        """GET annotations list returns created annotation; deleted_at absent."""
        r = app_client.get(f"/api/forensics/cases/{ann_case_id}/annotations")
        assert r.status_code == 200, r.text
        data = r.json()
        assert "annotations" in data
        assert len(data["annotations"]) >= 1
        ann = data["annotations"][0]
        assert "deleted_at" not in ann
        assert ann["body"] == "C2 beacon observed post-containment."

    def test_ann_03_update_annotation(self, app_client: TestClient, ann_case_id: int):
        """PATCH annotation body returns 200 with updated content."""
        anns = app_client.get(
            f"/api/forensics/cases/{ann_case_id}/annotations"
        ).json()["annotations"]
        ann_id = anns[0]["id"]

        r = app_client.patch(
            f"/api/forensics/cases/{ann_case_id}/annotations/{ann_id}",
            json={"body": "Updated: lateral movement confirmed after containment."},
        )
        assert r.status_code == 200, r.text
        assert r.json()["body"] == "Updated: lateral movement confirmed after containment."

    def test_ann_04_delete_annotation(self, app_client: TestClient, ann_case_id: int):
        """DELETE annotation; subsequent GET list does not include it."""
        r = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T15:00:00", "body": "To be deleted."},
        )
        assert r.status_code == 201
        ann_id = r.json()["id"]

        del_r = app_client.delete(
            f"/api/forensics/cases/{ann_case_id}/annotations/{ann_id}"
        )
        assert del_r.status_code == 200, del_r.text

        anns = app_client.get(
            f"/api/forensics/cases/{ann_case_id}/annotations"
        ).json()["annotations"]
        ids = [a["id"] for a in anns]
        assert ann_id not in ids

    def test_ann_05_create_writes_ledger_row(self, app_client: TestClient, ann_case_id: int):
        """POST annotation writes a ledger row with action='annotation_created'."""
        r = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T16:00:00", "body": "Ledger check annotation."},
        )
        assert r.status_code == 201
        ann_id = r.json()["id"]

        ledger = app_client.get(
            f"/api/forensics/cases/{ann_case_id}/ledger"
        ).json()
        entries = ledger["entries"]
        ann_entries = [e for e in entries if e.get("action") == "annotation_created"]
        assert len(ann_entries) >= 1, "Expected at least one annotation_created ledger entry"
        payloads = [e["payload"] for e in ann_entries]
        assert any(p.get("annotation_id") == ann_id for p in payloads)

    def test_ann_06_cross_case_patch_rejected(self, app_client: TestClient, ann_case_id: int):
        """Cross-case PATCH returns 404; annotation unchanged."""
        r_b = app_client.post(
            "/api/forensics/cases",
            json={"title": "Cross B", "investigation_type": "malware_analysis",
                  "description": "", "priority": "low"},
        )
        assert r_b.status_code == 200
        case_b_id = r_b.json()["id"]

        r_ann = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T17:00:00", "body": "Original forensic body."},
        )
        assert r_ann.status_code == 201
        ann_id = r_ann.json()["id"]

        r_bad = app_client.patch(
            f"/api/forensics/cases/{case_b_id}/annotations/{ann_id}",
            json={"body": "Mutated by B"},
        )
        assert r_bad.status_code == 404, f"Expected 404, got {r_bad.status_code}"

        anns = app_client.get(
            f"/api/forensics/cases/{ann_case_id}/annotations"
        ).json()["annotations"]
        ann = next((a for a in anns if a["id"] == ann_id), None)
        assert ann is not None
        assert ann["body"] == "Original forensic body."

    def test_ann_07_cross_case_delete_rejected(self, app_client: TestClient, ann_case_id: int):
        """Cross-case DELETE returns 404; annotation not soft-deleted."""
        r_c = app_client.post(
            "/api/forensics/cases",
            json={"title": "Cross C", "investigation_type": "malware_analysis",
                  "description": "", "priority": "low"},
        )
        assert r_c.status_code == 200
        case_c_id = r_c.json()["id"]

        r_ann = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T18:00:00", "body": "Must survive cross-case delete."},
        )
        assert r_ann.status_code == 201
        ann_id = r_ann.json()["id"]

        r_bad = app_client.delete(
            f"/api/forensics/cases/{case_c_id}/annotations/{ann_id}"
        )
        assert r_bad.status_code == 404, f"Expected 404, got {r_bad.status_code}"

        anns = app_client.get(
            f"/api/forensics/cases/{ann_case_id}/annotations"
        ).json()["annotations"]
        ids = [a["id"] for a in anns]
        assert ann_id in ids

    def test_ann_08_empty_body_rejected(self, app_client: TestClient, ann_case_id: int):
        """POST annotation with empty body returns 422."""
        r = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T19:00:00", "body": ""},
        )
        assert r.status_code == 422, r.text

    def test_ann_09_body_too_long_rejected(self, app_client: TestClient, ann_case_id: int):
        """POST annotation with body > 2000 chars returns 422."""
        r = app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T19:30:00", "body": "y" * 2001},
        )
        assert r.status_code == 422, r.text

    def test_ann_10_edit_other_user_annotation_without_close(
        self, db_engine, admin_user: User, ann_case_id: int
    ):
        """Edit another user's annotation without forensic:close returns 403.

        We create a plain user who has forensic:update (passes the API gate)
        but is NOT the annotation author and does NOT have forensic:close.
        The annotation service should raise AnnotationForbiddenError -> 403.
        """
        from ion.web.server import app
        from ion.auth.dependencies import get_current_user as _gcu, get_db_session as _gds
        from sqlalchemy import select as _sel

        factory = sessionmaker(bind=db_engine, expire_on_commit=False)
        saved_overrides = dict(app.dependency_overrides)

        def _session():
            s = factory()
            try:
                yield s
            finally:
                s.close()

        # Build plain user with forensic:update but NOT forensic:close
        plain_session = factory()
        plain_perm_names = ["forensic:read", "forensic:update"]
        plain_perms = []
        for pname in plain_perm_names:
            resource, action = pname.split(":", 1)
            existing = plain_session.execute(
                _sel(Permission).where(Permission.name == pname)
            ).scalar_one_or_none()
            if existing:
                p = existing
            else:
                p = Permission(name=pname, resource=resource, action=action)
                plain_session.add(p)
                plain_session.flush()
            plain_perms.append(p)
        plain_role = Role(name="fann_plain_role")
        plain_session.add(plain_role)
        plain_session.flush()
        for p in plain_perms:
            plain_session.execute(
                role_permissions.insert().values(role_id=plain_role.id, permission_id=p.id)
            )
        plain_user = User(
            username="fann_plain",
            email="fann_plain@test.local",
            password_hash="x",
            display_name="fann_plain",
            is_active=True,
        )
        plain_session.add(plain_user)
        plain_session.flush()
        plain_session.execute(
            user_roles.insert().values(user_id=plain_user.id, role_id=plain_role.id)
        )
        plain_session.commit()
        plain_session.close()

        # Create annotation as admin_user (different user id)
        def _as_admin():
            return admin_user

        app.dependency_overrides[_gds] = _session
        app.dependency_overrides[_gcu] = _as_admin
        with TestClient(app, raise_server_exceptions=True) as admin_c:
            r_ann = admin_c.post(
                f"/api/forensics/cases/{ann_case_id}/annotations",
                json={"timeline_ts": "2026-05-07T20:00:00", "body": "Admin forensic annotation."},
            )
            assert r_ann.status_code == 201, r_ann.text
            ann_id = r_ann.json()["id"]

        # Keep a long-lived session open so the plain_user object
        # can lazy-load roles/permissions when has_permission is called.
        plain_holder_session = factory()
        plain_user_loaded = plain_holder_session.get(User, plain_user.id)
        # Eagerly touch the relationship chain so it is loaded into memory
        _ = [p.name for r in plain_user_loaded.roles for p in r.permissions]

        # Try to edit as plain_user — not author, no forensic:close
        def _as_plain():
            return plain_user_loaded

        app.dependency_overrides[_gcu] = _as_plain
        with TestClient(app, raise_server_exceptions=True) as plain_c:
            r_bad = plain_c.patch(
                f"/api/forensics/cases/{ann_case_id}/annotations/{ann_id}",
                json={"body": "Unauthorized edit"},
            )
            assert r_bad.status_code == 403, f"Expected 403, got {r_bad.status_code}: {r_bad.text}"

        plain_holder_session.close()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved_overrides)

    def test_ann_11_ledger_chain_valid_after_annotation(
        self, app_client: TestClient, ann_case_id: int
    ):
        """GET /ledger/verify returns is_valid=true after annotation creates."""
        app_client.post(
            f"/api/forensics/cases/{ann_case_id}/annotations",
            json={"timeline_ts": "2026-05-07T21:00:00", "body": "Chain check annotation."},
        )
        r = app_client.get(f"/api/forensics/cases/{ann_case_id}/ledger/verify")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("is_valid") is True, f"Ledger chain broken: {data}"
