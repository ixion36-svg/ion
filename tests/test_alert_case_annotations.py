"""Smoke test suite for AlertCase timeline annotations (v0.22.0).

11 test cases per spec §6.2. Tests run against a real SQLite database.
Covers: create, list, update, soft-delete, ledger write, cross-case TOCTOU
protection, empty body, body > 2000 chars, per-user edit permissions,
and ledger chain validity after annotation create.
"""

from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from ion.auth.dependencies import get_current_user, get_db_session
from ion.models.base import Base
from ion.models.user import Permission, Role, User, role_permissions, user_roles
from ion.storage.database import reset_engine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def db_engine(tmp_path_factory):
    """Module-scoped SQLite engine with all ION tables."""
    db_path = tmp_path_factory.mktemp("ann") / "test_annotations.db"
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    import ion.models  # noqa: F401
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(db_engine) -> Generator[Session, None, None]:
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)
    session = factory()
    yield session
    session.close()


def _make_user_with_perms(db_session: Session, username: str, perm_names: list[str]) -> User:
    """Helper: create a user with the given permissions.

    Permission.name must match the string passed to require_permission() exactly
    (e.g. "case:create"). We reuse existing Permission rows if they exist
    (since each Permission name is unique across the module-scoped DB).
    """
    from sqlalchemy import select as _select

    perms = []
    for pname in perm_names:
        resource, action = pname.split(":", 1)
        existing = db_session.execute(
            _select(Permission).where(Permission.name == pname)
        ).scalar_one_or_none()
        if existing is None:
            p = Permission(name=pname, resource=resource, action=action)
            db_session.add(p)
            db_session.flush()
        else:
            p = existing
        perms.append(p)
    role = Role(name=f"role_{username}")
    db_session.add(role)
    db_session.flush()
    for p in perms:
        db_session.execute(
            role_permissions.insert().values(role_id=role.id, permission_id=p.id)
        )
    user = User(
        username=username,
        email=f"{username}@test.local",
        password_hash="x",
        display_name=username,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    db_session.execute(user_roles.insert().values(user_id=user.id, role_id=role.id))
    db_session.commit()
    return user


@pytest.fixture(scope="module")
def admin_user(db_session: Session) -> User:
    return _make_user_with_perms(
        db_session,
        "ann_admin",
        ["case:read", "case:create", "case:update", "case:close"],
    )


@pytest.fixture(scope="module")
def plain_user(db_session: Session) -> User:
    """User with case:update but NOT case:close — can only edit own annotations."""
    return _make_user_with_perms(
        db_session,
        "ann_plain",
        ["case:read", "case:update"],
    )


def _make_client(app, db_engine, user: User) -> TestClient:
    """Build a TestClient with the given user wired as the authenticated user."""
    factory = sessionmaker(bind=db_engine, expire_on_commit=False)

    def _override_session() -> Generator[Session, None, None]:
        s = factory()
        try:
            yield s
        finally:
            s.close()

    def _override_user() -> User:
        return user

    app.dependency_overrides[get_db_session] = _override_session
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture(scope="module")
def app_client(db_engine, admin_user: User) -> Generator[TestClient, None, None]:
    from ion.web.server import app
    client = _make_client(app, db_engine, admin_user)
    with client:
        yield client
    app.dependency_overrides.clear()
    reset_engine()


@pytest.fixture(scope="module")
def case_id(app_client: TestClient) -> int:
    """Create an AlertCase and return its id."""
    r = app_client.post(
        "/api/elasticsearch/alerts/cases",
        json={
            "title": "Annotation Smoke Case",
            "severity": "medium",
            "affected_hosts": [],
            "affected_users": [],
            "triggered_rules": [],
            "source_alert_ids": [],
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAlertCaseAnnotations:

    def test_01_create_annotation(self, app_client: TestClient, case_id: int):
        """POST annotation with valid body and timeline_ts returns 201 with id."""
        r = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T14:35:00", "body": "DNS beaconing resumed."},
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert "id" in data
        assert data["body"] == "DNS beaconing resumed."
        assert data["case_id"] == case_id
        assert "deleted_at" not in data

    def test_02_list_annotations(self, app_client: TestClient, case_id: int):
        """GET annotations list returns created annotation; deleted_at absent."""
        r = app_client.get(f"/api/alert-cases/{case_id}/annotations")
        assert r.status_code == 200, r.text
        data = r.json()
        assert "annotations" in data
        assert len(data["annotations"]) >= 1
        ann = data["annotations"][0]
        assert "deleted_at" not in ann
        assert ann["body"] == "DNS beaconing resumed."

    def test_03_update_annotation(self, app_client: TestClient, case_id: int):
        """PATCH annotation body returns 200 with updated content."""
        # Get the annotation id from the list
        anns = app_client.get(f"/api/alert-cases/{case_id}/annotations").json()["annotations"]
        ann_id = anns[0]["id"]

        r = app_client.patch(
            f"/api/alert-cases/{case_id}/annotations/{ann_id}",
            json={"body": "Updated: DNS beaconing confirmed C2."},
        )
        assert r.status_code == 200, r.text
        assert r.json()["body"] == "Updated: DNS beaconing confirmed C2."

    def test_04_delete_annotation(self, app_client: TestClient, case_id: int):
        """DELETE annotation; subsequent GET list does not include it."""
        # Create a fresh annotation to delete
        r = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T15:00:00", "body": "Temporary note."},
        )
        assert r.status_code == 201
        ann_id = r.json()["id"]

        del_r = app_client.delete(f"/api/alert-cases/{case_id}/annotations/{ann_id}")
        assert del_r.status_code == 200, del_r.text

        anns = app_client.get(f"/api/alert-cases/{case_id}/annotations").json()["annotations"]
        ids = [a["id"] for a in anns]
        assert ann_id not in ids, "soft-deleted annotation must not appear in list"

    def test_05_create_writes_ledger_row(self, app_client: TestClient, case_id: int):
        """POST annotation writes a ledger row with action='annotation_created'."""
        r = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T16:00:00", "body": "Ledger test annotation."},
        )
        assert r.status_code == 201
        ann_id = r.json()["id"]

        ledger = app_client.get(f"/api/alert-cases/{case_id}/ledger").json()
        entries = ledger["entries"]
        ann_entries = [e for e in entries if e.get("action") == "annotation_created"]
        assert len(ann_entries) >= 1, "Expected at least one annotation_created ledger entry"
        payloads = [e["payload"] for e in ann_entries]
        assert any(p.get("annotation_id") == ann_id for p in payloads), (
            f"No ledger entry with annotation_id={ann_id}"
        )

    def test_06_cross_case_patch_rejected(self, app_client: TestClient, case_id: int):
        """PATCH annotation via a different case's URL returns 404; annotation unchanged."""
        # Create a second case
        r_b = app_client.post(
            "/api/elasticsearch/alerts/cases",
            json={"title": "Cross-case B", "severity": "low",
                  "affected_hosts": [], "affected_users": [], "triggered_rules": [], "source_alert_ids": []},
        )
        assert r_b.status_code == 200
        case_b_id = r_b.json()["id"]

        # Create annotation on original case
        r_ann = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T17:00:00", "body": "Original body."},
        )
        assert r_ann.status_code == 201
        ann_id = r_ann.json()["id"]

        # Attempt PATCH via case B's URL
        r_bad = app_client.patch(
            f"/api/alert-cases/{case_b_id}/annotations/{ann_id}",
            json={"body": "Mutated by B"},
        )
        assert r_bad.status_code == 404, f"Expected 404, got {r_bad.status_code}"

        # Annotation must be unchanged
        anns = app_client.get(f"/api/alert-cases/{case_id}/annotations").json()["annotations"]
        ann = next((a for a in anns if a["id"] == ann_id), None)
        assert ann is not None
        assert ann["body"] == "Original body."

    def test_07_cross_case_delete_rejected(self, app_client: TestClient, case_id: int):
        """DELETE annotation via a different case's URL returns 404; annotation not deleted."""
        r_b = app_client.post(
            "/api/elasticsearch/alerts/cases",
            json={"title": "Cross-case C", "severity": "low",
                  "affected_hosts": [], "affected_users": [], "triggered_rules": [], "source_alert_ids": []},
        )
        assert r_b.status_code == 200
        case_c_id = r_b.json()["id"]

        r_ann = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T18:00:00", "body": "Must survive cross-case delete."},
        )
        assert r_ann.status_code == 201
        ann_id = r_ann.json()["id"]

        r_bad = app_client.delete(f"/api/alert-cases/{case_c_id}/annotations/{ann_id}")
        assert r_bad.status_code == 404, f"Expected 404, got {r_bad.status_code}"

        anns = app_client.get(f"/api/alert-cases/{case_id}/annotations").json()["annotations"]
        ids = [a["id"] for a in anns]
        assert ann_id in ids, "annotation must still exist after cross-case delete attempt"

    def test_08_empty_body_rejected(self, app_client: TestClient, case_id: int):
        """POST annotation with empty body returns 422."""
        r = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T19:00:00", "body": ""},
        )
        assert r.status_code == 422, r.text

    def test_09_body_too_long_rejected(self, app_client: TestClient, case_id: int):
        """POST annotation with body > 2000 chars returns 422."""
        r = app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T19:30:00", "body": "x" * 2001},
        )
        assert r.status_code == 422, r.text

    def test_10_edit_other_user_annotation_without_close(
        self, app_client: TestClient, db_engine, admin_user: User, plain_user: User, case_id: int
    ):
        """Edit another user's annotation without case:close returns 403."""
        from ion.web.server import app

        # Save the existing overrides set by the module-scoped app_client fixture
        saved_overrides = dict(app.dependency_overrides)
        factory = sessionmaker(bind=db_engine, expire_on_commit=False)

        def _session():
            s = factory()
            try:
                yield s
            finally:
                s.close()

        # Create annotation as admin_user (annotation will be owned by admin)
        app.dependency_overrides[get_db_session] = _session
        app.dependency_overrides[get_current_user] = lambda: admin_user
        with TestClient(app, raise_server_exceptions=True) as admin_c:
            r_ann = admin_c.post(
                f"/api/alert-cases/{case_id}/annotations",
                json={"timeline_ts": "2026-05-07T20:00:00", "body": "Admin-owned annotation."},
            )
            assert r_ann.status_code == 201, r_ann.text
            ann_id = r_ann.json()["id"]

        # Eagerly load plain_user's roles/permissions so has_permission works
        # without a live session (since the object comes from a different session).
        _ = [p.name for r in plain_user.roles for p in r.permissions]

        # Try to edit as plain_user (not author, no case:close)
        app.dependency_overrides[get_current_user] = lambda: plain_user
        with TestClient(app, raise_server_exceptions=True) as plain_c:
            r_bad = plain_c.patch(
                f"/api/alert-cases/{case_id}/annotations/{ann_id}",
                json={"body": "Trying to mutate admin annotation"},
            )
            assert r_bad.status_code == 403, f"Expected 403, got {r_bad.status_code}"

        # Restore original overrides so subsequent tests in the module still work
        app.dependency_overrides.clear()
        app.dependency_overrides.update(saved_overrides)

    def test_11_ledger_chain_valid_after_annotation(
        self, app_client: TestClient, case_id: int
    ):
        """GET /ledger/verify returns is_valid=true after annotation create."""
        # Create another annotation to ensure the chain was written
        app_client.post(
            f"/api/alert-cases/{case_id}/annotations",
            json={"timeline_ts": "2026-05-07T21:00:00", "body": "Chain check annotation."},
        )

        r = app_client.get(f"/api/alert-cases/{case_id}/ledger/verify")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data.get("is_valid") is True, f"Ledger chain broken: {data}"
