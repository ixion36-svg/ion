"""Integration tests for the Audit Use Cases tab.

Same shape as the Detection tab tests (Task 9) — we use the project-wide
``client`` + ``make_system`` fixtures from conftest, and resolve the system's
sub-profile from a tagged ``CyabDataSource`` (per Task 5 finding).

The handler branch (``if tab_name in ("detection", "audit-use-cases")``) is
already wired in Task 9; this task just exercises the new template and
verifies the heading + key (``audit_use_cases``) differ from Detection.
"""

import pytest


@pytest.fixture
def seeded_subprofile(temp_db, monkeypatch):
    """Seed pillars + sub-profiles so the active_directory sub-profile exists."""
    monkeypatch.setattr(
        "ion.storage.database.get_engine", lambda *_a, **_k: temp_db
    )
    from ion.storage.database import reset_engine
    reset_engine()
    from ion.services.cyab_subprofile_service import seed_catalogue
    seed_catalogue()
    return "active_directory"


def _attach_source(temp_db, system_id: int, subprofile_id: str) -> int:
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabDataSource
    Session = sessionmaker(bind=temp_db)
    s = Session()
    src = CyabDataSource(
        system_id=system_id,
        name="winlog",
        data_source_type="windows_security",
        subprofile_id=subprofile_id,
    )
    s.add(src)
    s.commit()
    src_id = src.id
    s.close()
    return src_id


def test_audit_uc_tab_returns_partial(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="aud-test")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r = client.get(f"/cyab/systems/{sys_id}/tab/audit-use-cases")
    assert r.status_code == 200
    # Partial — no full HTML document.
    assert "<html" not in r.text
    assert "Audit Use Cases" in r.text


def test_audit_uc_tab_distinct_from_detection(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="aud-vs-det")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r1 = client.get(f"/cyab/systems/{sys_id}/tab/detection")
    r2 = client.get(f"/cyab/systems/{sys_id}/tab/audit-use-cases")
    assert r1.status_code == 200
    assert r2.status_code == 200
    # Headings differ — Audit Use Cases must appear in r2 but not in r1.
    assert "Audit Use Cases" in r2.text
    assert "Audit Use Cases" not in r1.text


def test_audit_uc_tab_no_subprofile_empty_state(client, make_system):
    """If the system has no tagged data source, show an empty state."""
    sys_id = make_system(name="aud-no-sub")
    r = client.get(f"/cyab/systems/{sys_id}/tab/audit-use-cases")
    assert r.status_code == 200
    assert "no sub-profile" in r.text.lower() or "no audit" in r.text.lower()
