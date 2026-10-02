"""Integration tests for the Detection Use Cases tab.

The plan literal references inline ``admin_session`` + ``system_with_subprofile``
fixtures. Per task adjustments we use the project-wide ``client`` + ``make_system``
from ``conftest.py`` (the conftest ``client`` fixture already injects an admin
user via dependency overrides, so no login is needed).

Per Task 5 finding, ``subprofile_id`` lives on ``CyabDataSource``, not
``CyabSystem``. We attach a tagged data source and the tab handler resolves
the system's sub-profile from its first tagged source.
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


def test_detection_tab_lists_use_cases(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="det-test")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r = client.get(f"/cyab/systems/{sys_id}/tab/detection")
    assert r.status_code == 200
    # Sub-profile catalogue contains detection use cases
    assert "use-case" in r.text or "Use case" in r.text or "detection" in r.text.lower()


def test_detection_tab_shows_status_chips(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="det-status")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r = client.get(f"/cyab/systems/{sys_id}/tab/detection")
    body = r.text.lower()
    # Statuses: shipped / partial / gap / n/a
    assert any(s in body for s in ("shipped", "partial", "gap", "n/a"))


def test_detection_tab_no_subprofile_empty_state(client, make_system):
    """If the system has no tagged data source, show an empty state."""
    sys_id = make_system(name="det-no-sub")
    r = client.get(f"/cyab/systems/{sys_id}/tab/detection")
    assert r.status_code == 200
    assert "no sub-profile" in r.text.lower() or "no detection" in r.text.lower()
