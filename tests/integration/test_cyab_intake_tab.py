"""Integration tests for the Intake tab — sub-profile-driven questions.

The plan literal references ``system.subprofile_id``, but the schema
actually stores the sub-profile tag on ``CyabDataSource`` (see
``ion.models.cyab.CyabDataSource.subprofile_id``). We attach a data
source carrying the sub-profile id; the server resolves the system's
intake sub-profile from its first tagged data source.
"""

import re

import pytest


@pytest.fixture
def seeded_subprofile(temp_db, monkeypatch):
    """Seed pillars + sub-profiles so the active_directory sub-profile exists.

    The seeder uses the global session factory; we monkey-patch
    ``get_engine`` to the temp_db so the seed lands in the per-test DB.
    """
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


def test_intake_tab_renders_questions(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="prod-intake-test")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r = client.get(f"/cyab/systems/{sys_id}/tab/intake")
    assert r.status_code == 200
    assert "intake-question" in r.text or "data-intake-q" in r.text


def test_intake_tab_shows_progress_count(client, make_system, seeded_subprofile, temp_db):
    sys_id = make_system(name="prod-intake-progress")
    _attach_source(temp_db, sys_id, seeded_subprofile)
    r = client.get(f"/cyab/systems/{sys_id}/tab/intake")
    # Format like "0 / N answered"
    assert re.search(r"\d+\s*/\s*\d+\s+answered", r.text, re.IGNORECASE)
