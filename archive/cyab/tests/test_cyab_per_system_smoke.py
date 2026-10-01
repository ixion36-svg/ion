"""End-to-end smoke test covering the per-system page across all 7 tabs.

A single fully-seeded system (sub-profile catalogue + a data source wired to
a sub-profile + the doc checklist seeded with one item marked done) is the
fixture; every tab partial is exercised against it to catch cross-tab
regressions before release.
"""

import pytest


@pytest.fixture
def fully_seeded_system(temp_db, make_system):
    """A system with sub-profile, a data source, and a checklist item done.

    Returns the system id. Uses the conftest ``make_system`` factory for the
    base row and wires sub-profile + data source manually.
    """
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabDataSource
    from ion.services.cyab_subprofile_service import seed_catalogue
    from ion.services.cyab_doc_checklist_service import (
        seed_for_system,
        list_for_system,
        update_item,
    )

    seed_catalogue()

    sys_id = make_system(
        name="prod-smoke",
        department="Identity",
        owner="Alice",
        containment_authority="SOC Lead",
    ) if "owner" in _system_columns() else make_system(
        name="prod-smoke",
        department="Identity",
        containment_authority="SOC Lead",
    )

    Session = sessionmaker(bind=temp_db)
    s = Session()
    try:
        s.add(CyabDataSource(
            system_id=sys_id,
            name="winlog",
            data_source_type="windows-evtx",
            field_mapping='{"@timestamp": "ts", "host.name": "host"}',
            subprofile_id="active_directory",
        ))
        s.commit()
        seed_for_system(s, sys_id)
        items = list_for_system(s, sys_id)
        if items:
            update_item(s, items[0]["id"], status="done")
    finally:
        s.close()

    return sys_id


def _system_columns():
    """Return the set of column names on CyabSystem (used to skip-set ``owner``
    if the model never gained that field)."""
    from ion.models.cyab import CyabSystem
    return {c.name for c in CyabSystem.__table__.columns}


def test_full_page_loads(client, fully_seeded_system):
    r = client.get(f"/cyab/systems/{fully_seeded_system}")
    assert r.status_code == 200, r.text
    assert "prod-smoke" in r.text
    assert "onboarding-progress" in r.text


@pytest.mark.parametrize("tab", [
    "overview", "intake", "sources", "data-health",
    "detection", "audit-use-cases", "signoff",
])
def test_each_tab_loads_for_seeded_system(client, fully_seeded_system, tab):
    r = client.get(f"/cyab/systems/{fully_seeded_system}/tab/{tab}")
    assert r.status_code == 200, f"Tab {tab} returned {r.status_code}: {r.text[:200]}"
    assert len(r.text) > 100, f"Tab {tab} returned suspiciously short content"
