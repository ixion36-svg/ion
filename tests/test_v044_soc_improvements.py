"""v0.44.0 — SOC QoL improvements.

Covers two of the four v0.44.0 changes at the unit level (the other two —
the /cases show-all toggle and the closure-rewrite length cap — are exercised
by the frontend and test_v042_0_closure_rewrite.py respectively):

* #1 Daily-work editable timed entries — the worklog service gains
  ``logged_at`` on create plus owner-scoped ``update_entry`` / ``delete_entry``,
  and manual timeline items now carry their ``id`` so the UI can edit them.
* #3 Bob case-wide analysis — ``_render_alert_fields_section`` lays out the
  well-known fields of EVERY linked alert (de-duplicating the shared detection
  rule prose) so a multi-alert case gets one overall analysis.
"""

from datetime import date, datetime

# Importing the model registers its table on Base.metadata for the conftest
# `session` fixture's create_all().
from ion.models.worklog import WorkLogEntry, seed_default_task_types
from ion.services import worklog_service
from ion.web.bob_analysis_api import _render_alert_fields_section


# ── #1 daily-work: timed + editable entries ──────────────────────────────


def test_add_entry_accepts_explicit_logged_at(session):
    seed_default_task_types(session)
    when = datetime(2026, 6, 25, 14, 30, 0)
    entry = worklog_service.add_entry(session, 7, "meeting", "Stand-up", logged_at=when)
    session.commit()
    assert entry.logged_at == when


def test_add_entry_strips_timezone_to_naive(session):
    from datetime import timezone

    aware = datetime(2026, 6, 25, 9, 0, 0, tzinfo=timezone.utc)
    entry = worklog_service.add_entry(session, 7, "note", "tz test", logged_at=aware)
    session.commit()
    assert entry.logged_at.tzinfo is None
    assert entry.logged_at == datetime(2026, 6, 25, 9, 0, 0)


def test_update_entry_edits_time_type_and_text(session):
    entry = worklog_service.add_entry(session, 7, "note", "original")
    session.commit()
    new_time = datetime(2026, 6, 25, 16, 45, 0)
    updated = worklog_service.update_entry(
        session, 7, entry.id, task_type="meeting", text="edited", logged_at=new_time
    )
    session.commit()
    assert updated is not None
    assert updated.task_type == "meeting"
    assert updated.text == "edited"
    assert updated.logged_at == new_time


def test_update_entry_owner_scoped(session):
    """A non-owner must never be able to mutate another analyst's entry."""
    entry = worklog_service.add_entry(session, 7, "note", "mine")
    session.commit()
    # Wrong user → no mutation, returns None.
    assert worklog_service.update_entry(session, 99, entry.id, text="hijacked") is None
    session.commit()
    fetched = session.query(WorkLogEntry).filter_by(id=entry.id).one()
    assert fetched.text == "mine"


def test_delete_entry_owner_scoped(session):
    entry = worklog_service.add_entry(session, 7, "note", "mine")
    session.commit()
    # Wrong user → nothing deleted.
    assert worklog_service.delete_entry(session, 99, entry.id) is False
    session.commit()
    assert session.query(WorkLogEntry).filter_by(id=entry.id).count() == 1
    # Owner → deleted.
    assert worklog_service.delete_entry(session, 7, entry.id) is True
    session.commit()
    assert session.query(WorkLogEntry).filter_by(id=entry.id).count() == 0


def test_delete_missing_entry_returns_false(session):
    assert worklog_service.delete_entry(session, 7, 999999) is False


def test_manual_items_carry_id_for_editing(session):
    when = datetime(2026, 6, 25, 11, 0, 0)
    entry = worklog_service.add_entry(session, 7, "hunt", "threat hunt", logged_at=when)
    session.commit()
    start = datetime.combine(date(2026, 6, 25), datetime.min.time())
    end = datetime.combine(date(2026, 6, 25), datetime.max.time())
    items = worklog_service._manual_items(session, 7, start, end)
    assert len(items) == 1
    assert items[0]["id"] == entry.id
    assert items[0]["source"] == "logged"
    assert items[0]["time"] == "11:00"


# ── #3 bob: case-wide per-alert field rendering ──────────────────────────


def _summary(es_id, rule, fields):
    return {"es_id": es_id, "rule_name": rule, "fields": fields}


def test_render_alert_fields_lists_every_alert():
    summaries = [
        _summary("A1", "Encoded PowerShell", {"host": "ws-01", "process_name": "powershell.exe"}),
        _summary("A2", "Encoded PowerShell", {"host": "ws-02", "process_name": "cmd.exe"}),
    ]
    md = "\n".join(_render_alert_fields_section(summaries, total_alerts=2))
    assert "## Well-known fields across all alerts" in md
    assert "### Alert 1 — `A1`" in md
    assert "### Alert 2 — `A2`" in md
    assert "ws-01" in md and "ws-02" in md
    assert "powershell.exe" in md and "cmd.exe" in md


def test_render_dedupes_shared_rule_prose():
    """Rule description/guide are shown once, not repeated per alert."""
    fields = {
        "host": "ws-01",
        "rule_description": "Detects base64 PowerShell.",
        "rule_investigation_guide": "Inspect the parent process.",
    }
    summaries = [_summary("A1", "R", dict(fields)), _summary("A2", "R", dict(fields))]
    md = "\n".join(_render_alert_fields_section(summaries, total_alerts=2))
    assert md.count("Detects base64 PowerShell.") == 1
    assert "### Detection rule context" in md
    assert "What this rule detects:" in md
    # The rule prose lives in the dedicated section, not duplicated as a flat
    # per-alert field line.
    assert "- rule_description:" not in md
    assert "- rule_investigation_guide:" not in md


def test_render_notes_truncated_alerts():
    summaries = [_summary("A1", "R", {"host": "ws-01"})]
    md = "\n".join(_render_alert_fields_section(summaries, total_alerts=5))
    assert "4 more alert(s)" in md


def test_render_handles_no_alert_data():
    md = "\n".join(_render_alert_fields_section([], total_alerts=0))
    assert "Elasticsearch unavailable" in md
