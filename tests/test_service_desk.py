"""Tests for the service-desk features — bug reports (→ GitLab) and CAB change
requests (status workflow + CHANGELOG-delta auto-fill).

GitLab is faked; the DB is the in-memory `session` fixture from conftest.
"""

import asyncio

from ion.models.service_desk import BugReportStatus, ChangeRequestStatus
from ion.services import service_desk_service as svc

_SAMPLE_CHANGELOG = """# Changelog

## v0.49.0 — 2026-07-01

- Big new feature.

## v0.48.1 — 2026-06-30

- RTMON rework.
- pptx fix.

## v0.48.0 — 2026-06-29

- AD briefing decks.
"""


# ── CHANGELOG parsing ────────────────────────────────────────────────────────
def test_changelog_sections_parse():
    secs = svc._parse_changelog_sections(_SAMPLE_CHANGELOG)
    vers = [v for v, _ in secs]
    assert vers == ["0.49.0", "0.48.1", "0.48.0"]


def test_changelog_between_range():
    delta = svc.changelog_between("0.48.0", "0.49.0", text=_SAMPLE_CHANGELOG)
    assert "v0.49.0" in delta and "v0.48.1" in delta  # both introduced by the upgrade
    assert "v0.48.0" not in delta  # the version we're upgrading FROM is excluded


def test_changelog_between_fallback_to_target_section():
    # current == target tuple has no (current, target] range → fall back to target section
    delta = svc.changelog_between("0.49.0", "0.49.0", text=_SAMPLE_CHANGELOG)
    assert "v0.49.0" in delta


def test_changelog_between_missing_is_empty():
    assert svc.changelog_between("0.1.0", "0.2.0", text="no headings here") == ""


# ── reference generation ─────────────────────────────────────────────────────
def test_next_cr_reference(session):
    assert svc.next_cr_reference(session) == "CR-0001"


# ── bug reports ──────────────────────────────────────────────────────────────
class _FakeIssue:
    def __init__(self, state="opened"):
        self.iid = 42
        self.web_url = "http://gitlab.local/ion/issues/42"
        self.state = state


class _FakeGitLab:
    is_configured = True

    def __init__(self, state="opened"):
        self._state = state
        self.created = []

    async def create_issue(self, **kwargs):
        self.created.append(kwargs)
        return _FakeIssue(self._state)

    async def get_issue(self, iid):
        return _FakeIssue(self._state)


def test_create_bug_report_gitlab_unconfigured(session):
    br = asyncio.run(svc.create_bug_report(
        session, 1, {"title": "X", "description": "broke", "severity": "high"}
    ))
    assert br.id and br.status == BugReportStatus.OPEN
    assert br.gitlab_issue_iid is None
    assert br.gitlab_error  # records why no issue was created
    assert br.ion_version  # captured


def test_create_bug_report_gitlab_success(session, monkeypatch):
    import ion.services.gitlab_service as gl
    fake = _FakeGitLab()
    monkeypatch.setattr(gl, "get_gitlab_service", lambda: fake)
    br = asyncio.run(svc.create_bug_report(
        session, 1, {"title": "Crash", "description": "boom", "severity": "critical", "component": "/alerts"}
    ))
    assert br.gitlab_issue_iid == 42
    assert br.gitlab_issue_url.endswith("/42")
    assert br.gitlab_state == "opened"
    assert br.gitlab_error is None
    # issue body carries the operating context
    body = fake.created[0]["description"]
    assert "Severity" in body and "/alerts" in body


def test_sync_bug_report_maps_closed_to_resolved(session, monkeypatch):
    import ion.services.gitlab_service as gl
    monkeypatch.setattr(gl, "get_gitlab_service", lambda: _FakeGitLab(state="opened"))
    br = asyncio.run(svc.create_bug_report(session, 1, {"title": "X", "description": "y"}))
    assert br.status == BugReportStatus.OPEN
    # now GitLab reports the issue closed
    monkeypatch.setattr(gl, "get_gitlab_service", lambda: _FakeGitLab(state="closed"))
    br = asyncio.run(svc.sync_bug_report(session, br))
    assert br.gitlab_state == "closed"
    assert br.status == BugReportStatus.RESOLVED


# ── change requests ──────────────────────────────────────────────────────────
def test_create_change_request_autofills(session, monkeypatch):
    monkeypatch.setattr(svc, "_find_changelog", lambda: _SAMPLE_CHANGELOG)
    monkeypatch.setattr(svc, "_ion_version", lambda: "0.48.0")
    cr = asyncio.run(svc.create_change_request(
        session, 1, {"target_version": "0.49.0", "justification": "feature"}, create_gitlab=False
    ))
    assert cr.reference == "CR-0001"
    assert cr.status == ChangeRequestStatus.DRAFT
    assert cr.current_version == "0.48.0" and cr.target_version == "0.49.0"
    assert cr.changes and "v0.49.0" in cr.changes  # pulled from changelog delta
    assert cr.backout_plan and "ION_VERSION" in cr.backout_plan  # pre-filled
    assert cr.title  # defaulted


def test_create_change_request_non_upgrade_type(session, monkeypatch):
    # A non-upgrade change type: no target version, no changelog auto-fill,
    # title defaults to the change type.
    monkeypatch.setattr(svc, "_find_changelog", lambda: _SAMPLE_CHANGELOG)
    cr = asyncio.run(svc.create_change_request(
        session, 1, {"change_type": "Patching", "justification": "monthly patches"},
        create_gitlab=False,
    ))
    assert cr.change_type == "Patching"
    assert cr.target_version is None
    assert cr.changes is None  # changelog delta is upgrade-only
    assert cr.title == "Patching"  # defaulted to the change type


def test_create_change_request_gitlab_linked(session, monkeypatch):
    import ion.services.gitlab_service as gl
    fake = _FakeGitLab()
    monkeypatch.setattr(gl, "get_gitlab_service", lambda: fake)
    monkeypatch.setattr(svc, "_find_changelog", lambda: _SAMPLE_CHANGELOG)
    cr = asyncio.run(svc.create_change_request(
        session, 1, {"target_version": "0.49.0"}, create_gitlab=True
    ))
    assert cr.gitlab_issue_iid == 42
    assert "[CAB]" in fake.created[0]["title"]


def test_cr_transition_happy_path(session, monkeypatch):
    monkeypatch.setattr(svc, "_find_changelog", lambda: None)
    cr = asyncio.run(svc.create_change_request(session, 1, {"target_version": "0.49.0"}, create_gitlab=False))
    for action, expected in [
        ("submit", ChangeRequestStatus.SUBMITTED),
        ("approve", ChangeRequestStatus.APPROVED),
        ("schedule", ChangeRequestStatus.SCHEDULED),
        ("implement", ChangeRequestStatus.IMPLEMENTED),
        ("close", ChangeRequestStatus.CLOSED),
    ]:
        svc.transition_change_request(session, cr, action, user_id=7)
        assert cr.status == expected
    assert cr.implemented_at is not None


def test_cr_transition_illegal_raises(session, monkeypatch):
    monkeypatch.setattr(svc, "_find_changelog", lambda: None)
    cr = asyncio.run(svc.create_change_request(session, 1, {"target_version": "0.49.0"}, create_gitlab=False))
    # can't approve a draft (must submit first)
    try:
        svc.transition_change_request(session, cr, "approve", user_id=7)
        assert False, "expected ValueError"
    except ValueError:
        pass
    # unknown action
    try:
        svc.transition_change_request(session, cr, "frobnicate", user_id=7)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_cr_reject_stamps_decision(session, monkeypatch):
    monkeypatch.setattr(svc, "_find_changelog", lambda: None)
    cr = asyncio.run(svc.create_change_request(session, 1, {"target_version": "0.49.0"}, create_gitlab=False))
    svc.transition_change_request(session, cr, "submit", user_id=1)
    svc.transition_change_request(session, cr, "reject", user_id=9, notes="too risky this window")
    assert cr.status == ChangeRequestStatus.REJECTED
    assert cr.decided_by_id == 9
    assert cr.decided_at is not None
    assert cr.decision_notes == "too risky this window"


def test_cab_markdown_contains_all_fields(session, monkeypatch):
    monkeypatch.setattr(svc, "_find_changelog", lambda: None)
    cr = asyncio.run(svc.create_change_request(
        session, 1,
        {"target_version": "0.49.0", "justification": "J", "impact": "I",
         "implementation_plan": "P", "test_plan": "T"},
        create_gitlab=False,
    ))
    md = svc.cab_markdown(cr)
    for needle in ["Change Request CR-0001", "Justification", "Backout / rollback plan",
                   "Implementation plan", "Test / validation plan", "0.49.0"]:
        assert needle in md
