"""v0.96.2 — a KFP auto-close must push the closed status to Kibana inline.

The create-case endpoint creates the Kibana case as *open*, then, on a strong
Known-False-Positive match, flips ION's own status to CLOSED and posts an
auto-close Note to Kibana. Before this fix it stopped there: the Kibana case
kept ``status: open`` with only the note attached, and the status caught up
only whenever the periodic bidirectional reconciler next ran (up to a full
loop interval later, and not at all if the Kibana circuit breaker was open or
a reverse-sync race intervened).

Every other close path (the manual PATCH handler via
``_background_kibana_case_sync``) pushes the status with
``sync_case_update_to_kibana(status="closed")``. The auto-close must do the
same. This pins that it does — the same class of invariant as
``test_v078_bob_case_note_kibana_sync`` (a writer that skips the Kibana mirror
is silently invisible from the Kibana side).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _run_create_case(*, kibana_case_id):
    """Drive create_case through a strong-KFP auto-close with I/O seams mocked.

    Returns the sync_case_update_to_kibana mock so the caller can assert the
    status push (or its absence when there is no Kibana case).
    """
    import ion.web.case_lifecycle_api as mod
    from ion.models.alert_triage import AlertCaseStatus

    data = SimpleNamespace(
        title="Brute force on db-srv-01",
        description="repro",
        severity="high",
        assigned_to_id=None,
        affected_hosts=["db-srv-01"],
        affected_users=[],
        triggered_rules=["Brute Force Login Attempt Detected"],
        evidence_summary=None,
        alert_ids=None,
        alert_contexts=None,
    )
    current_user = SimpleNamespace(id=1, username="admin")
    session = MagicMock()

    # A strong match: rules + at least one other field triggers the auto-close.
    strong_match = [{
        "id": 1,
        "title": "Scheduled scanner brute force",
        "matched_fields": ["rules", "hosts"],
    }]

    kibana_create = {
        "kibana_case_id": kibana_case_id,
        "kibana_case_version": "WzEsMV0=",
        "kibana_url": "https://kibana/app/security/cases/x",
    } if kibana_case_id else None

    # assign_case_number and get_observable_service are imported inside
    # create_case, so patch them at their source modules, not on `mod`.
    obs_service = MagicMock()
    obs_service.enrich_and_link_observables_for_case = AsyncMock(return_value=[])

    with patch("ion.services.case_numbering.assign_case_number", return_value="CASE-0001"), \
         patch("ion.services.observable_service.get_observable_service", return_value=obs_service), \
         patch.object(mod, "_match_known_false_positives", return_value=strong_match), \
         patch.object(mod, "sync_new_case_to_kibana", return_value=kibana_create), \
         patch.object(mod, "sync_note_to_kibana") as _note, \
         patch.object(mod, "push_case_status_to_kibana", return_value=True) as _status, \
         patch.object(mod, "_should_investigate_new_case", return_value=False):
        result = asyncio.run(mod.create_case(data, current_user, session))

    assert result["auto_closed"] is True
    assert result["status"] in ("closed", AlertCaseStatus.CLOSED.value)
    return _status, _note


def test_autoclose_pushes_closed_status_to_kibana():
    """With a linked Kibana case, the auto-close mirrors the closed status."""
    status_mock, note_mock = _run_create_case(kibana_case_id="kc-123")

    note_mock.assert_called_once()  # the auto-close note still mirrors
    status_mock.assert_called_once()
    # Called with the case object, which is now CLOSED.
    case_arg = status_mock.call_args.args[1]
    status = case_arg.status.value if hasattr(case_arg.status, "value") else case_arg.status
    assert status == "closed"
    assert case_arg.kibana_case_id == "kc-123"


def test_autoclose_without_kibana_case_makes_no_status_call():
    """No linked Kibana case → nothing to push; must not raise or call sync."""
    status_mock, note_mock = _run_create_case(kibana_case_id=None)

    note_mock.assert_not_called()
    status_mock.assert_not_called()


# ---------------------------------------------------------------------------
# The shared helper: every close/transition path routes through this.
# ---------------------------------------------------------------------------


def _fake_case(*, kibana_case_id, status="closed", number="CASE-0009"):
    case = SimpleNamespace(
        kibana_case_id=kibana_case_id,
        case_number=number,
        status=status,
        kibana_case_version=None,
    )
    return case


def test_helper_pushes_current_status_and_persists_version():
    from ion.services import kibana_sync_helpers as h

    session = MagicMock()
    case = _fake_case(kibana_case_id="kc-9", status="closed")
    with patch.object(h, "sync_case_update_to_kibana",
                      return_value=("v2", None)) as _sync:
        assert h.push_case_status_to_kibana(session, case) is True
    kwargs = _sync.call_args.kwargs
    assert kwargs.get("kibana_case_id") == "kc-9"
    assert kwargs.get("status") == "closed"
    assert case.kibana_case_version == "v2"
    session.commit.assert_called_once()


def test_helper_noop_without_kibana_case():
    from ion.services import kibana_sync_helpers as h

    session = MagicMock()
    case = _fake_case(kibana_case_id=None)
    with patch.object(h, "sync_case_update_to_kibana") as _sync:
        assert h.push_case_status_to_kibana(session, case) is False
    _sync.assert_not_called()


def test_helper_never_raises_on_kibana_failure():
    from ion.services import kibana_sync_helpers as h

    session = MagicMock()
    case = _fake_case(kibana_case_id="kc-9")
    with patch.object(h, "sync_case_update_to_kibana",
                      side_effect=RuntimeError("kibana down")):
        assert h.push_case_status_to_kibana(session, case) is False


def test_close_as_known_fp_endpoint_mirrors_status():
    """The dedicated close-as-FP endpoint must push the close to Kibana."""
    import ion.web.case_lifecycle_api as mod
    from ion.models.alert_triage import AlertCaseStatus

    case = MagicMock()
    case.id = 9
    case.case_number = "CASE-0009"
    case.kibana_case_id = "kc-9"
    case.triage_entries = []
    kfp = MagicMock()
    kfp.title = "t"
    kfp.description = "d"

    session = MagicMock()
    session.query.return_value.filter_by.return_value.first.side_effect = [case, kfp]

    data = SimpleNamespace(known_fp_id=1)
    current_user = SimpleNamespace(id=1, username="admin")

    async def _noop_es(*a, **k):
        return None

    with patch.object(mod, "_sync_case_to_es", _noop_es), \
         patch.object(mod, "push_case_status_to_kibana") as _status:
        asyncio.run(mod.close_case_as_known_fp(9, data, current_user, session))

    assert case.status == AlertCaseStatus.CLOSED
    _status.assert_called_once()
    assert _status.call_args.args[1] is case
