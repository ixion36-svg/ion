"""v0.78.0 — Bob's per-case comment must reach the linked Kibana case.

The v0.78.0 feature moves Bob's automatic run from a per-alert sweep to one
cluster investigation per case, and posts the result as a Note on the case
(``_post_to_case(write_comment=True)``). That Note was written to ION's DB
only.

ION mirrors case notes into the linked Kibana case everywhere else — the
interactive ``add_case_note`` path, the closure note, the MCP tool, the
v0.59.0 enrichment note, and (since the fix these tests are modelled on) the
PCAP report note. A note-writer that skips the mirror is invisible to anyone
working the case from the Kibana side, and the omission is silent: nothing
errors, the comment simply never appears.

Same shape as ``test_pcap_note_kibana_sync.py``, which pins the identical fix
on the PCAP path.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _run_post_to_case(*, kibana_case_id, write_comment=True, bob_username="bob"):
    """Drive ``_post_to_case`` with every I/O seam mocked.

    Returns (mock_sync, session) so callers can assert on both the Kibana push
    and the DB write.
    """
    from ion.models.alert_triage import AlertCase, AlertCaseStatus
    from ion.models.user import User
    from ion.services.investigation_service import InvestigationService

    triage = MagicMock()
    triage.case_id = 7

    case_obj = MagicMock()
    case_obj.id = 7
    case_obj.kibana_case_id = kibana_case_id
    case_obj.source_alert_ids = ["a1", "a2", "a3"]
    case_obj.observables = []
    # Not the OPEN member, so the ACKNOWLEDGED transition is skipped and the
    # test stays focused on the comment path.
    case_obj.status = AlertCaseStatus.ACKNOWLEDGED

    user_obj = MagicMock()
    user_obj.username = bob_username

    session = MagicMock()
    session.query.return_value.filter_by.return_value.first.return_value = triage

    def _get(model, pk):
        if model is AlertCase:
            return case_obj
        if model is User:
            return user_obj
        return None

    session.get.side_effect = _get

    svc = InvestigationService.__new__(InvestigationService)

    with patch("ion.storage.database.get_session_factory", return_value=lambda: session), \
         patch("ion.services.ai_user.get_bob_user_id", return_value=42), \
         patch("ion.services.kibana_sync_helpers.sync_note_to_kibana") as mock_sync:
        asyncio.run(svc._post_to_case(
            alert_id="alert-1",
            inv_id=1,
            verdict="true_positive",
            severity="high",
            summary="Encoded PowerShell download cradle.",
            actions=["Isolate host"],
            mitre_tags=["T1059.001"],
            iocs=None,
            write_comment=write_comment,
            cluster_size=3,
        ))

    return mock_sync, session


def test_bob_case_comment_is_mirrored_to_kibana():
    mock_sync, session = _run_post_to_case(kibana_case_id="kb-901")

    assert session.add.called, "the Note was never written to ION"
    mock_sync.assert_called_once()
    kb_id, username, body = mock_sync.call_args[0]
    assert kb_id == "kb-901"
    assert username == "bob"
    # The mirrored body is Bob's rendered comment, not a placeholder.
    assert "Bob (AI analyst)" in body
    assert "true_positive" in body


def test_kibana_sync_skipped_when_case_has_no_link():
    """An unlinked case must not attempt a push — and must still write the Note."""
    mock_sync, session = _run_post_to_case(kibana_case_id=None)

    assert session.add.called
    mock_sync.assert_not_called()


def test_per_alert_callers_neither_comment_nor_sync():
    """``write_comment=False`` is the per-alert path. It stayed comment-free at
    v0.23.1 precisely because one Bob note per alert buried analyst notes —
    mirroring those to Kibana would spread the same noise further."""
    mock_sync, _session = _run_post_to_case(kibana_case_id="kb-901", write_comment=False)

    mock_sync.assert_not_called()


def test_cluster_size_reaches_the_rendered_comment():
    """The comment says "analysed N alerts"; N comes from cluster_size."""
    mock_sync, _session = _run_post_to_case(kibana_case_id="kb-901")

    _kb, _user, body = mock_sync.call_args[0]
    assert "3 alerts" in body
