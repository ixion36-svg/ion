"""Regression: PCAP auto-analysis notes must be mirrored to Kibana.

Bug: ``pcap_analysis_service._post_case_note`` wrote the Note to ION's DB only
and never called ``sync_note_to_kibana`` — so the PCAP analysis comment never
appeared on the linked Kibana case, unlike the interactive ``add_case_note``
path (case_lifecycle_api) and the v0.59.0 threat-enrichment note path.

These tests pin the fix: after committing the note, ``_post_case_note`` loads
the case's ``kibana_case_id`` and Bob's username and calls
``sync_note_to_kibana`` — and stays a silent no-op when the case has no Kibana
link.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _run_post_case_note(*, kibana_case_id, bob_id=42, bob_username="bob"):
    """Drive _post_case_note with all its I/O seams mocked.

    Returns the MagicMock standing in for sync_note_to_kibana so the caller can
    assert on the Kibana push.
    """
    from ion.models.alert_triage import AlertCase
    from ion.models.user import User
    from ion.services import pcap_analysis_service as svc

    case_obj = MagicMock()
    case_obj.kibana_case_id = kibana_case_id
    user_obj = MagicMock()
    user_obj.username = bob_username

    session = MagicMock()

    def _get(model, pk):
        if model is AlertCase:
            return case_obj
        if model is User:
            return user_obj
        return None

    session.get.side_effect = _get

    with patch("ion.core.config.get_config", return_value=MagicMock(db_path=":memory:")), \
         patch("ion.storage.database.get_engine", return_value=object()), \
         patch("ion.storage.database.get_session_factory", return_value=lambda: session), \
         patch("ion.services.ai_user.get_bob_user_id", return_value=bob_id), \
         patch("ion.services.kibana_sync_helpers.sync_note_to_kibana") as mock_sync:
        svc._post_case_note(555, "## PCAP report\n\nbeaconing detected")

    # The note write still happens exactly once regardless of Kibana state.
    assert session.add.called
    assert session.commit.called
    return mock_sync


def test_pcap_note_is_pushed_to_kibana_when_case_is_linked():
    mock_sync = _run_post_case_note(kibana_case_id="kb-777", bob_username="bob")
    mock_sync.assert_called_once_with(
        "kb-777", "bob", "## PCAP report\n\nbeaconing detected"
    )


def test_pcap_note_skips_kibana_when_case_has_no_link():
    mock_sync = _run_post_case_note(kibana_case_id=None)
    mock_sync.assert_not_called()
