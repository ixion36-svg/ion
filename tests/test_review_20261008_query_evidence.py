"""Query evidence capture (8 Oct 2026 review, §9, stage 3).

    "Preserve query evidence containing query, index/scope, time window,
    execution time, returned count/truncation and selected results. Pin it
    to a case and rerun without overwriting original evidence."

Discover could run a search and, after stage 2, export the rows to CSV. What
it could not do was make the search itself part of the case. An analyst who
found the decisive evidence by searching had to paste a screenshot or retype
the query into a note, which loses the two things that make a search
reproducible: the exact scope it ran against and the window it covered.

This rides on the existing evidence pin + hash-chained ledger rather than a
new table. ``PinSourceType`` is a VARCHAR precisely so a new source can be
added without a migration, so a captured query is a pin of source type
``query`` whose metadata carries the full provenance.

Two honesty requirements, continuing stage 2's line:

* **Truncation must not be guessed.** If the search backend did not report a
  total, ION does not know whether the rows it has are all of them.
  ``truncated`` is then ``None`` with ``truncation_known`` false, rather than
  the convenient ``False``.
* **A rerun is new evidence, never an overwrite.** The original capture is
  what the analyst drew their conclusion from. A rerun months later against
  rolled indices legitimately returns something else, and the case has to keep
  both. So a rerun creates a second pin linked by ``rerun_of``, and the
  original row must come back byte-identical.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase
from ion.models.base import Base
from ion.models.case_evidence import CaseEvidencePin, PinSourceType
from ion.models.user import User
from ion.services import case_ledger_service, query_evidence_service
from ion.services.query_evidence_service import QueryEvidenceError


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'query_evidence.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    s.add(User(id=1, username="alice", email="a@x", password_hash="x",
               display_name="Alice", is_active=True))
    s.add(AlertCase(id=1, case_number="CASE-0001", title="Beaconing from finance VLAN",
                    severity="high", created_by_id=1))
    s.commit()
    yield s
    s.close()


_T0 = datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)


def _capture(db, **over):
    kwargs = dict(
        alert_case_id=1,
        actor_id=1,
        query='process.name:"rundll32.exe" and destination.port:443',
        index="logs-endpoint-*",
        time_from=_T0,
        time_to=_T1,
        duration_ms=412,
        returned_count=37,
        total_hits=37,
    )
    kwargs.update(over)
    return query_evidence_service.capture_query_evidence(db, **kwargs)


def _meta(pin):
    return pin.pin_metadata or {}


# ── What a capture preserves ─────────────────────────────────────────────


class TestProvenance:
    def test_the_capture_is_a_query_pin(self, db):
        pin = _capture(db)
        assert pin.source_type == PinSourceType.QUERY.value == "query"
        assert pin.alert_case_id == 1
        assert pin.pinned_by_id == 1

    def test_the_query_text_is_preserved_verbatim(self, db):
        pin = _capture(db)
        assert _meta(pin)["query"]["text"] == (
            'process.name:"rundll32.exe" and destination.port:443'
        )

    def test_the_query_language_is_recorded(self, db):
        """A bare string is ambiguous between KQL, Lucene and a DSL body."""
        pin = _capture(db, language="lucene")
        assert _meta(pin)["query"]["language"] == "lucene"

    def test_the_language_defaults_to_kql_and_says_it_is_a_default(self, db):
        pin = _capture(db)
        q = _meta(pin)["query"]
        assert q["language"] == "kql"
        assert q["language_assumed"] is True

    def test_an_explicit_language_is_not_marked_assumed(self, db):
        pin = _capture(db, language="dsl")
        assert _meta(pin)["query"]["language_assumed"] is False

    def test_an_unknown_language_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            _capture(db, language="sql")

    def test_the_index_scope_is_preserved(self, db):
        pin = _capture(db)
        assert _meta(pin)["scope"]["index"] == "logs-endpoint-*"

    def test_the_time_window_is_preserved(self, db):
        pin = _capture(db)
        window = _meta(pin)["time_window"]
        assert window["from"] == _T0.isoformat()
        assert window["to"] == _T1.isoformat()
        assert window["bounded"] is True

    def test_execution_time_is_preserved(self, db):
        pin = _capture(db)
        execution = _meta(pin)["execution"]
        assert execution["duration_ms"] == 412
        assert execution["executed_at"]
        assert execution["executed_by"] == "alice"

    def test_an_explicit_execution_timestamp_is_kept(self, db):
        """Capture may happen a moment after the search; the search's own
        timestamp is the one that matters for reproducing it."""
        ran = datetime(2026, 10, 8, 8, 59, 30, tzinfo=timezone.utc)
        pin = _capture(db, executed_at=ran)
        assert _meta(pin)["execution"]["executed_at"] == ran.isoformat()

    def test_the_returned_count_is_preserved(self, db):
        pin = _capture(db)
        assert _meta(pin)["results"]["returned"] == 37

    def test_the_capture_version_is_stamped(self, db):
        """Evidence outlives the code that wrote it."""
        pin = _capture(db)
        assert _meta(pin)["capture_version"] == query_evidence_service.CAPTURE_VERSION
        assert _meta(pin)["kind"] == "query_evidence"

    def test_the_title_names_the_scope_when_none_is_given(self, db):
        pin = _capture(db)
        assert "logs-endpoint-*" in pin.title

    def test_an_analyst_title_wins(self, db):
        pin = _capture(db, title="rundll32 beaconing to 443")
        assert pin.title == "rundll32 beaconing to 443"

    def test_an_analyst_note_is_the_pin_summary(self, db):
        pin = _capture(db, note="Only three hosts, all in finance.")
        assert pin.summary == "Only three hosts, all in finance."


# ── Truncation honesty ───────────────────────────────────────────────────


class TestTruncation:
    def test_a_complete_result_set_is_not_truncated(self, db):
        pin = _capture(db, returned_count=37, total_hits=37)
        results = _meta(pin)["results"]
        assert results["truncated"] is False
        assert results["truncation_known"] is True

    def test_fewer_rows_than_hits_is_truncated(self, db):
        pin = _capture(db, returned_count=500, total_hits=12840)
        results = _meta(pin)["results"]
        assert results["truncated"] is True
        assert results["truncation_known"] is True
        assert results["total_hits"] == 12840

    def test_an_unknown_total_leaves_truncation_unknown(self, db):
        """The convenient answer is False. ION does not know, so it says so."""
        pin = _capture(db, returned_count=500, total_hits=None)
        results = _meta(pin)["results"]
        assert results["truncated"] is None
        assert results["truncation_known"] is False
        assert results["total_hits"] is None

    def test_an_explicit_truncation_flag_is_believed(self, db):
        """Some backends report "there are more" without a count."""
        pin = _capture(db, returned_count=500, total_hits=None, truncated=True)
        results = _meta(pin)["results"]
        assert results["truncated"] is True
        assert results["truncation_known"] is True

    def test_a_total_below_the_returned_count_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            _capture(db, returned_count=10, total_hits=3)

    def test_a_negative_returned_count_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            _capture(db, returned_count=-1)

    def test_a_zero_result_search_is_capturable(self, db):
        """"Nothing matched" is a finding, and often the decisive one."""
        pin = _capture(db, returned_count=0, total_hits=0, selected_results=None)
        results = _meta(pin)["results"]
        assert results["returned"] == 0
        assert results["truncated"] is False


# ── Selected results ─────────────────────────────────────────────────────


class TestSelectedResults:
    def test_selected_rows_are_stored(self, db):
        rows = [{"_id": "a", "host": "fin-01"}, {"_id": "b", "host": "fin-02"}]
        pin = _capture(db, selected_results=rows)
        results = _meta(pin)["results"]
        assert results["selected"] == rows
        assert results["selected_count"] == 2

    def test_no_selection_is_an_empty_set_not_a_missing_key(self, db):
        pin = _capture(db, selected_results=None)
        results = _meta(pin)["results"]
        assert results["selected"] == []
        assert results["selected_count"] == 0

    def test_the_selection_is_capped_and_the_cap_is_recorded(self, db):
        rows = [{"_id": str(i)} for i in range(500)]
        pin = _capture(db, selected_results=rows)
        results = _meta(pin)["results"]
        cap = query_evidence_service.SELECTED_RESULT_CAP
        assert len(results["selected"]) == cap
        assert results["selected_capped"] is True
        assert results["selected_cap"] == cap
        # The count must be what was actually selected, not what was stored,
        # or the evidence understates the analyst's selection.
        assert results["selected_count"] == 500

    def test_an_uncapped_selection_says_so(self, db):
        pin = _capture(db, selected_results=[{"_id": "a"}])
        assert _meta(pin)["results"]["selected_capped"] is False

    def test_a_non_list_selection_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            _capture(db, selected_results={"_id": "a"})


# ── Required inputs ──────────────────────────────────────────────────────


class TestRequiredInputs:
    def test_an_empty_query_is_rejected(self, db):
        """Evidence that does not say what was searched for is not evidence."""
        for bad in ("", "   ", None):
            with pytest.raises(QueryEvidenceError):
                _capture(db, query=bad)

    def test_an_empty_index_is_rejected(self, db):
        for bad in ("", "   ", None):
            with pytest.raises(QueryEvidenceError):
                _capture(db, index=bad)

    def test_an_unknown_case_is_rejected(self, db):
        from ion.services.case_pin_service import CaseNotFoundError

        with pytest.raises((CaseNotFoundError, QueryEvidenceError)):
            _capture(db, alert_case_id=4242)


# ── Unbounded windows ────────────────────────────────────────────────────


class TestTimeWindow:
    def test_a_missing_bound_is_marked_unbounded_with_a_reason(self, db):
        pin = _capture(db, time_from=None)
        window = _meta(pin)["time_window"]
        assert window["bounded"] is False
        assert window["from"] is None
        assert window["description"]

    def test_both_bounds_missing_is_still_capturable(self, db):
        """An all-time search is a real search; refusing to record it would
        just push the analyst back to pasting screenshots."""
        pin = _capture(db, time_from=None, time_to=None)
        window = _meta(pin)["time_window"]
        assert window["bounded"] is False
        assert "all" in window["description"].lower() or "no " in window["description"].lower()

    def test_an_inverted_window_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            _capture(db, time_from=_T1, time_to=_T0)

    def test_naive_timestamps_are_treated_as_utc(self, db):
        """ION stores naive UTC in several places; a window must not shift."""
        pin = _capture(db, time_from=_T0.replace(tzinfo=None),
                       time_to=_T1.replace(tzinfo=None))
        window = _meta(pin)["time_window"]
        assert window["from"].startswith("2026-10-07T09:00:00")
        assert window["to"].startswith("2026-10-08T09:00:00")
        assert window["bounded"] is True

    def test_the_window_duration_is_recorded(self, db):
        pin = _capture(db)
        assert _meta(pin)["time_window"]["duration_seconds"] == int(
            (_T1 - _T0).total_seconds()
        )


# ── Rerun never overwrites ───────────────────────────────────────────────


class TestRerun:
    def test_a_rerun_creates_a_second_pin(self, db):
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
            duration_ms=388,
        )
        assert second.id != first.id
        assert db.query(CaseEvidencePin).count() == 2

    def test_the_original_capture_is_untouched(self, db):
        first = _capture(db)
        before = dict(_meta(first))
        query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
        )
        db.expire_all()
        after = db.get(CaseEvidencePin, first.id)
        assert after.pin_metadata == before
        assert after.pin_metadata["results"]["returned"] == 37

    def test_the_rerun_links_back_to_the_original(self, db):
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
        )
        assert _meta(second)["rerun_of"] == first.id

    def test_the_rerun_reuses_the_query_and_the_scope(self, db):
        """A rerun that silently changed the query would prove nothing."""
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
        )
        assert _meta(second)["query"] == _meta(first)["query"]
        assert _meta(second)["scope"] == _meta(first)["scope"]

    def test_the_rerun_records_its_own_counts(self, db):
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
        )
        assert _meta(second)["results"]["returned"] == 41

    def test_the_rerun_may_cover_a_different_window(self, db):
        first = _capture(db)
        later = _T1 + timedelta(days=30)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=0, total_hits=0,
            time_from=_T1, time_to=later,
        )
        assert _meta(second)["time_window"]["to"] == later.isoformat()
        assert _meta(first)["time_window"]["to"] == _T1.isoformat()

    def test_the_rerun_defaults_to_the_original_window(self, db):
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41,
        )
        assert _meta(second)["time_window"] == _meta(first)["time_window"]

    def test_rerunning_a_rerun_points_at_the_first_capture(self, db):
        """Otherwise the chain has to be walked to find the original."""
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41)
        third = query_evidence_service.rerun_query_evidence(
            db, pin_id=second.id, actor_id=1, returned_count=44, total_hits=44)
        assert _meta(third)["rerun_of"] == first.id
        assert _meta(third)["rerun_parent"] == second.id

    def test_rerunning_a_non_query_pin_is_rejected(self, db):
        from ion.services import case_pin_service

        pin = case_pin_service.create_pin(
            db, alert_case_id=1, source_type=PinSourceType.NOTE.value,
            source_ref="", title="just a note", actor_id=1,
        )
        db.commit()
        with pytest.raises(QueryEvidenceError):
            query_evidence_service.rerun_query_evidence(
                db, pin_id=pin.id, actor_id=1, returned_count=1)

    def test_rerunning_a_missing_pin_is_rejected(self, db):
        with pytest.raises(QueryEvidenceError):
            query_evidence_service.rerun_query_evidence(
                db, pin_id=9999, actor_id=1, returned_count=1)

    def test_a_rerun_of_a_capture_whose_total_is_now_unknown_stays_honest(self, db):
        first = _capture(db)
        second = query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=500, total_hits=None,
        )
        assert _meta(second)["results"]["truncation_known"] is False


# ── The ledger sees it ───────────────────────────────────────────────────


class TestLedger:
    def test_a_capture_appends_to_the_hash_chain(self, db):
        _capture(db)
        entries = case_ledger_service.list_entries(db, 1)
        assert len(entries) == 1

    def test_a_rerun_appends_a_second_entry(self, db):
        first = _capture(db)
        query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41)
        assert len(case_ledger_service.list_entries(db, 1)) == 2

    def test_the_chain_still_verifies(self, db):
        first = _capture(db)
        query_evidence_service.rerun_query_evidence(
            db, pin_id=first.id, actor_id=1, returned_count=41, total_hits=41)
        result = case_ledger_service.verify_chain(db, 1)
        assert result["is_valid"] is True
        assert result["seq_count"] == 2


# ── Reading it back ──────────────────────────────────────────────────────


class TestListing:
    def test_captures_are_listable_for_a_case(self, db):
        _capture(db)
        _capture(db, query="event.code:4625", index="logs-windows-*")
        captures = query_evidence_service.list_query_evidence(db, alert_case_id=1)
        assert len(captures) == 2

    def test_listing_excludes_other_pin_types(self, db):
        from ion.services import case_pin_service

        _capture(db)
        case_pin_service.create_pin(
            db, alert_case_id=1, source_type=PinSourceType.NOTE.value,
            source_ref="", title="a note", actor_id=1)
        db.commit()
        assert len(query_evidence_service.list_query_evidence(db, alert_case_id=1)) == 1

    def test_a_listed_capture_carries_its_provenance(self, db):
        _capture(db)
        entry = query_evidence_service.list_query_evidence(db, alert_case_id=1)[0]
        assert entry["query"]["text"]
        assert entry["scope"]["index"]
        assert entry["results"]["returned"] == 37
        assert entry["pin_id"]

    def test_listing_is_newest_first(self, db):
        a = _capture(db, query="first")
        b = _capture(db, query="second")
        ids = [e["pin_id"] for e in query_evidence_service.list_query_evidence(db, 1)]
        assert ids == [b.id, a.id]


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "workbench_api.py").read_text(encoding="utf-8")

    def test_the_capture_route_exists(self):
        assert '@router.post(\n    "/{case_id}/query-evidence",' in self._api()

    def test_the_capture_route_requires_case_update(self):
        """A capture writes to the case and its ledger, so it is a mutation."""
        block = self._api().split('@router.post(\n    "/{case_id}/query-evidence",')[1][:300]
        assert 'require_permission("case:update")' in block

    def test_the_listing_route_only_needs_case_read(self):
        block = self._api().split('@router.get(\n    "/{case_id}/query-evidence",')[1][:300]
        assert 'require_permission("case:read")' in block

    def test_the_rerun_route_exists(self):
        assert "query-evidence/{pin_id}/rerun" in self._api()

    def test_the_rerun_route_requires_case_update(self):
        block = self._api().split('"/{case_id}/query-evidence/{pin_id}/rerun",')[1][:300]
        assert 'require_permission("case:update")' in block

    def test_query_is_a_valid_pin_source_type(self):
        from ion.services.case_pin_service import _VALID_SOURCE_TYPES

        assert "query" in _VALID_SOURCE_TYPES

    def test_discover_offers_the_capture_control(self):
        tpl = (_SRC / "ion" / "web" / "templates" / "discover.html"
               ).read_text(encoding="utf-8")
        assert "query-evidence" in tpl
