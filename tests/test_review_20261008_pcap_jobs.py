"""Durable PCAP jobs and attach-to-case (8 Oct 2026 review, §13).

    "Observed gap: standalone upload returns results without a persistent
    job/history/case association. The inspected standalone UI lacks a clear
    save/export/attach-to-case flow."

    "Improve: durable jobs with upload hash, parser version,
    progress/cancellation and reusable results. Attach selected findings and
    packet/stream references to an investigation. ... Explain heuristic
    findings with supporting traffic rather than presenting every flag as a
    confirmed threat."

``POST /api/pcap/analyze`` parsed the upload and returned the result. Nothing
was stored, so a capture that took forty seconds to parse had to be
re-uploaded to look at again, two analysts could not see each other's work,
and a finding that mattered could not be moved onto the case except by
retyping it.

Three things the tests pin beyond the obvious persistence:

* **Reuse is by content, not by name.** The job records the upload's sha256
  and the parser version, and a second upload of the same bytes under a
  different filename reuses the first result. A *different* parser version
  does not reuse it — that is the whole point of recording the version.
* **Cancellation is cooperative and honest.** Requesting a cancel does not
  pretend the work stopped; the status becomes ``cancelled`` only when the
  runner actually notices, and a job that already finished cannot be
  retroactively cancelled.
* **A heuristic is not a confirmed threat.** Attaching a finding to a case
  records its evidential basis — a threat-intel match is an observation about
  a known-bad indicator, whereas beaconing periodicity is an inference — plus
  the traffic that supports it. The review is explicit that every flag must
  not be presented as a confirmed threat.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.alert_triage import AlertCase
from ion.models.base import Base
from ion.models.case_evidence import CaseEvidencePin, PinSourceType
from ion.models.pcap_job import PcapJob, PcapJobStatus
from ion.models.user import User
from ion.services import pcap_job_service as jobs
from ion.services.pcap_job_service import PcapJobError
from ion.storage.database import _run_migrations


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'pcap_jobs.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def sf(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def db(sf):
    s = sf()
    s.add(User(id=1, username="alice", email="a@x", password_hash="x",
               display_name="Alice", is_active=True))
    s.add(User(id=2, username="bob", email="b@x", password_hash="x",
               display_name="Bob", is_active=True))
    s.add(AlertCase(id=1, case_number="CASE-0001", title="Beaconing",
                    severity="high", created_by_id=1))
    s.commit()
    yield s
    s.close()


CONTENT = b"\xd4\xc3\xb2\xa1" + b"fake capture bytes" * 10
OTHER_CONTENT = b"\xd4\xc3\xb2\xa1" + b"different bytes" * 10

RESULT = {
    "verdict": "suspicious",
    "packet_count": 1420,
    "findings": [
        {"category": "Command & Control", "severity": "high",
         "title": "Periodic beaconing to 203.0.113.7",
         "detail": "47 connections at 60s +/- 2s intervals"},
        {"category": "threat_intel", "severity": "critical",
         "title": "203.0.113.7 matches a known C2 indicator",
         "detail": "OpenCTI: Cobalt Strike infrastructure"},
        {"category": "Cleartext Protocol", "severity": "low",
         "title": "HTTP Basic auth observed",
         "detail": "GET /admin from 10.0.0.5"},
    ],
    "streams": [{"id": "tcp-14", "src": "10.0.0.5", "dst": "203.0.113.7"}],
}


def _create(db, content=CONTENT, filename="capture.pcap", **over):
    kwargs = dict(filename=filename, content=content, requested_by_id=1)
    kwargs.update(over)
    return jobs.create_job(db, **kwargs)


# ── Schema ───────────────────────────────────────────────────────────────


class TestSchema:
    def test_the_table_exists_on_a_fresh_database(self, engine):
        assert inspect(engine).has_table("pcap_jobs")

    def test_the_migration_creates_it_on_an_upgrade(self, tmp_path):
        eng = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
        try:
            Base.metadata.create_all(
                eng,
                tables=[t for n, t in Base.metadata.tables.items()
                        if n != "pcap_jobs"],
            )
            assert not inspect(eng).has_table("pcap_jobs")
            _run_migrations(eng)
            assert inspect(eng).has_table("pcap_jobs")
        finally:
            eng.dispose()


# ── Creating a job ───────────────────────────────────────────────────────


class TestCreate:
    def test_a_new_job_is_queued(self, db):
        job = _create(db)
        assert job.status == PcapJobStatus.QUEUED.value

    def test_the_upload_hash_is_recorded(self, db):
        job = _create(db)
        assert job.content_sha256 == hashlib.sha256(CONTENT).hexdigest()

    def test_the_parser_version_is_recorded(self, db):
        """Without it a cached result cannot be known to be current."""
        assert _create(db).parser_version == jobs.PARSER_VERSION

    def test_the_size_and_filename_are_recorded(self, db):
        job = _create(db)
        assert job.file_size == len(CONTENT)
        assert job.filename == "capture.pcap"

    def test_the_requester_is_recorded(self, db):
        assert _create(db).requested_by_id == 1

    def test_a_job_may_be_bound_to_a_case_up_front(self, db):
        assert _create(db, case_id=1).case_id == 1

    def test_an_empty_upload_is_refused(self, db):
        with pytest.raises(PcapJobError):
            _create(db, content=b"")

    def test_an_unsupported_extension_is_refused(self, db):
        with pytest.raises(PcapJobError):
            _create(db, filename="notes.txt")

    def test_the_accepted_extensions_are_the_api_ones(self, db):
        for name in ("a.pcap", "b.pcapng", "c.cap", "D.PCAP"):
            assert _create(db, filename=name).id

    def test_an_oversize_upload_is_refused(self, db):
        with pytest.raises(PcapJobError):
            jobs.create_job(db, filename="big.pcap",
                            content=b"x" * (jobs.MAX_FILE_SIZE + 1),
                            requested_by_id=1)


# ── Running ──────────────────────────────────────────────────────────────


class TestRun:
    def test_a_completed_job_stores_the_result(self, db):
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda content, name: RESULT)
        job = db.get(PcapJob, job.id)
        assert job.status == PcapJobStatus.COMPLETED.value
        assert job.result["packet_count"] == 1420

    def test_a_completed_job_records_its_duration(self, db):
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda content, name: RESULT)
        job = db.get(PcapJob, job.id)
        assert job.started_at is not None
        assert job.completed_at is not None
        assert job.duration_ms is not None and job.duration_ms >= 0

    def test_a_parser_failure_is_recorded_not_swallowed(self, db):
        job = _create(db)

        def _boom(content, name):
            raise ValueError("truncated capture")

        jobs.run_job(db, job_id=job.id, parse=_boom)
        job = db.get(PcapJob, job.id)
        assert job.status == PcapJobStatus.FAILED.value
        assert job.error
        assert job.completed_at is not None

    def test_running_a_job_twice_is_refused(self, db):
        """Claiming the job is what stops two workers parsing the same bytes."""
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda content, name: RESULT)
        with pytest.raises(PcapJobError):
            jobs.run_job(db, job_id=job.id, parse=lambda content, name: RESULT)

    def test_the_claim_is_atomic(self, sf, db):
        """Two workers observing `queued` must resolve to one runner."""
        job = _create(db)
        s_a, s_b = sf(), sf()
        try:
            assert s_a.get(PcapJob, job.id).status == PcapJobStatus.QUEUED.value
            assert s_b.get(PcapJob, job.id).status == PcapJobStatus.QUEUED.value
            assert jobs.claim_job(s_a, job_id=job.id) is True
            assert jobs.claim_job(s_b, job_id=job.id) is False
        finally:
            s_a.close()
            s_b.close()

    def test_running_a_missing_job_is_an_error(self, db):
        with pytest.raises(PcapJobError):
            jobs.run_job(db, job_id=9999, parse=lambda content, name: RESULT)

    def test_the_content_is_passed_to_the_parser(self, db):
        job = _create(db)
        seen = {}

        def _capture(content, name):
            seen["content"] = content
            seen["name"] = name
            return RESULT

        jobs.run_job(db, job_id=job.id, parse=_capture, content=CONTENT)
        assert seen["content"] == CONTENT
        assert seen["name"] == "capture.pcap"


# ── Reusable results ─────────────────────────────────────────────────────


class TestReuse:
    def test_the_same_bytes_reuse_a_completed_result(self, db):
        first = _create(db)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)

        second = _create(db, filename="renamed.pcap")
        assert second.status == PcapJobStatus.COMPLETED.value
        assert second.result["packet_count"] == 1420
        assert second.reused_from_id == first.id

    def test_reuse_is_by_content_not_filename(self, db):
        """Same capture, different name. Reuse must still apply."""
        first = _create(db, filename="monday.pcap")
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)
        second = _create(db, filename="tuesday.pcap")
        assert second.reused_from_id == first.id

    def test_different_bytes_do_not_reuse(self, db):
        first = _create(db)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)
        second = _create(db, content=OTHER_CONTENT)
        assert second.status == PcapJobStatus.QUEUED.value
        assert second.reused_from_id is None

    def test_a_different_parser_version_does_not_reuse(self, db, monkeypatch):
        """Recording the version is pointless if a stale result is served."""
        first = _create(db)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)

        monkeypatch.setattr(jobs, "PARSER_VERSION", "99.0.0-test")
        second = _create(db)
        assert second.status == PcapJobStatus.QUEUED.value
        assert second.reused_from_id is None
        assert second.parser_version == "99.0.0-test"

    def test_a_failed_job_is_not_reused(self, db):
        """Re-running is the right behaviour: the failure may be transient."""
        first = _create(db)
        jobs.run_job(db, job_id=first.id,
                     parse=lambda c, n: (_ for _ in ()).throw(ValueError("x")))
        second = _create(db)
        assert second.status == PcapJobStatus.QUEUED.value
        assert second.reused_from_id is None

    def test_a_cancelled_job_is_not_reused(self, db):
        first = _create(db)
        jobs.request_cancel(db, job_id=first.id, actor_id=1)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)
        second = _create(db)
        assert second.status == PcapJobStatus.QUEUED.value

    def test_reuse_can_be_declined(self, db):
        """An analyst who suspects the cached result wants a fresh parse."""
        first = _create(db)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)
        second = _create(db, reuse=False)
        assert second.status == PcapJobStatus.QUEUED.value
        assert second.reused_from_id is None

    def test_a_reused_job_keeps_its_own_requester_and_case(self, db):
        first = _create(db)
        jobs.run_job(db, job_id=first.id, parse=lambda c, n: RESULT)
        second = _create(db, requested_by_id=2, case_id=1)
        assert second.requested_by_id == 2
        assert second.case_id == 1
        assert second.reused_from_id == first.id


# ── Cancellation ─────────────────────────────────────────────────────────


class TestCancellation:
    def test_a_queued_job_can_be_cancelled(self, db):
        job = _create(db)
        jobs.request_cancel(db, job_id=job.id, actor_id=1)
        assert db.get(PcapJob, job.id).cancel_requested is True

    def test_requesting_a_cancel_does_not_claim_the_work_stopped(self, db):
        """The runner has not noticed yet. Saying `cancelled` would be a guess."""
        job = _create(db)
        jobs.request_cancel(db, job_id=job.id, actor_id=1)
        assert db.get(PcapJob, job.id).status == PcapJobStatus.QUEUED.value

    def test_the_runner_honours_a_cancel_before_parsing(self, db):
        job = _create(db)
        jobs.request_cancel(db, job_id=job.id, actor_id=1)
        called = []
        jobs.run_job(db, job_id=job.id,
                     parse=lambda c, n: called.append(1) or RESULT)
        job = db.get(PcapJob, job.id)
        assert job.status == PcapJobStatus.CANCELLED.value
        assert called == []

    def test_a_completed_job_cannot_be_cancelled(self, db):
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda c, n: RESULT)
        with pytest.raises(PcapJobError):
            jobs.request_cancel(db, job_id=job.id, actor_id=1)

    def test_cancelling_records_who_asked(self, db):
        job = _create(db)
        jobs.request_cancel(db, job_id=job.id, actor_id=2)
        assert db.get(PcapJob, job.id).cancelled_by_id == 2


# ── Listing and reading ──────────────────────────────────────────────────


class TestListing:
    def test_jobs_are_listed_newest_first(self, db):
        a = _create(db)
        b = _create(db, content=OTHER_CONTENT)
        assert [j["id"] for j in jobs.list_jobs(db)] == [b.id, a.id]

    def test_a_listed_job_names_its_requester(self, db):
        _create(db)
        assert jobs.list_jobs(db)[0]["requested_by"] == "alice"

    def test_the_listing_can_be_scoped_to_a_case(self, db):
        _create(db)
        _create(db, content=OTHER_CONTENT, case_id=1)
        scoped = jobs.list_jobs(db, case_id=1)
        assert len(scoped) == 1
        assert scoped[0]["case_id"] == 1

    def test_the_listing_omits_the_bulky_result(self, db):
        """A history list must not ship every parsed capture."""
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda c, n: RESULT)
        row = jobs.list_jobs(db)[0]
        assert "result" not in row
        assert row["finding_count"] == 3
        assert row["verdict"] == "suspicious"

    def test_the_detail_carries_the_result(self, db):
        job = _create(db)
        jobs.run_job(db, job_id=job.id, parse=lambda c, n: RESULT)
        detail = jobs.get_job(db, job.id)
        assert detail["result"]["packet_count"] == 1420

    def test_a_missing_job_is_an_error(self, db):
        with pytest.raises(PcapJobError):
            jobs.get_job(db, 9999)

    def test_the_limit_is_honoured(self, db):
        for i in range(4):
            _create(db, content=CONTENT + bytes([i]), reuse=False)
        assert len(jobs.list_jobs(db, limit=2)) == 2


# ── Evidential basis ─────────────────────────────────────────────────────


class TestFindingBasis:
    def test_a_threat_intel_match_is_an_observation(self, db):
        basis = jobs.classify_finding_basis(
            {"category": "threat_intel", "title": "matches a known C2 indicator"})
        assert basis["basis"] == "threat_intel"
        assert basis["confirmed"] is False

    def test_beaconing_is_an_inference(self, db):
        basis = jobs.classify_finding_basis(
            {"category": "Command & Control", "title": "Periodic beaconing"})
        assert basis["basis"] == "heuristic"
        assert basis["confirmed"] is False

    def test_a_yara_match_is_a_signature(self, db):
        basis = jobs.classify_finding_basis({"category": "YARA Match"})
        assert basis["basis"] == "signature"

    def test_a_protocol_observation_is_an_observation(self, db):
        """Cleartext HTTP was literally seen. It is a fact, not a guess."""
        basis = jobs.classify_finding_basis({"category": "Cleartext Protocol"})
        assert basis["basis"] == "observation"

    def test_nothing_is_ever_a_confirmed_threat(self, db):
        """A packet capture cannot confirm intent. The review's point."""
        for category in ("threat_intel", "Command & Control", "YARA Match",
                         "Cleartext Protocol", "DGA Detection", "whatever"):
            assert jobs.classify_finding_basis({"category": category})["confirmed"] is False

    def test_every_basis_carries_an_explanation(self, db):
        for category in ("threat_intel", "Command & Control", "YARA Match",
                         "Cleartext Protocol", "unknown-thing"):
            basis = jobs.classify_finding_basis({"category": category})
            assert basis["explanation"]
            assert basis["basis"] in jobs.FINDING_BASES

    def test_an_unknown_category_is_unclassified_not_guessed(self, db):
        basis = jobs.classify_finding_basis({"category": "brand new detector"})
        assert basis["basis"] == "unclassified"


# ── Attaching to a case ──────────────────────────────────────────────────


class TestAttach:
    def _completed(self, db, **over):
        job = _create(db, **over)
        jobs.run_job(db, job_id=job.id, parse=lambda c, n: RESULT)
        return db.get(PcapJob, job.id)

    def test_a_selected_finding_becomes_case_evidence(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        assert len(pins) == 1
        assert pins[0].source_type == PinSourceType.PCAP.value
        assert db.query(CaseEvidencePin).count() == 1

    def test_several_findings_can_be_attached_at_once(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0, 2], actor_id=1)
        assert len(pins) == 2

    def test_the_pin_carries_the_evidential_basis(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        meta = pins[0].pin_metadata
        assert meta["basis"]["basis"] == "heuristic"
        assert meta["basis"]["confirmed"] is False
        assert meta["basis"]["explanation"]

    def test_the_pin_carries_the_supporting_traffic(self, db):
        """"with supporting traffic rather than presenting every flag as a
        confirmed threat"."""
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        meta = pins[0].pin_metadata
        assert meta["finding"]["detail"] == "47 connections at 60s +/- 2s intervals"
        assert meta["streams"]

    def test_the_pin_carries_the_capture_provenance(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        meta = pins[0].pin_metadata
        assert meta["capture"]["sha256"] == hashlib.sha256(CONTENT).hexdigest()
        assert meta["capture"]["filename"] == "capture.pcap"
        assert meta["capture"]["parser_version"] == jobs.PARSER_VERSION
        assert meta["capture"]["job_id"] == job.id

    def test_attaching_an_incomplete_job_is_refused(self, db):
        job = _create(db)
        with pytest.raises(PcapJobError):
            jobs.attach_findings_to_case(
                db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)

    def test_an_out_of_range_index_is_refused(self, db):
        job = self._completed(db)
        with pytest.raises(PcapJobError):
            jobs.attach_findings_to_case(
                db, job_id=job.id, case_id=1, finding_indexes=[99], actor_id=1)

    def test_an_empty_selection_is_refused(self, db):
        job = self._completed(db)
        with pytest.raises(PcapJobError):
            jobs.attach_findings_to_case(
                db, job_id=job.id, case_id=1, finding_indexes=[], actor_id=1)

    def test_attaching_the_same_finding_twice_is_not_a_duplicate(self, db):
        """The pin's uniqueness constraint is per case and source ref."""
        job = self._completed(db)
        jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        again = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        assert again == []
        assert db.query(CaseEvidencePin).count() == 1

    def test_attaching_links_the_job_to_the_case(self, db):
        """An unbound job attached to a case now belongs to that case."""
        job = self._completed(db)
        assert job.case_id is None
        jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[0], actor_id=1)
        assert db.get(PcapJob, job.id).case_id == 1

    def test_the_pin_title_names_the_finding_and_the_basis(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[1], actor_id=1)
        assert "known C2 indicator" in pins[0].title

    def test_the_finding_severity_becomes_the_pin_severity(self, db):
        job = self._completed(db)
        pins = jobs.attach_findings_to_case(
            db, job_id=job.id, case_id=1, finding_indexes=[1], actor_id=1)
        assert pins[0].severity == "critical"


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "pcap_api.py").read_text(encoding="utf-8")

    def test_pcap_is_a_valid_pin_source_type(self):
        from ion.services.case_pin_service import _VALID_SOURCE_TYPES

        assert "pcap" in _VALID_SOURCE_TYPES

    def test_the_job_routes_exist(self):
        src = self._api()
        for route in ('"/jobs"', '"/jobs/{job_id}"', '"/jobs/{job_id}/cancel"',
                      '"/jobs/{job_id}/attach"'):
            assert route in src, route

    def test_attaching_requires_case_update(self):
        block = self._api().split('"/jobs/{job_id}/attach"')[1][:400]
        assert 'require_permission("case:update")' in block

    def test_the_page_offers_the_history_and_attach(self):
        tpl = (_SRC / "ion" / "web" / "templates" / "pcap.html"
               ).read_text(encoding="utf-8")
        assert "/pcap/jobs" in tpl
        assert "attach" in tpl.lower()
