"""Durable PCAP jobs, reusable results, and attach-to-case (review §13).

    "Improve: durable jobs with upload hash, parser version,
    progress/cancellation and reusable results. Attach selected findings and
    packet/stream references to an investigation. ... Explain heuristic
    findings with supporting traffic rather than presenting every flag as a
    confirmed threat."

Three things here are more than bookkeeping:

**Reuse is by content.** The job stores the upload's sha256 and the parser
version. The same bytes through the same parser cannot produce a different
answer, so a second upload of the same capture serves the stored result and
records which job it came from. A parser upgrade invalidates that
automatically, which is why the version lives on the row rather than being
assumed. A failed or cancelled job is never reused — its failure may have
been transient, and serving it would make a blip permanent.

**Cancellation is cooperative and honest.** Asking for a cancel sets
``cancel_requested`` and leaves the status alone, because until the runner
checks, the parse may well still be going. Only the runner writes
``cancelled``. Claiming the work stopped the moment a button was pressed is
the same class of error as calling a dry run "completed".

**A finding is not a confirmed threat.** The review is explicit about this.
:func:`classify_finding_basis` separates what was *seen* (cleartext
credentials crossed the wire) from what was *matched* (an address appears in
a threat-intel feed) from what was *inferred* (connections are suspiciously
periodic). Nothing is ever marked confirmed: a packet capture can show
behaviour, and behaviour is not intent. The basis and the supporting traffic
travel with the evidence pin, so a case reader can see which kind of claim
they are looking at months later.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ion.core.safe_errors import safe_error
from ion.models.case_evidence import PinSourceType
from ion.models.pcap_job import PcapJob, PcapJobStatus
from ion.services import case_pin_service

logger = logging.getLogger(__name__)


class PcapJobError(Exception):
    """A PCAP job operation was refused."""


#: Bumped whenever a parser change could alter a result. A stored result is
#: only reused for the version that produced it.
PARSER_VERSION = "1.0.0"

#: Mirrors the upload cap on the analyse endpoint.
MAX_FILE_SIZE = 100 * 1024 * 1024

#: Mirrors the extensions the analyse endpoint accepts.
ALLOWED_EXTENSIONS = (".pcap", ".pcapng", ".cap")

#: How strong a claim a finding is making about the traffic.
FINDING_BASES = ("observation", "signature", "threat_intel", "heuristic",
                 "unclassified")

#: Finding category → evidential basis. The point of the split is that these
#: are different kinds of claim and should not be rendered identically.
_BASIS_BY_CATEGORY = {
    # Seen in the packets. A fact about the capture.
    "Cleartext Protocol": "observation",
    "Credential Exposure": "observation",
    "credential_capture": "observation",
    "Legacy SMB Protocol": "observation",
    "Encrypted QUIC": "observation",
    "ISAKMP/IKE": "observation",
    "file_extraction": "observation",
    "tls_fingerprint": "observation",
    "TLS Certificate": "observation",
    # Matched against a rule written by someone.
    "YARA Match": "signature",
    # Matched against an external indicator list.
    "threat_intel": "threat_intel",
    # Inferred from a pattern. The traffic is consistent with the label; it
    # does not establish it.
    "Command & Control": "heuristic",
    "Data Exfiltration": "heuristic",
    "DGA Detection": "heuristic",
    "DNS Anomaly": "heuristic",
    "DNS Tunneling": "heuristic",
    "Protocol Tunneling": "heuristic",
    "Reconnaissance": "heuristic",
    "Network Anomaly": "heuristic",
    "Lateral Tool Transfer": "heuristic",
    "Suspicious Port": "heuristic",
    "Suspicious User-Agent": "heuristic",
    "Suspicious Email Attachment": "heuristic",
    "ARP Spoofing": "heuristic",
    "Rogue DHCP": "heuristic",
    "Rogue Router Advertisement": "heuristic",
}

_BASIS_EXPLANATION = {
    "observation": (
        "Directly observed in the capture. This is a fact about the traffic, "
        "though it does not by itself establish intent."
    ),
    "signature": (
        "Matched a detection rule. The rule's accuracy is the limit of this "
        "claim."
    ),
    "threat_intel": (
        "Matched an external indicator list. It says the indicator is "
        "attributed somewhere, not that this traffic is malicious."
    ),
    "heuristic": (
        "Inferred from a traffic pattern. The behaviour is consistent with "
        "the label; it does not demonstrate it. Benign software produces "
        "periodic, encrypted and automated traffic too."
    ),
    "unclassified": (
        "This detector has no recorded evidential basis, so how strong a "
        "claim it makes is unknown."
    ),
}


def classify_finding_basis(finding: dict) -> dict:
    """What kind of claim a finding is making, and why that matters.

    Returns ``{"basis", "confirmed", "explanation"}``. ``confirmed`` is
    always ``False``: a packet capture can establish that traffic happened,
    never that it was hostile, and the review asks explicitly that not every
    flag be presented as a confirmed threat.
    """
    category = str((finding or {}).get("category") or "").strip()
    basis = _BASIS_BY_CATEGORY.get(category, "unclassified")
    return {
        "basis": basis,
        "confirmed": False,
        "explanation": _BASIS_EXPLANATION[basis],
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _require(session: Session, job_id: int) -> PcapJob:
    job = session.get(PcapJob, job_id)
    if job is None:
        raise PcapJobError(f"PCAP job {job_id} not found")
    return job


# ---------------------------------------------------------------------------
# Creating
# ---------------------------------------------------------------------------

def create_job(
    session: Session,
    *,
    filename: str,
    content: bytes,
    requested_by_id: int,
    case_id: Optional[int] = None,
    reuse: bool = True,
) -> PcapJob:
    """Record an upload as a job, serving a stored result when one applies.

    Args:
        session: Database session.
        filename: The uploaded name, used for display and extension checks.
        content: The uploaded bytes. Hashed, not stored.
        requested_by_id: Who uploaded it.
        case_id: Bind the job to a case up front, if known.
        reuse: Serve a previous completed result for identical bytes parsed
            by the same parser version. An analyst who suspects the cached
            answer can pass ``False`` to force a fresh parse.

    Returns:
        A ``queued`` job, or a ``completed`` one carrying a reused result.

    Raises:
        PcapJobError: On an empty, oversize or unsupported upload.
    """
    name = (filename or "").strip() or "upload.pcap"
    if not any(name.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise PcapJobError(
            f"unsupported file type; expected one of {', '.join(ALLOWED_EXTENSIONS)}"
        )
    if not content:
        raise PcapJobError("the upload is empty")
    if len(content) > MAX_FILE_SIZE:
        raise PcapJobError(
            f"the upload is {len(content)} bytes, over the "
            f"{MAX_FILE_SIZE}-byte limit"
        )

    digest = hashlib.sha256(content).hexdigest()

    job = PcapJob(
        filename=name[:500],
        file_size=len(content),
        content_sha256=digest,
        parser_version=PARSER_VERSION,
        status=PcapJobStatus.QUEUED.value,
        requested_by_id=requested_by_id,
        case_id=case_id,
        cancel_requested=False,
    )

    if reuse:
        previous = session.execute(
            select(PcapJob)
            .where(
                PcapJob.content_sha256 == digest,
                PcapJob.parser_version == PARSER_VERSION,
                PcapJob.status == PcapJobStatus.COMPLETED.value,
            )
            .order_by(PcapJob.id.asc())
            .limit(1)
        ).scalars().first()

        if previous is not None:
            # Same bytes, same parser. The answer cannot differ, so serve it
            # and say where it came from rather than parsing again.
            job.status = PcapJobStatus.COMPLETED.value
            job.result = previous.result
            job.reused_from_id = previous.id
            job.started_at = _naive(_now())
            job.completed_at = job.started_at
            job.duration_ms = 0
            logger.info(
                "PCAP upload %s reuses job %s (sha256=%s, parser=%s)",
                name, previous.id, digest[:12], PARSER_VERSION,
            )

    session.add(job)
    session.commit()
    session.refresh(job)
    return job


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def claim_job(session: Session, *, job_id: int) -> bool:
    """Conditional queued → running transition. True only for the winner.

    Without the ``WHERE``, two workers that both read ``queued`` would both
    parse the same capture and the second would overwrite the first's result.
    """
    result = session.execute(
        update(PcapJob)
        .where(
            PcapJob.id == job_id,
            PcapJob.status == PcapJobStatus.QUEUED.value,
        )
        .values(status=PcapJobStatus.RUNNING.value,
                started_at=_naive(_now()))
    )
    won = result.rowcount == 1
    session.commit()
    if not won:
        session.expire_all()
    return won


def run_job(
    session: Session,
    *,
    job_id: int,
    parse: Callable[[bytes, str], dict],
    content: bytes = b"",
) -> PcapJob:
    """Parse a claimed job's capture and store the outcome.

    ``parse`` is injected rather than imported so the heavy parser is not a
    dependency of the job bookkeeping, and so a caller can run the real
    parser or a stub without the service caring.

    A cancel requested before the parse starts is honoured here: the status
    becomes ``cancelled`` and ``parse`` is never called.
    """
    job = _require(session, job_id)

    if job.cancel_requested:
        # The runner is the only thing that writes `cancelled`, because only
        # the runner knows the work really did not happen.
        job.status = PcapJobStatus.CANCELLED.value
        job.completed_at = _naive(_now())
        session.commit()
        session.refresh(job)
        return job

    if not claim_job(session, job_id=job_id):
        current = session.get(PcapJob, job_id)
        raise PcapJobError(
            f"PCAP job {job_id} is '{current.status if current else 'missing'}' "
            "and cannot be run"
        )

    started = _now()
    try:
        result = parse(content, job.filename)
    except Exception as exc:  # noqa: BLE001 — the failure is the outcome
        finished = _now()
        job = _require(session, job_id)
        job.status = PcapJobStatus.FAILED.value
        job.error = safe_error(exc, f"pcap_job[{job_id}]")
        job.completed_at = _naive(finished)
        job.duration_ms = int((finished - started).total_seconds() * 1000)
        session.commit()
        session.refresh(job)
        logger.warning("PCAP job %s failed: %s", job_id, job.error)
        return job

    finished = _now()
    job = _require(session, job_id)
    job.status = PcapJobStatus.COMPLETED.value
    job.result = result if isinstance(result, dict) else {"result": result}
    job.error = None
    job.completed_at = _naive(finished)
    job.duration_ms = int((finished - started).total_seconds() * 1000)
    session.commit()
    session.refresh(job)
    return job


def request_cancel(
    session: Session, *, job_id: int, actor_id: Optional[int] = None
) -> PcapJob:
    """Ask for a job to stop. Does not claim it has stopped."""
    job = _require(session, job_id)
    if job.status in (PcapJobStatus.COMPLETED.value, PcapJobStatus.FAILED.value,
                      PcapJobStatus.CANCELLED.value):
        raise PcapJobError(
            f"PCAP job {job_id} already finished as '{job.status}'; there is "
            "nothing left to cancel"
        )
    job.cancel_requested = True
    job.cancelled_by_id = actor_id
    session.commit()
    session.refresh(job)
    return job


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def list_jobs(
    session: Session,
    *,
    case_id: Optional[int] = None,
    limit: int = 50,
) -> list[dict]:
    """Analysis history, newest first, without the bulky parse results."""
    stmt = select(PcapJob)
    if case_id is not None:
        stmt = stmt.where(PcapJob.case_id == case_id)
    rows = session.execute(
        stmt.order_by(PcapJob.id.desc()).limit(limit)
    ).scalars().all()
    return [job.summary() for job in rows]


def get_job(session: Session, job_id: int) -> dict:
    """One job with its stored result."""
    return _require(session, job_id).to_dict()


# ---------------------------------------------------------------------------
# Attach to a case
# ---------------------------------------------------------------------------

def _supporting_streams(result: dict, finding: dict) -> list:
    """Traffic references that back a finding.

    The parser does not currently tag findings with the streams that produced
    them, so this carries the capture's stream list as context rather than
    inventing a link that is not in the data. When the parser starts tagging
    findings, this narrows without the stored shape changing.
    """
    streams = result.get("streams")
    if not isinstance(streams, list):
        return []
    return streams[:20]


def attach_findings_to_case(
    session: Session,
    *,
    job_id: int,
    case_id: int,
    finding_indexes: list[int],
    actor_id: int,
) -> list:
    """Pin selected findings to a case as evidence, with their basis.

    Each pin carries the capture provenance (filename, sha256, parser
    version, job id), the finding itself, the traffic that supports it, and
    :func:`classify_finding_basis` — so a reader can tell an observation from
    an inference rather than seeing a uniform list of alarming titles.

    Already-pinned findings are skipped rather than erroring: the evidence is
    already on the case, which is what the caller wanted.

    Returns:
        The pins created. Empty when every selected finding was already
        pinned.

    Raises:
        PcapJobError: If the job has not completed, the selection is empty,
            or an index is out of range.
    """
    job = _require(session, job_id)
    if job.status != PcapJobStatus.COMPLETED.value:
        raise PcapJobError(
            f"PCAP job {job_id} is '{job.status}'; only a completed analysis "
            "has findings to attach"
        )

    result = job.result if isinstance(job.result, dict) else {}
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []

    if not finding_indexes:
        raise PcapJobError("select at least one finding to attach")

    for index in finding_indexes:
        if not isinstance(index, int) or index < 0 or index >= len(findings):
            raise PcapJobError(
                f"finding index {index} is not in this analysis "
                f"(it has {len(findings)} findings)"
            )

    capture = {
        "job_id": job.id,
        "filename": job.filename,
        "sha256": job.content_sha256,
        "file_size": job.file_size,
        "parser_version": job.parser_version,
        "analysed_at": job.completed_at.isoformat() if job.completed_at else None,
        "reused_from_id": job.reused_from_id,
    }
    streams = _supporting_streams(result, {})

    pins = []
    for index in finding_indexes:
        finding = findings[index] or {}
        basis = classify_finding_basis(finding)
        title = finding.get("title") or finding.get("category") or "PCAP finding"

        try:
            pin = case_pin_service.create_pin(
                session,
                alert_case_id=case_id,
                source_type=PinSourceType.PCAP.value,
                # Stable per (job, finding), so re-attaching the same finding
                # hits the per-case uniqueness constraint instead of making a
                # second pin.
                source_ref=f"pcap:{job.id}:{index}",
                title=str(title)[:500],
                summary=finding.get("detail") or None,
                severity=finding.get("severity") or None,
                mitre_techniques=finding.get("mitre") or None,
                metadata={
                    "kind": "pcap_finding",
                    "capture": capture,
                    "finding": finding,
                    "finding_index": index,
                    "basis": basis,
                    "streams": streams,
                    "verdict": result.get("verdict"),
                },
                actor_id=actor_id,
            )
        except case_pin_service.DuplicatePinError:
            # Already on the case. That is the desired end state.
            logger.debug(
                "PCAP finding %s:%s already pinned to case %s",
                job.id, index, case_id,
            )
            continue
        pins.append(pin)

    # An unbound job attached to a case now belongs to it, so the case's own
    # history shows the capture it was built from.
    if job.case_id is None:
        job.case_id = case_id

    session.commit()
    for pin in pins:
        session.refresh(pin)
    return pins


__all__ = [
    "PcapJobError",
    "PARSER_VERSION",
    "MAX_FILE_SIZE",
    "ALLOWED_EXTENSIONS",
    "FINDING_BASES",
    "classify_finding_basis",
    "create_job",
    "claim_job",
    "run_job",
    "request_cancel",
    "list_jobs",
    "get_job",
    "attach_findings_to_case",
]
