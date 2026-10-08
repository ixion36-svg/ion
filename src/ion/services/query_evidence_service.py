"""Capture a Discover search as case evidence, with its full provenance.

From the 8 Oct 2026 feature review (§9):

    "Preserve query evidence containing query, index/scope, time window,
    execution time, returned count/truncation and selected results. Pin it
    to a case and rerun without overwriting original evidence."

Discover could run a search and export the rows. What it could not do was
make the search itself part of the case, so an analyst who found the decisive
evidence by searching pasted a screenshot or retyped the query into a note.
That loses the two things that make a search reproducible: the exact scope it
ran against and the window it covered.

This rides on the existing evidence pin and its hash-chained ledger rather
than adding a table. ``PinSourceType`` is stored as VARCHAR precisely so a
new source can be added without a migration, so a captured search is a pin of
source type ``query`` whose ``pin_metadata`` holds the provenance.

Two deliberate honesty rules:

**Truncation is not guessed.** If the backend did not report a total, ION does
not know whether the rows it holds are all of them. ``truncated`` is then
``None`` and ``truncation_known`` is ``False``, rather than the convenient
``False``. Evidence that silently claims completeness it cannot demonstrate is
worse than evidence that admits the gap.

**A rerun is new evidence, never an overwrite.** The original capture is what
the analyst drew their conclusion from. A rerun months later, against rolled
indices and after retention has expired, legitimately returns something else
— and the case has to keep both. So a rerun writes a second pin linked by
``rerun_of``, and the original row is never touched.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.case_evidence import CaseEvidencePin, PinSourceType
from ion.models.user import User
from ion.services import case_pin_service

logger = logging.getLogger(__name__)

#: Bumped when the stored metadata shape changes. Evidence outlives the code
#: that wrote it, so a reader has to know which shape it is looking at.
CAPTURE_VERSION = 1

#: How many analyst-selected rows are stored with the capture. A selection is
#: meant to be the handful of rows that mattered, not the result set — that is
#: what the CSV export is for. The cap is recorded in the metadata, and
#: ``selected_count`` stays the true number, so a capped capture cannot read
#: as a smaller selection than the analyst actually made.
SELECTED_RESULT_CAP = 50

#: Query languages ION can record. ``dsl`` is a raw Elasticsearch query body.
#: A bare query string is ambiguous between these, and running a KQL string as
#: Lucene gives different results, so the language is part of the evidence.
VALID_LANGUAGES = ("kql", "lucene", "dsl")

_DEFAULT_LANGUAGE = "kql"

_KIND = "query_evidence"


class QueryEvidenceError(Exception):
    """A capture was refused because it would not be reproducible."""


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _as_utc(value: datetime | None) -> datetime | None:
    """Treat a naive datetime as UTC rather than local time.

    ION stores naive UTC in several places. Letting ``astimezone()`` apply the
    host's zone would shift a recorded window by the local offset, which is
    exactly the kind of quiet error that makes evidence unusable.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _require_text(value: Any, field: str) -> str:
    if value is None or not str(value).strip():
        raise QueryEvidenceError(f"{field} is required for a reproducible capture")
    return str(value).strip()


def _time_window(
    time_from: datetime | None,
    time_to: datetime | None,
    expression: dict | None = None,
) -> dict:
    """The window the search covered, and whether it was bounded at all.

    ``expression`` preserves the relative form the analyst actually picked
    (``now-24h`` to ``now``) alongside the absolute window it resolved to.
    Both matter: the expression is what they chose, the absolute pair is what
    was searched, and only the latter can be reproduced later.
    """
    start = _as_utc(time_from)
    end = _as_utc(time_to)
    expr = dict(expression) if isinstance(expression, dict) else None

    if start is not None and end is not None:
        if start > end:
            raise QueryEvidenceError(
                "time_from is after time_to; the window would not describe "
                "any search that could have run"
            )
        return {
            "from": start.isoformat(),
            "to": end.isoformat(),
            "bounded": True,
            "duration_seconds": int((end - start).total_seconds()),
            "description": f"{start.isoformat()} to {end.isoformat()}",
            "expression": expr,
        }

    if start is None and end is None:
        description = "No time filter recorded — the search covered all data in scope"
    elif start is None:
        description = f"Open-ended start; data up to {end.isoformat()}"
    else:
        description = f"From {start.isoformat()} with no end bound"

    return {
        "from": start.isoformat() if start else None,
        "to": end.isoformat() if end else None,
        "bounded": False,
        "duration_seconds": None,
        "description": description,
        "expression": expr,
    }


def _results_block(
    *,
    returned_count: int,
    total_hits: Optional[int],
    truncated: Optional[bool],
    selected_results: Optional[list],
) -> dict:
    """Counts, truncation and selection — with the unknowns left unknown."""
    try:
        returned = int(returned_count)
    except (TypeError, ValueError) as exc:
        raise QueryEvidenceError("returned_count must be an integer") from exc
    if returned < 0:
        raise QueryEvidenceError("returned_count cannot be negative")

    total: Optional[int] = None
    if total_hits is not None:
        try:
            total = int(total_hits)
        except (TypeError, ValueError) as exc:
            raise QueryEvidenceError("total_hits must be an integer") from exc
        if total < returned:
            raise QueryEvidenceError(
                f"total_hits ({total}) is below returned_count ({returned}); "
                "one of the two counts is wrong"
            )

    if truncated is not None:
        # Some backends report "there are more" without a usable total. An
        # explicit flag is better evidence than an inferred one.
        is_truncated: Optional[bool] = bool(truncated)
        truncation_known = True
    elif total is not None:
        is_truncated = returned < total
        truncation_known = True
    else:
        # The honest answer. `False` here would be a claim of completeness
        # that nothing in the capture supports.
        is_truncated = None
        truncation_known = False

    if selected_results is None:
        selected: list = []
    elif isinstance(selected_results, list):
        selected = selected_results
    else:
        raise QueryEvidenceError("selected_results must be a list of rows")

    stored = selected[:SELECTED_RESULT_CAP]

    return {
        "returned": returned,
        "total_hits": total,
        "truncated": is_truncated,
        "truncation_known": truncation_known,
        # The analyst's real selection size, even when only part is stored.
        "selected_count": len(selected),
        "selected": stored,
        "selected_capped": len(selected) > SELECTED_RESULT_CAP,
        "selected_cap": SELECTED_RESULT_CAP,
    }


def _language_block(language: Optional[str]) -> tuple[str, bool]:
    if language is None:
        return _DEFAULT_LANGUAGE, True
    normalised = str(language).strip().lower()
    if normalised not in VALID_LANGUAGES:
        raise QueryEvidenceError(
            f"unknown query language '{language}'; expected one of "
            f"{', '.join(VALID_LANGUAGES)}"
        )
    return normalised, False


def _default_title(index: str, window: dict, returned: int) -> str:
    span = "all time" if not window["bounded"] else (
        f"{window['from'][:16]}Z to {window['to'][:16]}Z"
    )
    return f"Search of {index} ({span}) — {returned} row(s)"[:500]


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

def capture_query_evidence(
    session: Session,
    *,
    alert_case_id: int,
    actor_id: int,
    query: Optional[str],
    index: Optional[str],
    language: Optional[str] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    time_expression: Optional[dict] = None,
    executed_at: Optional[datetime] = None,
    duration_ms: Optional[int] = None,
    returned_count: int = 0,
    total_hits: Optional[int] = None,
    truncated: Optional[bool] = None,
    selected_results: Optional[list] = None,
    title: Optional[str] = None,
    note: Optional[str] = None,
    severity: Optional[str] = None,
    tags: Optional[list[str]] = None,
    _rerun_of: Optional[int] = None,
    _rerun_parent: Optional[int] = None,
    _language_assumed: Optional[bool] = None,
) -> CaseEvidencePin:
    """Pin a search to a case with everything needed to reproduce it.

    Args:
        session: Database session.
        alert_case_id: Case the evidence belongs to.
        actor_id: User capturing it.
        query: The search text, exactly as it ran. Required.
        index: Index or index pattern the search ran against. Required.
        language: One of :data:`VALID_LANGUAGES`. Defaults to ``kql`` and the
            capture records that the language was assumed rather than stated.
        time_from: Window start, if the search was bounded.
        time_to: Window end, if the search was bounded.
        time_expression: The relative form the analyst picked, e.g.
            ``{"from": "now-24h", "to": "now"}``, preserved beside the
            absolute window it resolved to.
        executed_at: When the search ran. Defaults to now — capture usually
            happens a moment after the search, and the search's own timestamp
            is the one that matters.
        duration_ms: How long the search took.
        returned_count: Rows the search returned.
        total_hits: Total matches, if the backend reported one.
        truncated: Explicit truncation flag, if the backend gave one instead
            of a total.
        selected_results: The rows the analyst picked out as the evidence.
        title: Pin title. Defaults to a description of the scope and window.
        note: Analyst's own words, stored as the pin summary.
        severity: Optional pin severity.
        tags: Optional pin tags.

    Returns:
        The created :class:`CaseEvidencePin`.

    Raises:
        QueryEvidenceError: If the capture would not be reproducible.
        CaseNotFoundError: If the case does not exist.
    """
    query_text = _require_text(query, "query")
    index_scope = _require_text(index, "index")
    lang, assumed = _language_block(language)
    if _language_assumed is not None:
        # A rerun passes the original's resolved language, which would
        # otherwise read as stated. If the original only assumed it, the
        # rerun inherited that assumption and has to say so.
        assumed = bool(_language_assumed)

    window = _time_window(time_from, time_to, time_expression)
    results = _results_block(
        returned_count=returned_count,
        total_hits=total_hits,
        truncated=truncated,
        selected_results=selected_results,
    )

    ran_at = _as_utc(executed_at) or datetime.now(timezone.utc)
    actor = session.get(User, actor_id)

    metadata: dict[str, Any] = {
        "capture_version": CAPTURE_VERSION,
        "kind": _KIND,
        "query": {
            "text": query_text,
            "language": lang,
            "language_assumed": assumed,
        },
        "scope": {"index": index_scope},
        "time_window": window,
        "execution": {
            "executed_at": ran_at.isoformat(),
            "duration_ms": int(duration_ms) if duration_ms is not None else None,
            "executed_by": actor.username if actor else None,
            "executed_by_id": actor_id,
        },
        "results": results,
        "rerun_of": _rerun_of,
        "rerun_parent": _rerun_parent,
    }

    pin = case_pin_service.create_pin(
        session,
        alert_case_id=alert_case_id,
        source_type=PinSourceType.QUERY.value,
        # Unique per capture, so a rerun is a new row rather than a duplicate
        # rejected by the per-case uniqueness constraint.
        source_ref=f"query:{uuid.uuid4().hex[:16]}",
        title=(title.strip() if title and title.strip()
               else _default_title(index_scope, window, results["returned"])),
        summary=(note.strip() if note and note.strip() else None),
        severity=severity,
        tags=tags,
        metadata=metadata,
        actor_id=actor_id,
    )

    logger.info(
        "Captured query evidence on case %s (pin=%s, index=%s, returned=%s, "
        "truncation_known=%s)",
        alert_case_id, pin.id, index_scope, results["returned"],
        results["truncation_known"],
    )
    return pin


def rerun_query_evidence(
    session: Session,
    *,
    pin_id: int,
    actor_id: int,
    returned_count: int,
    total_hits: Optional[int] = None,
    truncated: Optional[bool] = None,
    selected_results: Optional[list] = None,
    duration_ms: Optional[int] = None,
    executed_at: Optional[datetime] = None,
    time_from: Optional[datetime] = None,
    time_to: Optional[datetime] = None,
    note: Optional[str] = None,
) -> CaseEvidencePin:
    """Re-capture an earlier search, as a new pin, leaving the original alone.

    The query, language and scope come from the original capture, so a rerun
    cannot quietly become a different search. The window defaults to the
    original's, but may be given explicitly — rerunning the same query over a
    later period is a normal thing to want.

    ``rerun_of`` always points at the first capture in the chain and
    ``rerun_parent`` at the one actually rerun, so finding the original never
    requires walking the chain.

    Args:
        session: Database session.
        pin_id: The query-evidence pin to rerun.
        actor_id: User performing the rerun.
        returned_count: Rows this run returned.
        total_hits: Total matches this run, if reported.
        truncated: Explicit truncation flag for this run.
        selected_results: Rows selected from this run.
        duration_ms: How long this run took.
        executed_at: When this run happened. Defaults to now.
        time_from: Window start for this run. Defaults to the original's.
        time_to: Window end for this run. Defaults to the original's.
        note: Analyst's note on this run.

    Returns:
        The new :class:`CaseEvidencePin`.

    Raises:
        QueryEvidenceError: If the pin is missing or is not a query capture.
    """
    original = session.get(CaseEvidencePin, pin_id)
    if original is None:
        raise QueryEvidenceError(f"evidence pin {pin_id} not found")
    if original.source_type != PinSourceType.QUERY.value:
        raise QueryEvidenceError(
            f"evidence pin {pin_id} is a '{original.source_type}' pin, not a "
            "captured query, so there is nothing to rerun"
        )

    meta = original.pin_metadata or {}
    query_block = meta.get("query") or {}
    scope_block = meta.get("scope") or {}
    window = meta.get("time_window") or {}

    # The first capture in the chain, so a rerun of a rerun still points home.
    root = meta.get("rerun_of") or original.id

    def _window_bound(key: str, explicit: Optional[datetime]) -> Optional[datetime]:
        if explicit is not None:
            return explicit
        raw = window.get(key)
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    return capture_query_evidence(
        session,
        alert_case_id=original.alert_case_id,
        actor_id=actor_id,
        query=query_block.get("text"),
        index=scope_block.get("index"),
        language=query_block.get("language"),
        time_from=_window_bound("from", time_from),
        time_to=_window_bound("to", time_to),
        # Only meaningful when the rerun kept the original window; a new
        # window makes the original expression a different claim.
        time_expression=(window.get("expression")
                         if time_from is None and time_to is None else None),
        executed_at=executed_at,
        duration_ms=duration_ms,
        returned_count=returned_count,
        total_hits=total_hits,
        truncated=truncated,
        selected_results=selected_results,
        title=f"Rerun of #{original.id}: {original.title}",
        note=note,
        severity=original.severity,
        tags=original.tags,
        _rerun_of=root,
        _rerun_parent=original.id,
        _language_assumed=query_block.get("language_assumed"),
    )


def list_query_evidence(
    session: Session,
    alert_case_id: int,
    limit: int = 100,
) -> list[dict]:
    """Every captured search on a case, newest first.

    Returns the pin's own fields flattened together with the provenance
    blocks, so a caller rendering the evidence does not have to know that it
    lives under ``metadata``.
    """
    rows = session.execute(
        select(CaseEvidencePin)
        .where(
            CaseEvidencePin.alert_case_id == alert_case_id,
            CaseEvidencePin.source_type == PinSourceType.QUERY.value,
        )
        .order_by(CaseEvidencePin.id.desc())
        .limit(limit)
    ).scalars().all()

    out = []
    for pin in rows:
        meta = pin.pin_metadata or {}
        out.append(
            {
                "pin_id": pin.id,
                "alert_case_id": pin.alert_case_id,
                "title": pin.title,
                "summary": pin.summary,
                "finding_status": pin.finding_status,
                "severity": pin.severity,
                "tags": pin.tags or [],
                "pinned_by_id": pin.pinned_by_id,
                "pinned_at": pin.pinned_at.isoformat() if pin.pinned_at else None,
                "capture_version": meta.get("capture_version"),
                "query": meta.get("query") or {},
                "scope": meta.get("scope") or {},
                "time_window": meta.get("time_window") or {},
                "execution": meta.get("execution") or {},
                "results": meta.get("results") or {},
                "rerun_of": meta.get("rerun_of"),
                "rerun_parent": meta.get("rerun_parent"),
            }
        )
    return out


__all__ = [
    "CAPTURE_VERSION",
    "SELECTED_RESULT_CAP",
    "VALID_LANGUAGES",
    "QueryEvidenceError",
    "capture_query_evidence",
    "rerun_query_evidence",
    "list_query_evidence",
]
