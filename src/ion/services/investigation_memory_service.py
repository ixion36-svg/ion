"""Investigation memory service.

Thin wrapper around ``investigation_memory_repository`` that manages its
own sessions via ``get_session_factory`` — so the autonomous
investigation loop can call these without needing a FastAPI request
context.

Singleton pattern: ``get_investigation_memory_service()`` returns the
shared instance.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from sqlalchemy.orm import Session

from ion.models.investigation import (
    FalsePositiveSignature,
    Investigation,
    IOCSighting,
)
from ion.storage import investigation_memory_repository as repo
from ion.storage.database import get_engine, get_session_factory

logger = logging.getLogger(__name__)


class InvestigationMemoryService:
    """Service-level facade over the investigation memory repository.

    Each public method opens its own session, commits on success, and
    rolls back on error. The markdown context-block helper is the main
    value-add beyond the bare repo — it's what the autonomous loop
    splices into LLM prompts when a familiar alert lands.
    """

    @contextmanager
    def _session(self) -> Iterator[Session]:
        factory = get_session_factory(get_engine())
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------ #
    # Investigations
    # ------------------------------------------------------------------ #

    def start_investigation(self, alert: dict) -> int:
        """Record an investigation-start and return its id."""
        with self._session() as db:
            inv = repo.record_investigation_start(alert, db)
            return inv.id

    def complete_investigation(
        self,
        inv_id: int,
        verdict: Optional[str] = None,
        severity: Optional[str] = None,
        summary: Optional[str] = None,
        actions: Any = None,
        iocs: Any = None,
        llm_model: Optional[str] = None,
        tokens: Optional[int] = None,
        duration_ms: Optional[int] = None,
    ) -> None:
        with self._session() as db:
            repo.record_investigation_end(
                inv_id=inv_id,
                verdict=verdict,
                severity=severity,
                summary=summary,
                actions=actions,
                iocs=iocs,
                llm_model=llm_model,
                tokens=tokens,
                duration_ms=duration_ms,
                db=db,
            )

    def fail_investigation(self, inv_id: int, error: Optional[str] = None) -> None:
        with self._session() as db:
            repo.mark_investigation_failed(inv_id, error, db)

    def list_investigations(
        self,
        filters: Optional[dict] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Investigation]:
        with self._session() as db:
            return repo.list_investigations(filters or {}, db, limit=limit, offset=offset)

    def get_investigation(self, inv_id: int) -> Optional[Investigation]:
        with self._session() as db:
            return repo.get_investigation(inv_id, db)

    def past_for_signature(
        self, alert_signature: str, limit: int = 5
    ) -> list[Investigation]:
        with self._session() as db:
            return repo.past_investigations_for_signature(
                alert_signature, db, limit=limit
            )

    # ------------------------------------------------------------------ #
    # IOC sightings
    # ------------------------------------------------------------------ #

    def upsert_ioc_sighting(
        self,
        ioc_type: str,
        ioc_value: str,
        reputation: Any = None,
        inv_id: Optional[int] = None,
    ) -> IOCSighting:
        with self._session() as db:
            return repo.upsert_ioc_sighting(
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                db=db,
                reputation=reputation,
                inv_id=inv_id,
            )

    def lookup_ioc(self, ioc_type: str, ioc_value: str) -> Optional[IOCSighting]:
        with self._session() as db:
            return repo.lookup_ioc_history(ioc_type, ioc_value, db)

    def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        is_known_bad: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[IOCSighting]:
        with self._session() as db:
            return repo.list_ioc_sightings(
                db,
                ioc_type=ioc_type,
                is_known_bad=is_known_bad,
                limit=limit,
                offset=offset,
            )

    def recent_for_host(self, host: str, limit: int = 10) -> list[IOCSighting]:
        with self._session() as db:
            return repo.recent_sightings_for_host(host, db, limit=limit)

    # ------------------------------------------------------------------ #
    # False Positives
    # ------------------------------------------------------------------ #

    def record_fp(
        self,
        reason: str,
        confidence: int = 80,
        recorded_by: Optional[int] = None,
        rule_id: Optional[str] = None,
        rule_name: Optional[str] = None,
        alert_signature: Optional[str] = None,
        host_pattern: Optional[str] = None,
        user_pattern: Optional[str] = None,
    ) -> FalsePositiveSignature:
        with self._session() as db:
            return repo.record_fp(
                db=db,
                reason=reason,
                confidence=confidence,
                recorded_by=recorded_by,
                rule_id=rule_id,
                rule_name=rule_name,
                alert_signature=alert_signature,
                host_pattern=host_pattern,
                user_pattern=user_pattern,
            )

    def is_likely_fp(self, alert: dict) -> tuple[bool, Optional[FalsePositiveSignature]]:
        with self._session() as db:
            return repo.is_likely_fp(alert, db)

    def list_fps(self, limit: int = 100, offset: int = 0) -> list[FalsePositiveSignature]:
        with self._session() as db:
            return repo.list_fps(db, limit=limit, offset=offset)

    def delete_fp(self, fp_id: int) -> bool:
        with self._session() as db:
            return repo.delete_fp(fp_id, db)

    def toggle_fp(self, fp_id: int) -> Optional[FalsePositiveSignature]:
        with self._session() as db:
            return repo.toggle_fp(fp_id, db)

    # ------------------------------------------------------------------ #
    # Context block for LLM prompts
    # ------------------------------------------------------------------ #

    def build_context_block_for_alert(self, alert: dict) -> str:
        """Return a markdown block summarising memory for this alert.

        Designed to be spliced into the system / user prompt of the
        autonomous investigation loop so the model sees:

          - whether we've flagged this pattern as a known FP
          - the verdicts of the last few investigations of this rule
          - any IOC history for indicators on the alert
          - recent sightings on the affected host

        The output is deliberately compact — LLM prompts are expensive.
        """
        rule_id, rule_name, signature, host, user = repo._extract_alert_fields(alert)

        lines: list[str] = ["## Investigation memory"]

        with self._session() as db:
            # --- FP check ------------------------------------------------
            is_fp, fp = repo.is_likely_fp(alert, db)
            if is_fp and fp is not None:
                lines.append(
                    f"- **Known false positive** (confidence {fp.confidence}%): "
                    f"{fp.reason}"
                )
                if fp.host_pattern or fp.user_pattern:
                    scope = []
                    if fp.host_pattern:
                        scope.append(f"host~{fp.host_pattern}")
                    if fp.user_pattern:
                        scope.append(f"user~{fp.user_pattern}")
                    lines.append(f"  - FP scope: {', '.join(scope)}")
            else:
                lines.append("- No matching false-positive signature.")

            # --- Past investigations for this rule ----------------------
            if signature:
                past = repo.past_investigations_for_signature(
                    signature, db, limit=5
                )
                if past:
                    lines.append(
                        f"- Prior investigations for rule **{signature}** "
                        f"({len(past)}, most confident first):"
                    )
                    for p in past:
                        verdict = p.verdict or "?"
                        when = p.created_at.date().isoformat() if p.created_at else "?"
                        sev = p.severity_assessment or "-"
                        conf = (
                            f", confidence={p.confidence_int}"
                            if p.confidence_int is not None
                            else ""
                        )
                        snippet = (p.summary_text or "").strip().splitlines()
                        head = snippet[0][:140] if snippet else ""
                        lines.append(
                            f"  - {when}: verdict={verdict}, severity={sev}{conf}"
                            + (f" — {head}" if head else "")
                        )
                else:
                    lines.append(
                        f"- No prior completed investigations for rule "
                        f"**{signature}**."
                    )

                # --- Human review outcomes (v0.54.0, RAG P4) -------------
                # What did analysts DECIDE when cases on this rule closed?
                # Disagreements are the highest-value memory signal there
                # is: they tell the model its own priors on this rule have
                # been overruled by a human before.
                lines.extend(self._human_outcome_lines(signature, db))

            # --- IOC history for indicators carried by the alert ---------
            ioc_lines = self._ioc_history_lines(alert, db)
            if ioc_lines:
                lines.append("- IOC history:")
                lines.extend(f"  - {line}" for line in ioc_lines)

            # --- Host sightings -----------------------------------------
            if host:
                host_sightings = repo.recent_sightings_for_host(host, db, limit=5)
                if host_sightings:
                    lines.append(f"- Recent IOCs seen on host **{host}**:")
                    for s in host_sightings:
                        flag = ""
                        if s.is_known_bad:
                            flag = " [known-bad]"
                        elif s.is_known_good:
                            flag = " [known-good]"
                        lines.append(
                            f"  - {s.ioc_type}: `{s.ioc_value}` "
                            f"(seen {s.seen_count}x){flag}"
                        )

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _human_outcome_lines(self, signature: str, db: Session) -> list[str]:
        """Render closed-case human verdicts for this rule (v0.54.0).

        One summary line (agreed/disagreed counts), then one line per
        DISAGREEMENT — Bob's verdict vs what the human closed it as, with
        the closer's delta reason when they left one. Agreements are only
        counted, not itemised: concordant history adds little beyond the
        prior-investigation lines, and the memory block is char-capped.

        Best-effort: any failure returns [] so memory keeps working on a
        DB without the ledger (e.g. minimal test fixtures).
        """
        try:
            rows = repo.feedback_outcomes_for_signature(signature, db, limit=5)
        except Exception as exc:
            logger.debug("human-outcome lookup failed for %s: %s", signature, exc)
            return []
        if not rows:
            return []

        agreed = sum(1 for r in rows if r.agreement is True)
        disagreed = [r for r in rows if r.agreement is False]
        no_verdict = sum(1 for r in rows if r.agreement is None)

        lines = [
            f"- Human review outcomes for this rule (last {len(rows)} closed): "
            f"{agreed} agreed with the AI verdict, {len(disagreed)} disagreed"
            + (f", {no_verdict} had no AI verdict" if no_verdict else "")
            + "."
        ]
        for r in disagreed:
            conf = (
                f" (confidence {r.bob_confidence_int})"
                if r.bob_confidence_int is not None
                else ""
            )
            reason = (r.delta_reason or "").strip()
            lines.append(
                f"  - **ANALYST DISAGREED**: AI said {r.bob_suggested_verdict}"
                f"{conf} → human closed as **{r.human_verdict}**"
                + (f" — {reason[:160]}" if reason else "")
            )
        if disagreed:
            lines.append(
                "  - Weigh the human closures above your own prior verdicts "
                "when they conflict."
            )
        return lines

    def _ioc_history_lines(self, alert: dict, db: Session) -> list[str]:
        """Best-effort IOC-history lookup from common alert fields.

        We probe a small set of well-known keys rather than running the
        full observable extractor — this runs on the hot path for every
        alert and needs to be cheap.
        """
        source = alert.get("_source", alert) if isinstance(alert, dict) else {}
        g = lambda k: alert.get(k) or source.get(k)

        probes: list[tuple[str, Any]] = [
            ("ip", g("source_ip") or g("source.ip")),
            ("ip", g("destination_ip") or g("destination.ip")),
            ("domain", g("domain") or g("dns.question.name")),
            ("url", g("url") or g("url.full")),
            ("sha256", g("file.hash.sha256") or g("hash_sha256") or g("sha256")),
            ("sha1", g("file.hash.sha1") or g("sha1")),
            ("md5", g("file.hash.md5") or g("md5")),
        ]

        lines: list[str] = []
        seen: set[tuple[str, str]] = set()
        for ioc_type, value in probes:
            if not value:
                continue
            key = (ioc_type, str(value))
            if key in seen:
                continue
            seen.add(key)
            sighting = repo.lookup_ioc_history(ioc_type, str(value), db)
            if sighting is None:
                continue
            flag = ""
            if sighting.is_known_bad:
                flag = " [known-bad]"
            elif sighting.is_known_good:
                flag = " [known-good]"
            lines.append(
                f"{ioc_type} `{sighting.ioc_value}`: seen {sighting.seen_count}x"
                f", last {sighting.last_seen_at.date().isoformat()}{flag}"
            )
        return lines


# --------------------------------------------------------------------------- #
# Singleton
# --------------------------------------------------------------------------- #

_service: Optional[InvestigationMemoryService] = None


def get_investigation_memory_service() -> InvestigationMemoryService:
    """Return the shared InvestigationMemoryService instance."""
    global _service
    if _service is None:
        _service = InvestigationMemoryService()
    return _service
