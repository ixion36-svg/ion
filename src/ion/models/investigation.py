"""Investigation memory models.

Long-term store of autonomous / analyst investigations, IOC sightings, and
known false-positive signatures. Used by the investigation loop to
rehydrate context on repeat alerts (so we don't re-investigate the same
benign noise over and over).

Three tables:

- ``investigations``          one row per investigation run
- ``ioc_sightings``           dedup'd IOC history with last reputation
- ``fp_signatures``           analyst-authored false-positive rules

All timestamps are timezone-aware UTC.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


def _utcnow() -> datetime:
    """Timezone-aware UTC now — used as the default for every timestamp."""
    return datetime.now(timezone.utc)


class Investigation(Base):
    """One autonomous / analyst investigation of an alert.

    A single alert may be investigated multiple times (e.g. retriggered
    after new enrichment) — each run is its own row. ``alert_id_ref`` is
    the Elasticsearch alert ``_id`` so we can group runs for the same
    source alert without coupling to ION's internal alert_triage table.
    """

    __tablename__ = "investigations"
    __table_args__ = (
        Index("ix_investigations_alert_id_ref", "alert_id_ref"),
        Index("ix_investigations_alert_signature", "alert_signature"),
        Index("ix_investigations_host", "host"),
        Index("ix_investigations_status", "status"),
        Index("ix_investigations_verdict", "verdict"),
        Index("ix_investigations_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Alert provenance — strings, not FKs, so this layer keeps working
    # even when the upstream alert_triage row has been purged.
    alert_id_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    alert_signature: Mapped[str] = mapped_column(String(500), nullable=False)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Lifecycle
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )  # pending | running | completed | failed

    # Outcome (filled in when status transitions to completed)
    verdict: Mapped[Optional[str]] = mapped_column(
        String(32), nullable=True
    )  # true_positive | false_positive | benign | inconclusive
    severity_assessment: Mapped[Optional[str]] = mapped_column(
        String(16), nullable=True
    )  # low | medium | high | critical

    summary_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommended_actions_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ioc_snapshot_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # numeric confidence score (0-100) from _compute_confidence.
    confidence_int: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # True when the confidence-gated escalation "deep pass" ran for
    # this investigation (low-confidence + high/critical → try harder before
    # abstaining). Telemetry only — advisory, the human still decides.
    escalation_attempted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )
    # Analyst explanation text — stored when ION_BOB_STORE_REASONING=true.
    reasoning_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # training-loop foundation. Every investigation persists the
    # rendered user prompt + the model's raw output + the grounded evidence
    # bullets. Without these, AIFeedback disagreements are uncountable but
    # undebuggable — you know Bob was wrong, not what he saw.
    prompt_snapshot: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_response: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # JSON list of {field, value, significance} dicts — the specific alert
    # fields Bob pointed at when forming the verdict.
    key_observations_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Model telemetry
    llm_model_used: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Plain Integer (no FK) — the alert_prompt_templates table is owned by
    # a parallel workstream and may not exist yet. We store the id so we
    # can correlate after both tables land. Add a real FK in a later migration.
    prompt_template_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )

    def __repr__(self) -> str:
        return (
            f"<Investigation(id={self.id}, alert='{self.alert_signature}', "
            f"status={self.status}, verdict={self.verdict})>"
        )


class IOCSighting(Base):
    """Dedup'd record of every IOC we've ever seen, with reputation cache.

    One row per (type, value) pair. ``seen_count`` and ``last_seen_at``
    are bumped on every sighting; ``reputation_snapshot_json`` is the
    last cached third-party reputation (VT / Shodan / AbuseIPDB) so the
    investigation loop can short-circuit repeated lookups.
    """

    __tablename__ = "ioc_sightings"
    __table_args__ = (
        UniqueConstraint("ioc_type", "ioc_value", name="uq_ioc_sighting_type_value"),
        Index("ix_ioc_sightings_value", "ioc_value"),
        Index("ix_ioc_sightings_type", "ioc_type"),
        Index("ix_ioc_sightings_last_seen", "last_seen_at"),
        Index("ix_ioc_sightings_known_bad", "is_known_bad"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    ioc_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # ip | domain | url | sha256 | sha1 | md5 | email | filename
    ioc_value: Mapped[str] = mapped_column(String(2048), nullable=False)

    seen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    # Soft reference — no FK so deleting an investigation doesn't cascade
    # or error. The investigation layer is a long-term memory; old FKs
    # would create ugly tombstone-cleanup problems.
    last_investigation_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    reputation_snapshot_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    is_known_bad: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    is_known_good: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<IOCSighting(type={self.ioc_type}, value='{self.ioc_value[:48]}', "
            f"seen={self.seen_count})>"
        )


class FalsePositiveSignature(Base):
    """Analyst-authored rule for suppressing known-benign alert patterns.

    Matches by rule_id / rule_name / alert_signature plus optional
    host/user wildcard patterns (``*`` glob via fnmatch). When a match
    fires, ``hit_count`` and ``last_matched_at`` are bumped so analysts
    can see which FP rules are actually pulling weight.

    **Governance** (review 2026-10-08 §8). A quirk — the other way ION
    records "this is benign" — needs a different person to verify it and
    carries a mandatory review date, after which it stops having any effect.
    An FP signature makes the same class of claim and is fed to Bob as
    known-benign context, but had only ``enabled`` and a confidence number:
    recorded once, applied forever, on one person's judgement. That is the
    more dangerous of the two, because this suppresses alerts rather than
    annotating them.

    So it now carries ``review_date``, ``verified_by_id``, ``verified_at``
    and ``verification_note``, and expiry is computed on read exactly as for
    quirks — no background worker, so nothing can fail and leave a stale
    assumption live.

    One asymmetry is deliberate: a signature with **no** review date
    (recorded before this existed) keeps matching, labelled ``ungoverned``
    and listed for review. Making every pre-upgrade signature inert would
    silently switch off a SOC's accumulated FP memory, which is a worse
    surprise than the gap it fixes. A signature whose review date has
    *passed* does stop matching — the SOC chose that date.
    """

    __tablename__ = "fp_signatures"
    __table_args__ = (
        Index("ix_fp_signatures_rule_id", "rule_id"),
        Index("ix_fp_signatures_alert_signature", "alert_signature"),
        Index("ix_fp_signatures_enabled", "enabled"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    rule_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    alert_signature: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Glob patterns (fnmatch) — e.g. "DEV-*", "svc_*"
    host_pattern: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_pattern: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    reason: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=80)

    recorded_by: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )

    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_matched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Governance (review 2026-10-08 §8) ───────────────────────────────
    # Nullable because rows recorded before this existed have no honest
    # value to backfill. NULL means "never reviewed", which is a state the
    # review inbox chases, not a date to invent.
    review_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verification_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Whether the review date has passed. Computed on read.

        A signature with no review date is not expired — it is ungoverned,
        which :meth:`governance_state` reports separately.
        """
        if self.review_date is None:
            return False
        ref = now or _utcnow()
        review = self.review_date
        # Stored naive in SQLite; comparing naive against aware raises, and
        # assuming local time would move every review date by the offset.
        if review.tzinfo is None:
            review = review.replace(tzinfo=timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        return review <= ref

    def governance_state(self, now: Optional[datetime] = None) -> str:
        """One word for how much this signature can be relied on.

        ``disabled``
            Switched off. Suppressing nothing, so nothing to review.
        ``lapsed``
            Its review date has passed. Stops matching — the parity with
            quirks. Checked before ``unverified`` because when both are
            true, this is the one that changes behaviour.
        ``ungoverned``
            No review date at all. Recorded before governance existed; it
            still matches, and is listed for review.
        ``unverified``
            Dated but on one person's judgement only.
        ``active``
            Verified by a second person and in date.
        """
        if not self.enabled:
            return "disabled"
        if self.is_expired(now):
            return "lapsed"
        if self.review_date is None:
            return "ungoverned"
        if self.verified_by_id is None:
            return "unverified"
        return "active"

    def to_dict(self, now: Optional[datetime] = None) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "alert_signature": self.alert_signature,
            "host_pattern": self.host_pattern,
            "user_pattern": self.user_pattern,
            "reason": self.reason,
            "confidence": self.confidence,
            "recorded_by": self.recorded_by,
            "recorded_at": self.recorded_at.isoformat() if self.recorded_at else None,
            "hit_count": self.hit_count,
            "last_matched_at": (
                self.last_matched_at.isoformat() if self.last_matched_at else None
            ),
            "enabled": self.enabled,
            "review_date": self.review_date.isoformat() if self.review_date else None,
            "expired": self.is_expired(now),
            "governance_state": self.governance_state(now),
            "verified_by_id": self.verified_by_id,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "verification_note": self.verification_note,
        }

    def __repr__(self) -> str:
        return (
            f"<FalsePositiveSignature(id={self.id}, rule='{self.rule_name}', "
            f"enabled={self.enabled}, hits={self.hit_count}, "
            f"governance={self.governance_state()})>"
        )
