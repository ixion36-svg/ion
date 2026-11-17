"""How each detection rule's alerts were closed, measured once.

The analyst's closure is the truth about a rule: a case closed as a false
positive says the rule fired on nothing. Every surface that shows a rule's
false-positive rate, or calls a rule noisy, reads it from here: Detection
Health, DE Metrics, the DE Workbench campaigns panel, and the external API
TIDE pulls. Before this, Detection Health counted only the alerts Bob had seen
(the ``ai_feedback`` ledger) while DE Metrics counted every closure, and the two
pages disagreed about the same rule.

The record is per rule identity. A rule is keyed by its ``rule_id`` (the Kibana
``rule_id`` or Wazuh ``rule.id`` copied from the alert) when one is known, and
by its name otherwise. Rows that have only a name fold into the id'd rule that
carries the same name in the window, when exactly one does: older triage rows
whose alert aged out of Elasticsearch before the id was recorded would
otherwise split one rule in two.

A closure is a triage row whose case was closed with a reason inside the
window. ``alerts`` counts triage rows created inside it. Time to close runs from
the triage row's creation, the moment ION first held the alert, to the case's
``closed_at``. Bob's agreement with the analyst is a separate measure and is
not here.
"""

from __future__ import annotations

import os
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_triage import AlertCase, AlertTriage, CaseClosureReason

UNMAPPED = "(unmapped)"
OTHER = "other"
#: Every closure outcome a record counts, in a fixed order. ``other`` holds a
#: reason outside CaseClosureReason, so the counts always sum to ``closed``.
OUTCOMES: Tuple[str, ...] = tuple(r.value for r in CaseClosureReason) + (OTHER,)

DEFAULT_WINDOW_DAYS = 90
MAX_WINDOW_DAYS = 365


def utcnow() -> datetime:
    """Naive UTC, which is how every timestamp column here is stored."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class Window:
    """``since <= t < until``, naive UTC, at most MAX_WINDOW_DAYS long."""

    since: datetime
    until: datetime

    def __post_init__(self) -> None:
        if self.since.tzinfo is not None or self.until.tzinfo is not None:
            raise ValueError("window bounds must be naive UTC")
        if self.until <= self.since:
            raise ValueError("window must end after it starts")
        if self.until - self.since > timedelta(days=MAX_WINDOW_DAYS):
            raise ValueError(f"window must be at most {MAX_WINDOW_DAYS} days")

    @classmethod
    def last(cls, days: int, now: Optional[datetime] = None) -> "Window":
        until = now or utcnow()
        return cls(since=until - timedelta(days=days), until=until)

    @property
    def midpoint(self) -> datetime:
        return self.since + (self.until - self.since) / 2

    @property
    def days(self) -> int:
        return (self.until - self.since).days


@dataclass(frozen=True)
class RuleKey:
    """A rule by its id, or by its name when no id is known.

    Exactly one of the two is set, except the unmapped bucket, which has
    neither: alerts with no rule name at all.
    """

    rule_id: Optional[str] = None
    rule_name: Optional[str] = None

    @property
    def token(self) -> str:
        """A stable, total sort key: every id'd rule, then every named one."""
        if self.rule_id is not None:
            return "i:" + self.rule_id
        return "n:" + (self.rule_name or "")


@dataclass
class RuleOutcome:
    """How one rule's alerts were closed in a window."""

    key: RuleKey
    rule_name: str = UNMAPPED
    rule_uuids: set = field(default_factory=set)
    alerts: int = 0
    outcomes: Dict[str, int] = field(default_factory=lambda: dict.fromkeys(OUTCOMES, 0))
    seconds_to_close: list = field(default_factory=list, repr=False)
    last_closed_at: Optional[datetime] = None
    _name_seen_at: Optional[datetime] = field(default=None, repr=False)

    @property
    def closed(self) -> int:
        return sum(self.outcomes.values())

    @property
    def false_positive(self) -> int:
        return self.outcomes[CaseClosureReason.FALSE_POSITIVE.value]

    @property
    def true_positive(self) -> int:
        return self.outcomes[CaseClosureReason.TRUE_POSITIVE.value]

    @property
    def fp_rate(self) -> Optional[float]:
        """False-positive closures as a percentage of closures, or None with none."""
        return _pct(self.false_positive, self.closed)

    @property
    def tp_yield(self) -> Optional[float]:
        return _pct(self.true_positive, self.closed)

    @property
    def median_seconds_to_close(self) -> Optional[int]:
        if not self.seconds_to_close:
            return None
        return int(statistics.median(self.seconds_to_close))

    def _see_name(self, name: Optional[str], at: Optional[datetime]) -> None:
        """Show the most recently seen name: a renamed rule reads as it is now."""
        if not name:
            return
        if self._name_seen_at is None or (at is not None and at >= self._name_seen_at):
            self.rule_name = name
            self._name_seen_at = at or self._name_seen_at


def _pct(num: int, denom: int) -> Optional[float]:
    if denom <= 0:
        return None
    return round(num / denom * 100, 1)


@dataclass(frozen=True)
class NoisyPolicy:
    """The one definition of a noisy rule.

    Noisy means enough closures to judge (``min_closed``) and a false-positive
    rate at or above ``fp_rate_pct``. The environment names predate this
    module; Detection Health read them first.
    """

    min_closed: int = 5
    fp_rate_pct: float = 70.0

    @classmethod
    def from_env(cls) -> "NoisyPolicy":
        try:
            min_closed = int(os.environ.get("ION_DH_MIN_SAMPLE", cls.min_closed))
        except (TypeError, ValueError):
            min_closed = cls.min_closed
        try:
            fp_rate_pct = float(os.environ.get("ION_DH_NOISY_FP_PCT", cls.fp_rate_pct))
        except (TypeError, ValueError):
            fp_rate_pct = cls.fp_rate_pct
        return cls(min_closed=min_closed, fp_rate_pct=fp_rate_pct)

    def judges(self, outcome: RuleOutcome) -> bool:
        """Whether the rule has enough closures for any verdict about it."""
        return outcome.closed >= self.min_closed

    def is_noisy(self, outcome: RuleOutcome) -> bool:
        rate = outcome.fp_rate
        return self.judges(outcome) and rate is not None and rate >= self.fp_rate_pct


class RuleOutcomes:
    """Every rule's outcome in one window, and the key a triage row belongs to."""

    def __init__(self, window: Window, ids_by_name: Dict[str, set]) -> None:
        self.window = window
        self._ids_by_name = ids_by_name
        self.records: Dict[RuleKey, RuleOutcome] = {}

    def key_for(self, rule_id: Optional[str], rule_name: Optional[str]) -> RuleKey:
        if rule_id:
            return RuleKey(rule_id=rule_id)
        ids = self._ids_by_name.get(rule_name or "")
        if ids is not None and len(ids) == 1:
            return RuleKey(rule_id=next(iter(ids)))
        return RuleKey(rule_name=rule_name or None)

    def record(self, key: RuleKey) -> RuleOutcome:
        rec = self.records.get(key)
        if rec is None:
            rec = self.records[key] = RuleOutcome(key=key, rule_name=key.rule_name or UNMAPPED)
        return rec

    def get(self, key: RuleKey) -> Optional[RuleOutcome]:
        return self.records.get(key)

    def sorted(self) -> list:
        return sorted(self.records.values(), key=lambda r: r.key.token)


def rule_outcomes(session: Session, window: Window) -> RuleOutcomes:
    """Aggregate every rule's alerts and closures inside ``window``."""
    fired = session.execute(
        select(
            AlertTriage.rule_id, AlertTriage.rule_uuid, AlertTriage.rule_name,
            AlertTriage.created_at,
        )
        .where(AlertTriage.created_at >= window.since)
        .where(AlertTriage.created_at < window.until)
    ).all()
    closures = session.execute(
        select(
            AlertTriage.rule_id, AlertTriage.rule_uuid, AlertTriage.rule_name,
            AlertTriage.created_at, AlertCase.closed_at, AlertCase.closure_reason,
        )
        .join(AlertCase, AlertTriage.case_id == AlertCase.id)
        .where(AlertCase.closure_reason.is_not(None))
        .where(AlertCase.closed_at >= window.since)
        .where(AlertCase.closed_at < window.until)
    ).all()

    result = RuleOutcomes(window, _ids_by_name(list(fired) + list(closures)))
    for rule_id, rule_uuid, rule_name, created_at in fired:
        rec = result.record(result.key_for(rule_id, rule_name))
        rec.alerts += 1
        rec._see_name(rule_name, created_at)
        if rule_uuid:
            rec.rule_uuids.add(rule_uuid)

    for rule_id, rule_uuid, rule_name, created_at, closed_at, reason in closures:
        rec = result.record(result.key_for(rule_id, rule_name))
        outcome = reason if reason in rec.outcomes else OTHER
        rec.outcomes[outcome] += 1
        rec._see_name(rule_name, closed_at)
        if rule_uuid:
            rec.rule_uuids.add(rule_uuid)
        if rec.last_closed_at is None or closed_at > rec.last_closed_at:
            rec.last_closed_at = closed_at
        if created_at is not None and closed_at >= created_at:
            rec.seconds_to_close.append((closed_at - created_at).total_seconds())
    return result


def _ids_by_name(rows: Iterable[tuple]) -> Dict[str, set]:
    ids: Dict[str, set] = {}
    for row in rows:
        rule_id, rule_name = row[0], row[2]
        if rule_id and rule_name:
            ids.setdefault(rule_name, set()).add(rule_id)
    return ids
