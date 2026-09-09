"""AnalystPinnedField — per-user / per-rule pins with a global fallback.

Locks the two things the pinned-fields API relies on: the resolution query
(global '' plus the alert's rule, never another user's rows) and that '' (not
NULL) makes the unique constraint reject duplicate global pins.
"""

import pytest
from sqlalchemy.exc import IntegrityError

from ion.models import AnalystPinnedField


def _add(session, uid, rule, field):
    p = AnalystPinnedField(user_id=uid, rule_id=rule, field_name=field)
    session.add(p)
    session.commit()
    return p


def _resolve(session, uid, rule_id):
    q = session.query(AnalystPinnedField).filter(AnalystPinnedField.user_id == uid)
    if rule_id:
        q = q.filter(AnalystPinnedField.rule_id.in_(["", rule_id]))
    return sorted(r.field_name for r in q.all())


def test_global_and_rule_scope_resolution(session):
    _add(session, 1, "", "host.name")                   # global
    _add(session, 1, "RuleX", "process.command_line")   # rule-scoped
    _add(session, 2, "", "user.name")                   # a different user

    # This rule -> global + rule-scoped, merged.
    assert _resolve(session, 1, "RuleX") == ["host.name", "process.command_line"]
    # A different rule -> only the global fallback.
    assert _resolve(session, 1, "RuleY") == ["host.name"]
    # Another user's pins never leak in.
    assert _resolve(session, 2, "RuleX") == ["user.name"]


def test_duplicate_rule_pin_rejected(session):
    _add(session, 1, "RuleX", "host.name")
    with pytest.raises(IntegrityError):
        _add(session, 1, "RuleX", "host.name")
    session.rollback()


def test_duplicate_global_pin_rejected(session):
    # '' rather than NULL so the (user, rule, field) unique constraint bites.
    _add(session, 1, "", "host.name")
    with pytest.raises(IntegrityError):
        _add(session, 1, "", "host.name")
    session.rollback()
