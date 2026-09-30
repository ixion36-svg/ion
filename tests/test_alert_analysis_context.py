"""The AI analysis prompt carries the SOC's own history, not just the alert.

The defect this pins: the model judged every alert cold — a rule closed as a
false positive twelve times looked exactly like a novel one, and a host
already in an open case carried no urgency.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ion.models.alert_triage import (
    AlertCase,
    AlertCaseStatus,
    AlertTriage,
    AlertTriageStatus,
    KnownFalsePositive,
)
from ion.models.base import Base
from ion.models.user import User
from ion.web.ai_api import _alert_history_context


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ctx.db'}")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _creator(db):
    u = db.query(User).first()
    if u is None:
        u = User(username="t", email="t@x.y", password_hash="x", display_name="t")
        db.add(u)
        db.flush()
    return u


def _case(db, number, title, status=AlertCaseStatus.CLOSED, reason=None, hosts=None):
    c = AlertCase(case_number=number, title=title, status=status,
                  severity="medium", closure_reason=reason, affected_hosts=hosts,
                  created_by_id=_creator(db).id)
    db.add(c)
    db.flush()
    return c


def test_rule_history_counts_and_prior_outcomes(db):
    c1 = _case(db, "CASE-0001", "Beacon on wks-1", reason="false_positive")
    c2 = _case(db, "CASE-0002", "Beacon on wks-2", status=AlertCaseStatus.OPEN)
    for i in range(3):
        db.add(AlertTriage(es_alert_id=f"a{i}", rule_name="Cobalt Strike C2",
                           status=AlertTriageStatus.CLOSED, case_id=c1.id))
    db.add(AlertTriage(es_alert_id="a9", rule_name="Cobalt Strike C2",
                       status=AlertTriageStatus.OPEN, case_id=c2.id))
    db.add(AlertTriage(es_alert_id="other", rule_name="Different Rule",
                       status=AlertTriageStatus.OPEN))
    db.commit()

    out = _alert_history_context(db, {"rule_name": "Cobalt Strike C2"})
    assert "last 4 alerts" in out, "the other rule's alert must not count"
    assert "closed=3" in out and "open=1" in out
    assert "CASE-0001" in out and "closed as false_positive" in out
    assert "CASE-0002" in out


def test_known_fp_patterns_surface(db):
    uid = _creator(db).id
    db.add(KnownFalsePositive(title="Backup agent beacon lookalike", description="d",
                              match_rules=["Cobalt Strike C2"], is_active=True,
                              created_by_id=uid))
    db.add(KnownFalsePositive(title="Inactive old pattern", description="d",
                              match_rules=["Cobalt Strike C2"], is_active=False,
                              created_by_id=uid))
    db.commit()

    out = _alert_history_context(db, {"rule_name": "Cobalt Strike C2"})
    assert "Backup agent beacon lookalike" in out
    assert "Inactive old pattern" not in out


def test_host_history_surfaces_open_cases(db):
    _case(db, "CASE-0010", "Cred dump on wks-114",
          status=AlertCaseStatus.OPEN, hosts=["wks-114.corp"])
    _case(db, "CASE-0011", "Unrelated", hosts=["dc01"])
    db.commit()

    out = _alert_history_context(db, {"host": "wks-114.corp"})
    assert "CASE-0010" in out and "wks-114.corp" in out
    assert "CASE-0011" not in out


def test_empty_inputs_produce_empty_context(db):
    assert _alert_history_context(db, {}) == ""
    assert _alert_history_context(db, {"rule_name": None, "host": 42}) == ""
