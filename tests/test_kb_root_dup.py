"""Regression: _get_kb_root_id must not raise MultipleResultsFound when the
top-level "Knowledge Base" collection has been seeded more than once — that was
crashing the KB-embedding background tick every cycle.
"""

from ion.models.template import Collection
from ion.services.kb_embedding_service import _get_kb_root_id


def test_single_kb_root(session):
    c = Collection(name="Knowledge Base", parent_id=None)
    session.add(c)
    session.commit()
    assert _get_kb_root_id(session) == c.id


def test_no_kb_root_returns_none(session):
    assert _get_kb_root_id(session) is None


def test_duplicate_kb_root_picks_earliest_not_raises(session):
    a = Collection(name="Knowledge Base", parent_id=None)
    session.add(a)
    session.commit()
    b = Collection(name="Knowledge Base", parent_id=None)
    session.add(b)
    session.commit()
    # must not raise; returns the earliest (lowest id)
    assert _get_kb_root_id(session) == min(a.id, b.id)
