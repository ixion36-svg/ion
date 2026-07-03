"""v0.49.3 code-review fix: deterministic KB root resolution.

Two seeders (kb_seed_service, soc_template_service) can both create a
top-level 'Knowledge Base' collection and there is no unique constraint, so
duplicates exist in real deployments. The v0.49.2 crash fix taught ONE reader
(kb_embedding_service) to pick the earliest id, but every other consumer
resolved the root via CollectionRepository with unordered `.first()` /
`scalar_one_or_none()` — articles could seed under one root while embeddings
indexed another (KB search silently missing documents), and
get_by_name_and_parent raised MultipleResultsFound outright.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from ion.models.template import Collection
from ion.storage.collection_repository import CollectionRepository


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    from ion.models.document import Base

    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _seed_duplicate_roots(session):
    """Two top-level 'Knowledge Base' roots, higher id inserted FIRST so any
    insertion-order scan would surface the wrong (later) root."""
    session.add(Collection(id=7, name="Knowledge Base", parent_id=None))
    session.commit()
    session.add(Collection(id=3, name="Knowledge Base", parent_id=None))
    session.commit()


def test_get_by_name_returns_earliest_root(session):
    _seed_duplicate_roots(session)
    repo = CollectionRepository(session)
    got = repo.get_by_name("Knowledge Base")
    assert got is not None
    assert got.id == 3, "must converge on the earliest id, like kb_embedding_service"


def test_get_by_name_and_parent_tolerates_duplicates(session):
    """Duplicate roots must resolve deterministically, not raise
    MultipleResultsFound (the original KB-root crash class)."""
    _seed_duplicate_roots(session)
    repo = CollectionRepository(session)
    got = repo.get_by_name_and_parent("Knowledge Base", None)
    assert got is not None
    assert got.id == 3
