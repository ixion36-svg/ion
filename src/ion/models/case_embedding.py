"""Case embedding model — vector representation of a case for similarity search.

Populated by `ion.services.case_embedding_service` on close (and periodically
for back-fill). Used by the "Similar cases" sidebar and by Bob's few-shot
exemplar retrieval (future work).

Separate table from ``alert_cases`` by design:
  * re-embedding doesn't touch the case row
  * the hot case table stays lean (no 768-float column)
  * we track which model produced the embedding (easy migration)
  * dropping the embedding table is a clean rollback
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ion.models.base import Base

# pgvector provides a SQLAlchemy Vector type. We guard the import so the
# module still loads on SQLite / non-pgvector environments — the migration
# and background task both no-op gracefully in that case.
try:
    from pgvector.sqlalchemy import Vector  # type: ignore
    _HAS_PGVECTOR = True
except ImportError:  # pragma: no cover — pgvector optional at dev-import time
    _HAS_PGVECTOR = False
    Vector = None  # type: ignore


# Embedding dimension for Ollama's `nomic-embed-text`. If the default model
# is changed via ``ION_EMBEDDING_MODEL``, this will need to be revisited —
# we keep the column sized for the default and record the model name per
# row so a mismatched model logs and skips rather than errors.
EMBEDDING_DIM = 768


class CaseEmbedding(Base):
    """Vector representation of a case for similarity search."""

    __tablename__ = "case_embeddings"
    __table_args__ = (
        Index("ix_case_embeddings_model", "model_name"),
        Index("ix_case_embeddings_embedded_at", "embedded_at"),
        # HNSW index for cosine similarity. Declared via Index(...) so
        # SQLAlchemy's create_all sees it — using a raw CREATE INDEX so we
        # can set ``USING hnsw`` and the ``vector_cosine_ops`` operator class.
        # The raw DDL is idempotent because pgvector's CREATE INDEX is
        # guarded by IF NOT EXISTS in our migration code.
    )

    case_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("alert_cases.id", ondelete="CASCADE"),
        primary_key=True,
    )

    # Vector column. The if-available pattern lets the module import on
    # SQLite / dev boxes without pgvector; at runtime with Postgres +
    # pgvector it becomes a proper VECTOR(768) column.
    if _HAS_PGVECTOR:
        embedding: Mapped[list] = mapped_column(
            Vector(EMBEDDING_DIM), nullable=False
        )
    else:  # pragma: no cover — fallback schema for non-pgvector setups
        embedding: Mapped[str] = mapped_column(String, nullable=False)

    # Which embedding model produced this vector (e.g. ``nomic-embed-text``).
    # If a future run uses a different model, background task re-embeds.
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # When this vector was computed — used to skip already-embedded cases
    # unless the source text hash has changed.
    embedded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # SHA-256 of the source text we embedded. Lets the background task
    # detect stale embeddings cheaply without decoding the case row.
    source_text_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    case = relationship("AlertCase", foreign_keys=[case_id])

    def __repr__(self) -> str:
        return (
            f"<CaseEmbedding(case_id={self.case_id}, model='{self.model_name}', "
            f"embedded_at={self.embedded_at.isoformat() if self.embedded_at else None})>"
        )


def ensure_hnsw_index(engine) -> None:
    """Create the HNSW index on ``case_embeddings.embedding`` if missing.

    Called from the startup migration. Uses raw DDL because SQLAlchemy's
    Index(...) doesn't know about pgvector's ``USING hnsw`` syntax. Idempotent.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_case_embeddings_vec_hnsw "
                    "ON case_embeddings USING hnsw (embedding vector_cosine_ops)"
                )
            )
    except Exception:
        # Non-pgvector backend or missing extension — safe to skip.
        pass
