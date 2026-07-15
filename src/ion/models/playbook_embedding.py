"""Playbook embedding — vector representation of a response playbook.

Populated by `ion.services.playbook_embedding_service` on a background
loop. Queried at Bob's investigation time as the FALLBACK arm of the
Playbook RAG layer (v0.51.0): the primary arm is the deterministic
structured matcher (``Playbook.matches_alert`` over rule patterns / MITRE
techniques / tactics), which needs no vectors at all; the embedding
similarity only fires when no playbook matches structurally, so an alert
type nobody wrote trigger conditions for can still surface a semantically
relevant procedure.

Parallel to ``CaseEmbedding`` / ``KBChunkEmbedding`` — same pattern.
Playbooks are single-screen procedures (name + description + a handful of
steps), well inside nomic's window, so one vector per playbook is enough —
no chunking needed here.
"""

from datetime import datetime

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

# Guarded pgvector import — module loads on non-pgvector dev setups.
try:
    from pgvector.sqlalchemy import Vector  # type: ignore
    _HAS_PGVECTOR = True
except ImportError:  # pragma: no cover
    _HAS_PGVECTOR = False
    Vector = None  # type: ignore


# Matches CaseEmbedding — same model (nomic-embed-text) => same dim.
EMBEDDING_DIM = 768


class PlaybookEmbedding(Base):
    """Vector representation of a Playbook for RAG retrieval."""

    __tablename__ = "playbook_embeddings"
    __table_args__ = (
        Index("ix_playbook_embeddings_model", "model_name"),
        Index("ix_playbook_embeddings_embedded_at", "embedded_at"),
    )

    playbook_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        primary_key=True,
    )

    if _HAS_PGVECTOR:
        embedding: Mapped[list] = mapped_column(
            Vector(EMBEDDING_DIM), nullable=False
        )
    else:  # pragma: no cover — non-pgvector fallback
        embedding: Mapped[str] = mapped_column(String, nullable=False)

    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    embedded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    source_text_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    playbook = relationship("Playbook", foreign_keys=[playbook_id])

    def __repr__(self) -> str:
        return (
            f"<PlaybookEmbedding(playbook_id={self.playbook_id}, "
            f"model='{self.model_name}')>"
        )


def ensure_playbook_hnsw_index(engine) -> None:
    """Create the HNSW index on ``playbook_embeddings.embedding``.

    Idempotent. Raw DDL because SQLAlchemy's Index(...) doesn't know
    pgvector's ``USING hnsw`` syntax. Called from ``init_db`` after
    ``create_all`` has created the table.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_playbook_embeddings_vec_hnsw "
                    "ON playbook_embeddings USING hnsw "
                    "(embedding vector_cosine_ops)"
                )
            )
    except Exception:
        # Non-pgvector backend — safe to skip.
        pass
