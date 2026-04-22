"""KB document embedding — vector representation of a Knowledge Base article.

Populated by `ion.services.kb_embedding_service` on a background loop.
Queried at Bob's investigation time to retrieve the top-K most semantically
similar KB articles and inject them into his system prompt as context.

Parallel to ``CaseEmbedding`` — same pattern, different source entity.
Separate table so the hot ``documents`` row stays lean and we can re-embed
without touching the doc itself.
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

# Guarded pgvector import — module loads on non-pgvector dev setups.
try:
    from pgvector.sqlalchemy import Vector  # type: ignore
    _HAS_PGVECTOR = True
except ImportError:  # pragma: no cover
    _HAS_PGVECTOR = False
    Vector = None  # type: ignore


# Matches CaseEmbedding — same model (nomic-embed-text) => same dim.
EMBEDDING_DIM = 768


class KBDocumentEmbedding(Base):
    """Vector representation of a Knowledge Base Document for RAG retrieval."""

    __tablename__ = "kb_document_embeddings"
    __table_args__ = (
        Index("ix_kb_doc_embeddings_model", "model_name"),
        Index("ix_kb_doc_embeddings_embedded_at", "embedded_at"),
    )

    document_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("documents.id", ondelete="CASCADE"),
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

    document = relationship("Document", foreign_keys=[document_id])

    def __repr__(self) -> str:
        return (
            f"<KBDocumentEmbedding(document_id={self.document_id}, "
            f"model='{self.model_name}')>"
        )


def ensure_kb_hnsw_index(engine) -> None:
    """Create the HNSW index on ``kb_document_embeddings.embedding``.

    Idempotent. Uses raw DDL because SQLAlchemy's Index(...) doesn't know
    about pgvector's ``USING hnsw`` syntax. Called from ``init_db`` after
    ``create_all`` has created the table.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_kb_doc_embeddings_vec_hnsw "
                    "ON kb_document_embeddings USING hnsw "
                    "(embedding vector_cosine_ops)"
                )
            )
    except Exception:
        # Non-pgvector backend — safe to skip.
        pass
