"""KB chunk embedding — vector representation of a Knowledge Base passage.

Populated by `ion.services.kb_embedding_service` on a background loop.
Queried at Bob's investigation time to retrieve the top-K most semantically
similar KB passages and inject them into his system prompt as context.

v0.51.0: chunk-level replaces the original whole-document embedding
(``kb_document_embeddings``, one row per doc). A single vector per document
had two defects: (1) nomic-embed-text silently truncates at its context
window, so long articles lost their tails entirely (the service additionally
capped input at 8,000 chars), and (2) retrieval could only surface the
*document*, so the prompt excerpt was the first 800 chars of the doc head —
not the passage that actually matched. Chunk rows fix both: every part of
every article is represented, and the matched chunk's own text goes into the
prompt. The retired whole-doc table is dropped by a v0.51.0 migration; the
background loop re-embeds the corpus into this table on first tick.

Parallel to ``CaseEmbedding`` — same pattern, different source entity.
Separate table so the hot ``documents`` row stays lean and we can re-embed
without touching the doc itself.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
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


class KBChunkEmbedding(Base):
    """Vector representation of one Knowledge Base passage for RAG retrieval."""

    __tablename__ = "kb_chunk_embeddings"
    __table_args__ = (
        Index("ix_kb_chunk_embeddings_model", "model_name"),
        Index("ix_kb_chunk_embeddings_embedded_at", "embedded_at"),
    )

    document_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("documents.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # 0-based position of this chunk within the document. Composite PK with
    # document_id — one row per (doc, chunk).
    chunk_index: Mapped[int] = mapped_column(Integer, primary_key=True)

    # The chunk's own text, stored so retrieval can render the passage that
    # actually matched without re-chunking the document (whose content may
    # have changed since this row was embedded).
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)

    if _HAS_PGVECTOR:
        embedding: Mapped[list] = mapped_column(
            Vector(EMBEDDING_DIM), nullable=False
        )
    else:  # pragma: no cover — non-pgvector fallback
        embedding: Mapped[str] = mapped_column(String, nullable=False)

    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    embedded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # SHA-256 of the WHOLE document's source text (plus the chunking-scheme
    # marker) at embed time — identical across a doc's chunk rows. Staleness
    # is checked per document: hash or model mismatch re-embeds all chunks.
    source_text_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    document = relationship("Document", foreign_keys=[document_id])

    def __repr__(self) -> str:
        return (
            f"<KBChunkEmbedding(document_id={self.document_id}, "
            f"chunk_index={self.chunk_index}, model='{self.model_name}')>"
        )


def ensure_kb_hnsw_index(engine) -> None:
    """Create the HNSW index on ``kb_chunk_embeddings.embedding``.

    Idempotent. Uses raw DDL because SQLAlchemy's Index(...) doesn't know
    about pgvector's ``USING hnsw`` syntax. Called from ``init_db`` after
    ``create_all`` has created the table.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_kb_chunk_embeddings_vec_hnsw "
                    "ON kb_chunk_embeddings USING hnsw "
                    "(embedding vector_cosine_ops)"
                )
            )
    except Exception:
        # Non-pgvector backend — safe to skip.
        pass
