"""Threat-intel report cache + chunk embeddings (TI-report RAG, v0.53.0).

ION never previously stored OpenCTI report bodies — every report view was a
live GraphQL fetch, which meant (a) no offline value on an air-gapped estate
whose OpenCTI is down, and (b) nothing for Bob's RAG to retrieve from. These
two tables close that gap:

``TIReport``
    A local cache of recent OpenCTI reports (metadata + bounded body),
    upserted by the ``ti_report_service`` background loop keyed on the
    OpenCTI id. First-party-adjacent data: it is the operator's own curated
    threat intel, already rendered in ION's Threat Landscape UI — caching
    it locally is a NEW data-at-rest surface and is documented as such in
    SECURITY_ASSESSMENT.

``TIReportChunkEmbedding``
    Chunk-level vectors over the cached report body — chunked for the same
    reason the KB corpus is (v0.51.0): whole-document vectors lose long
    reports' tails to the embedding window, and retrieval should quote the
    passage that matched, not the report head. Same shape as
    ``KBChunkEmbedding``: composite PK, chunk text stored, whole-report
    staleness hash shared across a report's rows.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
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


# Matches CaseEmbedding / KBChunkEmbedding — same model => same dim.
EMBEDDING_DIM = 768

# Bound on the cached body. Reports beyond this are clipped at sync time —
# the cache exists for retrieval context, not archival fidelity, and an
# unbounded TEXT column fed from an external system is a data-at-rest and
# memory hazard. 40k chars ≈ 25 chunks, far past what retrieval quotes.
MAX_REPORT_BODY_CHARS = 40_000


class TIReport(Base):
    """Locally cached OpenCTI threat report (metadata + bounded body)."""

    __tablename__ = "ti_reports"
    __table_args__ = (
        Index("ix_ti_reports_opencti_id", "opencti_id", unique=True),
        Index("ix_ti_reports_published", "published"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    opencti_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    # ISO-8601 string as OpenCTI supplies it — display/ordering context only,
    # so no fragile datetime parsing of an external system's formats.
    published: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    report_types: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    labels: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    # content if OpenCTI has it, else description — clipped to
    # MAX_REPORT_BODY_CHARS at sync time.
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    def __repr__(self) -> str:
        return f"<TIReport(id={self.id}, opencti_id='{self.opencti_id}')>"


class TIReportChunkEmbedding(Base):
    """Vector representation of one cached-report passage for RAG retrieval."""

    __tablename__ = "ti_report_chunk_embeddings"
    __table_args__ = (
        Index("ix_ti_chunk_embeddings_model", "model_name"),
        Index("ix_ti_chunk_embeddings_embedded_at", "embedded_at"),
    )

    report_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("ti_reports.id", ondelete="CASCADE"),
        primary_key=True,
    )
    chunk_index: Mapped[int] = mapped_column(Integer, primary_key=True)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)

    if _HAS_PGVECTOR:
        embedding: Mapped[list] = mapped_column(
            Vector(EMBEDDING_DIM), nullable=False
        )
    else:  # pragma: no cover — non-pgvector fallback
        embedding: Mapped[str] = mapped_column(String, nullable=False)

    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    embedded_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # SHA-256 of the WHOLE report's source text (+ chunk-scheme marker) at
    # embed time — identical across a report's chunk rows; staleness is
    # checked per report.
    source_text_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    report = relationship("TIReport", foreign_keys=[report_id])

    def __repr__(self) -> str:
        return (
            f"<TIReportChunkEmbedding(report_id={self.report_id}, "
            f"chunk_index={self.chunk_index}, model='{self.model_name}')>"
        )


def ensure_ti_report_hnsw_index(engine) -> None:
    """Create the HNSW index on ``ti_report_chunk_embeddings.embedding``.

    Idempotent. Raw DDL because SQLAlchemy's Index(...) doesn't know
    pgvector's ``USING hnsw`` syntax. Called from ``init_db`` after
    ``create_all`` has created the table.
    """
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_ti_chunk_embeddings_vec_hnsw "
                    "ON ti_report_chunk_embeddings USING hnsw "
                    "(embedding vector_cosine_ops)"
                )
            )
    except Exception:
        # Non-pgvector backend — safe to skip.
        pass
