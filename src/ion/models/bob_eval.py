"""Bob Prompt Evaluation Harness models (v0.21.0).

bob_eval_runs: one row per evaluation run (one template or "all").
bob_eval_run_samples: one row per ai_feedback sample evaluated.
"""

from typing import Optional

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class BobEvalRun(Base, TimestampMixin):
    """One evaluation run — a full sweep of ai_feedback rows for a template."""

    __tablename__ = "bob_eval_runs"
    __table_args__ = (
        Index("ix_bob_eval_runs_template_id", "template_id"),
        Index("ix_bob_eval_runs_started_at", "started_at"),
        Index("ix_bob_eval_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # NULL means "all templates"
    template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("alert_prompt_templates.id", ondelete="SET NULL"), nullable=True
    )
    template_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    prompt_body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    sample_size: Mapped[int] = mapped_column(Integer, nullable=False)

    started_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # running | completed | failed
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="running", server_default="running"
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    triggered_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Metric scores (populated on completion)
    precision_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)
    recall_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)
    f1_score: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)

    tp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fn_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tn_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    abstention_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Fraction of samples where dominant CaseClosureReason keyword in reasoning
    # does not match the emitted verdict.
    hallucination_proxy: Mapped[Optional[float]] = mapped_column(Numeric(5, 4), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "template_id": self.template_id,
            "template_name": self.template_name,
            "prompt_body_hash": self.prompt_body_hash,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "sample_size": self.sample_size,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "error_message": self.error_message,
            "triggered_by_id": self.triggered_by_id,
            "precision_score": float(self.precision_score) if self.precision_score is not None else None,
            "recall_score": float(self.recall_score) if self.recall_score is not None else None,
            "f1_score": float(self.f1_score) if self.f1_score is not None else None,
            "tp_count": self.tp_count,
            "fp_count": self.fp_count,
            "fn_count": self.fn_count,
            "tn_count": self.tn_count,
            "abstention_count": self.abstention_count,
            "hallucination_proxy": float(self.hallucination_proxy) if self.hallucination_proxy is not None else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class BobEvalRunSample(Base):
    """One sample row — an ai_feedback entry evaluated during a run."""

    __tablename__ = "bob_eval_run_samples"
    __table_args__ = (
        Index("ix_bob_eval_run_samples_run_id", "eval_run_id"),
        UniqueConstraint("eval_run_id", "ai_feedback_id", name="uq_bob_eval_sample"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    eval_run_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("bob_eval_runs.id", ondelete="CASCADE"), nullable=False
    )
    ai_feedback_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("ai_feedback.id", ondelete="CASCADE"), nullable=False
    )

    bob_verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    human_verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    agreement: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    confidence_int: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    reasoning_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "eval_run_id": self.eval_run_id,
            "ai_feedback_id": self.ai_feedback_id,
            "bob_verdict": self.bob_verdict,
            "human_verdict": self.human_verdict,
            "agreement": self.agreement,
            "confidence_int": self.confidence_int,
            "reasoning_text": self.reasoning_text,
        }
