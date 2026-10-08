"""Bob Prompt Evaluation Harness models (v0.21.0).

bob_eval_runs: one row per evaluation run (one template or "all").
bob_eval_run_samples: one row per ai_feedback sample evaluated.
"""

from typing import Optional

from sqlalchemy import (
    JSON,
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

    # Fix 2: rows skipped because the linked alert/investigation was deleted.
    skipped_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    # ── Replay accounting (review 2026-10-08 §6) ─────────────────────────
    # The harness used to count a production abstention as an abstention of
    # the *candidate* prompt, without ever asking the candidate. These keep
    # the two apart, which is what makes "has the new prompt learned to
    # answer what the old one gave up on" a measurable question.
    #
    # historical_abstention_count: production's circuit breaker fired for
    #   this many samples. A fact about the past, not about the candidate.
    # recovered_count: production abstained AND the candidate answered AND
    #   the answer matched the human. The number a tuner is looking for.
    # newly_abstained_count: production answered and the candidate gave up.
    #   The regression direction, which matters just as much.
    # unresolved_label_count: no human verdict to score against. Not an
    #   abstention -- blaming the prompt for a missing human decision is the
    #   same category error the shortcut made.
    historical_abstention_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    recovered_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    newly_abstained_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    unresolved_label_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    #: human_verdict -> count for the cohort, plus the dominant-class share.
    #: A cohort that is 95%% one class makes any accuracy figure meaningless,
    #: so the imbalance travels with the scores.
    class_balance: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

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
            "skipped_count": self.skipped_count,
            "historical_abstention_count": self.historical_abstention_count,
            "recovered_count": self.recovered_count,
            "newly_abstained_count": self.newly_abstained_count,
            "unresolved_label_count": self.unresolved_label_count,
            "class_balance": self.class_balance or {},
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

    #: Whether production's circuit breaker fired for this sample. Kept on
    #: the row so a changed-decision review can list exactly which samples
    #: the candidate recovered rather than recomputing from counts.
    production_abstained: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

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
