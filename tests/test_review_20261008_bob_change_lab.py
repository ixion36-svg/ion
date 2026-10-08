"""Bob change lab: evidence-backed prompt approval and replayed abstentions.

From the 8 Oct 2026 review (§6, stage 4):

    "**Observed gaps:** prompt approval does not require a referenced
    evaluation. The evaluation harness counts historical auto-escalated rows
    as abstentions without rerunning them, so it cannot show a new prompt
    recovering those examples.

    **Improve:** connect adjudicated cohort → current/candidate replay →
    changed-decision review → approval of exact evaluated text →
    monitoring/revert. Replay previously escalated samples. Expose sample
    size, class balance and unresolved labels. Separate historical
    production abstention from candidate behavior."

Two distinct defects.

**Approval without evidence.** ``approve_proposal`` checked separation of
duty and that a target template existed, then wrote the new prompt live. It
never asked whether anyone had evaluated the text being approved. So the
evaluation harness existed beside the approval flow rather than inside it.

**The abstention shortcut.** The harness did this::

    if auto_escalated or human_verdict == "pending":
        abstentions += 1
        continue

``auto_escalated`` means the *production* circuit breaker fired — Bob's
confidence was too low, so a human resolved the alert manually. Counting
that as an abstention *of the candidate prompt*, without ever asking the
candidate, makes the one thing a tuner most wants to know unmeasurable: has
the new prompt learned to answer the alerts the old one gave up on. Worse,
it is counted against the candidate, so a prompt that recovered every one of
them would still report them as its own failures.

``human_verdict == "pending"`` is a different thing again: there is no label
to score against. That is an *unresolved label*, not an abstention, and the
review asks for it to be exposed separately.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.models.bob_eval import BobEvalRun
from ion.models.bob_tuning_proposal import (
    BobTuningProposal,
    BobTuningProposalStatus,
)
from ion.models.user import User
from ion.services import bob_eval_service, de_bob_proposal_service as proposals


@pytest.fixture()
def engine(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'change_lab.db'}")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    for uid, name in ((1, "drafter"), (2, "approver")):
        s.add(User(id=uid, username=name, email=f"{name}@x", password_hash="x",
                   display_name=name, is_active=True))
    s.commit()
    yield s
    s.close()


CANDIDATE_TEXT = "You are Bob. Prefer abstaining over guessing.\nAlert: {alert}"


@pytest.fixture()
def template(db):
    from ion.models.alert_prompt import AlertPromptTemplate

    tmpl = AlertPromptTemplate(
        name="Default triage", prompt_text="old prompt text", enabled=True,
    )
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)
    return tmpl


def _proposal(db, template, **over):
    kwargs = dict(
        title="Abstain less on service accounts",
        proposed_text=CANDIDATE_TEXT,
        template_id=template.id,
        created_by_id=1,
    )
    kwargs.update(over)
    p = BobTuningProposal(status=BobTuningProposalStatus.DRAFT, **kwargs)
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _eval_run(db, template, *, text=CANDIDATE_TEXT, status="completed",
              sample_size=40):
    run = BobEvalRun(
        template_id=template.id,
        template_name=template.name,
        prompt_body_hash=bob_eval_service.prompt_body_hash(text),
        model_name="test-model",
        sample_size=sample_size,
        status=status,
        tp_count=20, fp_count=4, fn_count=3, tn_count=13,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


# ── Hashing the exact text ───────────────────────────────────────────────


class TestPromptBodyHash:
    def test_the_hash_is_sha256_of_the_text(self):
        assert bob_eval_service.prompt_body_hash("abc") == hashlib.sha256(
            b"abc").hexdigest()

    def test_the_hash_is_stable_across_processes(self):
        """A salted hash would break the tie between run and approval after
        a restart, so this must not be Python's built-in hash()."""
        assert bob_eval_service.prompt_body_hash("abc") == bob_eval_service.\
            prompt_body_hash("abc")
        assert len(bob_eval_service.prompt_body_hash("abc")) == 64

    def test_whitespace_is_significant(self):
        """A prompt differing only in whitespace is a different prompt to a
        model, so it must not be treated as already evaluated."""
        assert bob_eval_service.prompt_body_hash("a b") != \
            bob_eval_service.prompt_body_hash("a  b")

    def test_none_hashes_as_empty(self):
        assert bob_eval_service.prompt_body_hash(None) == \
            bob_eval_service.prompt_body_hash("")


# ── Approval requires a referenced evaluation ────────────────────────────


class TestApprovalRequiresEvidence:
    def test_approval_without_an_evaluation_is_refused(self, db, template):
        p = _proposal(db, template)
        with pytest.raises(ValueError, match="evaluat"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_approval_with_a_matching_evaluation_succeeds(self, db, template):
        run = _eval_run(db, template)
        p = _proposal(db, template, evaluation_run_id=run.id)
        approved = proposals.approve_proposal(db, p.id, user_id=2)
        assert approved.status == BobTuningProposalStatus.APPROVED

    def test_the_evaluation_must_cover_the_exact_text(self, db, template):
        """The review's "approval of exact evaluated text". Evaluating one
        draft and approving another is evidence for nothing."""
        run = _eval_run(db, template, text="some other candidate text")
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError, match="different text|exact"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_an_unfinished_evaluation_is_not_evidence(self, db, template):
        run = _eval_run(db, template, status="running")
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError, match="not completed|completed"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_a_failed_evaluation_is_not_evidence(self, db, template):
        run = _eval_run(db, template, status="error")
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_a_missing_evaluation_is_refused(self, db, template):
        p = _proposal(db, template, evaluation_run_id=9999)
        with pytest.raises(ValueError, match="not found|evaluat"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_an_evaluation_of_another_template_is_refused(self, db, template):
        """Scores from a different prompt's cohort say nothing about this one."""
        from ion.models.alert_prompt import AlertPromptTemplate

        other = AlertPromptTemplate(name="Other", prompt_text="x", enabled=True)
        db.add(other)
        db.commit()
        db.refresh(other)
        run = _eval_run(db, other)
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError, match="template"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_an_evaluation_with_no_samples_is_refused(self, db, template):
        """Zero samples is not evidence, whatever the status says."""
        run = _eval_run(db, template, sample_size=0)
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError, match="sample|no samples"):
            proposals.approve_proposal(db, p.id, user_id=2)

    def test_separation_of_duty_still_applies(self, db, template):
        run = _eval_run(db, template)
        p = _proposal(db, template, evaluation_run_id=run.id)
        with pytest.raises(ValueError, match="separation"):
            proposals.approve_proposal(db, p.id, user_id=1)

    def test_the_approval_records_which_evaluation_backed_it(self, db, template):
        run = _eval_run(db, template)
        p = _proposal(db, template, evaluation_run_id=run.id)
        approved = proposals.approve_proposal(db, p.id, user_id=2)
        assert approved.evaluation_run_id == run.id

    def test_the_template_is_actually_updated(self, db, template):
        run = _eval_run(db, template)
        p = _proposal(db, template, evaluation_run_id=run.id)
        proposals.approve_proposal(db, p.id, user_id=2)
        db.refresh(template)
        assert template.prompt_text == CANDIDATE_TEXT


# ── The override leaves a trace ──────────────────────────────────────────


class TestOverride:
    def test_an_override_needs_a_reason(self, db, template):
        p = _proposal(db, template)
        with pytest.raises(ValueError):
            proposals.approve_proposal(db, p.id, user_id=2, override_reason="  ")

    def test_an_override_with_a_reason_is_allowed(self, db, template):
        """The escape hatch has to exist -- an incident at 03:00 should not be
        blocked by the harness being down -- but it leaves a record."""
        p = _proposal(db, template)
        approved = proposals.approve_proposal(
            db, p.id, user_id=2,
            override_reason="Ollama unavailable; reverting prompt to a known-good text",
        )
        assert approved.status == BobTuningProposalStatus.APPROVED

    def test_the_override_reason_is_stored(self, db, template):
        p = _proposal(db, template)
        approved = proposals.approve_proposal(
            db, p.id, user_id=2, override_reason="Harness offline")
        assert "Harness offline" in (approved.evaluation_override_reason or "")

    def test_an_overridden_approval_is_marked_as_unevidenced(self, db, template):
        p = _proposal(db, template)
        approved = proposals.approve_proposal(
            db, p.id, user_id=2, override_reason="Harness offline")
        assert approved.evaluation_run_id is None
        assert approved.to_dict()["evidence_backed"] is False

    def test_an_evidenced_approval_says_so(self, db, template):
        run = _eval_run(db, template)
        p = _proposal(db, template, evaluation_run_id=run.id)
        approved = proposals.approve_proposal(db, p.id, user_id=2)
        assert approved.to_dict()["evidence_backed"] is True

    def test_an_override_does_not_bypass_separation_of_duty(self, db, template):
        """It waives the evidence requirement, nothing else."""
        p = _proposal(db, template)
        with pytest.raises(ValueError, match="separation"):
            proposals.approve_proposal(db, p.id, user_id=1,
                                       override_reason="urgent")


# ── Replaying production abstentions ─────────────────────────────────────


class TestAbstentionClassification:
    """``classify_replay_sample`` is the arithmetic the shortcut skipped."""

    def test_a_recovered_sample_is_recognised(self, db):
        """Production gave up; the candidate answered, and got it right.
        This is the single number a tuner is looking for."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=True, candidate_verdict="true_positive",
            human_verdict="true_positive",
        )
        assert out["recovered"] is True
        assert out["candidate_abstained"] is False
        assert out["production_abstained"] is True

    def test_a_candidate_answering_wrongly_is_not_a_recovery(self, db):
        """It answered, which is progress, but it is not a recovery."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=True, candidate_verdict="false_positive",
            human_verdict="true_positive",
        )
        assert out["recovered"] is False
        assert out["candidate_abstained"] is False
        assert out["answered_but_wrong"] is True

    def test_a_candidate_that_also_abstains_is_not_a_recovery(self, db):
        out = bob_eval_service.classify_replay_sample(
            production_abstained=True, candidate_verdict=None,
            human_verdict="true_positive",
        )
        assert out["recovered"] is False
        assert out["candidate_abstained"] is True

    def test_a_newly_abstained_sample_is_a_regression(self, db):
        """Production answered this one; the candidate gave up. The review
        asks for changed decisions in both directions."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=False, candidate_verdict=None,
            human_verdict="true_positive",
        )
        assert out["newly_abstained"] is True
        assert out["recovered"] is False

    def test_an_unresolved_label_is_not_an_abstention(self, db):
        """There is nothing to score against. Counting it as an abstention
        blames the prompt for a missing human decision."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=False, candidate_verdict="true_positive",
            human_verdict="pending",
        )
        assert out["unresolved_label"] is True
        assert out["scored"] is False

    def test_an_empty_human_verdict_is_also_unresolved(self, db):
        out = bob_eval_service.classify_replay_sample(
            production_abstained=False, candidate_verdict="true_positive",
            human_verdict="",
        )
        assert out["unresolved_label"] is True

    def test_an_unresolved_label_is_never_a_recovery(self, db):
        """Without a label there is no way to know the candidate was right."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=True, candidate_verdict="true_positive",
            human_verdict="pending",
        )
        assert out["recovered"] is False
        assert out["unresolved_label"] is True

    def test_a_normal_agreement_is_scored(self, db):
        out = bob_eval_service.classify_replay_sample(
            production_abstained=False, candidate_verdict="true_positive",
            human_verdict="true_positive",
        )
        assert out["scored"] is True
        assert out["recovered"] is False
        assert out["newly_abstained"] is False

    def test_a_candidate_abstention_is_not_scored(self, db):
        """No verdict means no confusion-matrix cell to put it in."""
        out = bob_eval_service.classify_replay_sample(
            production_abstained=False, candidate_verdict=None,
            human_verdict="true_positive",
        )
        assert out["scored"] is False


# ── Cohort composition ───────────────────────────────────────────────────


class TestCohortComposition:
    """"Expose sample size, class balance and unresolved labels"."""

    def test_the_class_balance_is_counted(self, db):
        rows = [
            {"human_verdict": "true_positive"},
            {"human_verdict": "true_positive"},
            {"human_verdict": "false_positive"},
            {"human_verdict": "benign_true_positive"},
        ]
        comp = bob_eval_service.cohort_composition(rows)
        assert comp["class_balance"]["true_positive"] == 2
        assert comp["class_balance"]["false_positive"] == 1
        assert comp["class_balance"]["benign_true_positive"] == 1

    def test_the_sample_size_is_the_whole_cohort(self, db):
        rows = [{"human_verdict": "true_positive"}, {"human_verdict": "pending"}]
        assert bob_eval_service.cohort_composition(rows)["sample_size"] == 2

    def test_unresolved_labels_are_counted_and_excluded_from_scored(self, db):
        rows = [
            {"human_verdict": "true_positive"},
            {"human_verdict": "pending"},
            {"human_verdict": ""},
            {"human_verdict": None},
        ]
        comp = bob_eval_service.cohort_composition(rows)
        assert comp["unresolved_labels"] == 3
        assert comp["scored_sample_size"] == 1

    def test_production_abstentions_are_counted_separately(self, db):
        """A fact about the past, not about the candidate."""
        rows = [
            {"human_verdict": "true_positive", "auto_escalated": True},
            {"human_verdict": "true_positive", "auto_escalated": True},
            {"human_verdict": "false_positive", "auto_escalated": False},
        ]
        comp = bob_eval_service.cohort_composition(rows)
        assert comp["production_abstentions"] == 2
        assert comp["replayable_abstentions"] == 2

    def test_an_empty_cohort_reports_zeroes_not_an_error(self, db):
        comp = bob_eval_service.cohort_composition([])
        assert comp["sample_size"] == 0
        assert comp["scored_sample_size"] == 0
        assert comp["class_balance"] == {}

    def test_the_dominant_class_share_is_reported(self, db):
        """A cohort that is 95% one class makes any accuracy figure
        meaningless, so the imbalance has to be visible."""
        rows = [{"human_verdict": "false_positive"} for _ in range(19)]
        rows.append({"human_verdict": "true_positive"})
        comp = bob_eval_service.cohort_composition(rows)
        assert comp["dominant_class"] == "false_positive"
        assert abs(comp["dominant_class_share"] - 0.95) < 0.01

    def test_an_empty_cohort_has_no_dominant_class(self, db):
        """Zero would read as "perfectly balanced"."""
        comp = bob_eval_service.cohort_composition([])
        assert comp["dominant_class"] is None
        assert comp["dominant_class_share"] is None


# ── The harness no longer short-circuits ─────────────────────────────────


class TestNoShortcut:
    def test_the_abstention_shortcut_is_gone(self):
        """The literal defect: auto_escalated rows skipped the Ollama call.

        Parsed rather than grepped. The docstring of
        classify_replay_sample quotes the old code to explain what it
        replaced, so a substring search finds the prose and reports a
        defect that is not there.
        """
        import ast

        src = (_SRC / "ion" / "services" / "bob_eval_service.py"
               ).read_text(encoding="utf-8")
        tree = ast.parse(src)

        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            names = {
                n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)
            }
            if "auto_escalated" not in names:
                continue
            # The defect is specifically: skip the sample entirely.
            if any(isinstance(stmt, ast.Continue) for stmt in node.body):
                offenders.append(node.lineno)

        assert not offenders, (
            "an `auto_escalated` branch still skips the sample with "
            f"`continue` at line(s) {offenders}; production abstentions must "
            "be replayed through the candidate prompt"
        )

    def test_production_abstentions_are_replayed(self):
        src = (_SRC / "ion" / "services" / "bob_eval_service.py"
               ).read_text(encoding="utf-8")
        # The candidate must be asked even when production abstained.
        assert "production_abstained" in src
        assert "classify_replay_sample" in src

    def test_the_run_records_the_new_counts(self):
        from ion.models.bob_eval import BobEvalRun as Run

        for column in ("historical_abstention_count", "recovered_count",
                       "newly_abstained_count", "unresolved_label_count"):
            assert hasattr(Run, column), column

    def test_the_sample_records_whether_production_abstained(self):
        from ion.models.bob_eval import BobEvalRunSample

        assert hasattr(BobEvalRunSample, "production_abstained")

    def test_the_migration_adds_the_columns(self, tmp_path):
        from sqlalchemy import inspect

        from ion.storage.database import _run_migrations

        eng = create_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
        try:
            Base.metadata.create_all(eng)
            _run_migrations(eng)
            run_cols = {c["name"] for c in inspect(eng).get_columns("bob_eval_runs")}
            for column in ("historical_abstention_count", "recovered_count",
                           "newly_abstained_count", "unresolved_label_count",
                           "class_balance"):
                assert column in run_cols, column
            prop_cols = {
                c["name"] for c in inspect(eng).get_columns("bob_tuning_proposals")
            }
            assert "evaluation_run_id" in prop_cols
            assert "evaluation_override_reason" in prop_cols
        finally:
            eng.dispose()
