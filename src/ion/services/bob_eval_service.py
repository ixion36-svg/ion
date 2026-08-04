"""Bob Prompt Evaluation Harness service (v0.21.0).

Runs every configured AlertPromptTemplate against a labelled ai_feedback
dataset and reports precision / recall / F1 per template.

Ground-truth mapping:
  agreement IS TRUE  => TP  (Bob agreed with human)
  agreement IS FALSE => FP or FN (misclassified — treated as missed)
  agreement IS NULL  => abstention (not penalised)
  auto_escalated = TRUE => abstention (circuit-breaker fired)

De-duplication: keeps max(id) row per (alert_id, alert_prompt_template_id)
so circuit-breaker "pending" rows from fire-time and later case-close rows
are not double-counted.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from ion.models.bob_eval import BobEvalRun, BobEvalRunSample
from ion.storage.database import (
    LOCK_INVESTIGATION_BG,
    get_engine,
    get_session_factory,
)

logger = logging.getLogger(__name__)

# Two-int advisory-lock namespaces for the eval harness.
# "BPEH" = Bob Prompt Eval Harness (4 ASCII bytes as int32). The per-template
# serialisation lock and the per-run re-entry lock MUST use DISTINCT namespaces
# so their keys (template_id vs eval_run_id, drawn from different PK sequences)
# cannot alias onto the same (ns, key) pair.
_BPEH_NS = 0x42504548          # per-template serialisation lock
_BPEH_RUN_NS = 0x42504552      # per-run re-entry lock ("BPER")

_MAX_SAMPLE_SIZE = 200

# CaseClosureReason keyword list for hallucination_proxy heuristic.
_VERDICT_KEYWORDS = [
    "true_positive",
    "false_positive",
    "benign",
    "inconclusive",
    "resolved",
    "tuned_out",
]


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def _compute_metrics(
    tp: int, fp: int, fn: int, tn: int
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """Return (precision, recall, f1) from raw counts.

    Returns None for each score if the denominator is zero.
    Precision = TP / (TP + FP)
    Recall    = TP / (TP + FN)
    F1        = 2 * P * R / (P + R)
    """
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None

    if tp + fp > 0:
        precision = tp / (tp + fp)
    if tp + fn > 0:
        recall = tp / (tp + fn)
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)

    return precision, recall, f1


def _dominant_verdict_keyword(text: str) -> Optional[str]:
    """Return the first CaseClosureReason keyword found in text, or None."""
    if not text:
        return None
    lower = text.lower()
    for kw in _VERDICT_KEYWORDS:
        if kw in lower:
            return kw
    return None


def _compute_hallucination_proxy(
    samples: List[Dict[str, Any]]
) -> Optional[float]:
    """Fraction of samples where reasoning_text dominant keyword != bob_verdict.

    Only populated when at least one sample has reasoning_text. Returns None
    if no samples have reasoning_text.
    """
    eligible = [s for s in samples if s.get("reasoning_text")]
    if not eligible:
        return None
    mismatches = 0
    for s in eligible:
        kw = _dominant_verdict_keyword(s["reasoning_text"])
        verdict = (s.get("bob_verdict") or "").lower()
        if kw is not None and kw != verdict:
            mismatches += 1
    return mismatches / len(eligible)


def _prompt_hash(prompt_text: str) -> str:
    """SHA-256 of the prompt text at run start — snapshot for drift detection."""
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def create_eval_run(
    *,
    template_id: Optional[int],
    sample_size: int,
    triggered_by_id: int,
    session: Session,
) -> BobEvalRun:
    """Create a BobEvalRun row and return it. Does NOT start the eval."""
    from ion.models.alert_prompt import AlertPromptTemplate
    from ion.services.ollama_service import get_ollama_service

    sample_size = min(sample_size, _MAX_SAMPLE_SIZE)

    # Snapshot template name + prompt hash at creation time.
    template_name: Optional[str] = None
    prompt_text_hash = "0" * 64  # sentinel for "all templates"

    if template_id is not None:
        tmpl = session.get(AlertPromptTemplate, template_id)
        if tmpl is None:
            raise ValueError(f"AlertPromptTemplate {template_id} not found")
        template_name = tmpl.name
        prompt_text_hash = _prompt_hash(tmpl.prompt_text or "")

    svc = get_ollama_service()
    model_name = svc.default_model if svc else "unknown"

    now_iso = datetime.now(timezone.utc).isoformat()
    run = BobEvalRun(
        template_id=template_id,
        template_name=template_name,
        prompt_body_hash=prompt_text_hash,
        model_name=model_name,
        model_version=None,
        sample_size=sample_size,
        started_at=now_iso,
        status="running",
        triggered_by_id=triggered_by_id,
        tp_count=0,
        fp_count=0,
        fn_count=0,
        tn_count=0,
        abstention_count=0,
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    return run


def get_eval_run(eval_run_id: int, session: Session) -> Optional[BobEvalRun]:
    """Return a single BobEvalRun or None."""
    return session.get(BobEvalRun, eval_run_id)


def list_eval_runs(
    template_id: Optional[int],
    limit: int,
    session: Session,
) -> List[BobEvalRun]:
    """List eval runs, optionally filtered by template_id, newest first."""
    q = session.query(BobEvalRun)
    if template_id is not None:
        q = q.filter(BobEvalRun.template_id == template_id)
    return q.order_by(BobEvalRun.id.desc()).limit(limit).all()


def list_eval_run_samples(
    eval_run_id: int,
    limit: int,
    offset: int,
    session: Session,
) -> List[BobEvalRunSample]:
    """Return paginated samples for a run."""
    return (
        session.query(BobEvalRunSample)
        .filter(BobEvalRunSample.eval_run_id == eval_run_id)
        .order_by(BobEvalRunSample.id)
        .offset(offset)
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Background evaluation
# ---------------------------------------------------------------------------


def run_eval_async(eval_run_id: int) -> None:
    """Spawn a daemon thread to run the evaluation. Returns immediately."""
    t = threading.Thread(
        target=_run_eval_sync,
        args=(eval_run_id,),
        daemon=True,
        name=f"ion-bob-eval-{eval_run_id}",
    )
    t.start()


def _acquire_try_advisory_lock(session: Session, lock_id: int) -> bool:
    """Non-blocking session-scoped advisory lock attempt (Postgres only).

    Returns True if acquired, False otherwise. On SQLite always returns True
    (single-process; no lock contention possible).
    """
    if session.bind is None:
        return True
    if session.bind.dialect.name != "postgresql":
        return True
    result = session.execute(
        text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}
    )
    return bool(result.scalar())


def _release_advisory_lock(session: Session, lock_id: int) -> None:
    """Release a session-scoped advisory lock. No-op on SQLite."""
    if session.bind is None:
        return
    if session.bind.dialect.name != "postgresql":
        return
    session.execute(
        text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id}
    )


def _try_lock_on(conn, ns: int, key: int) -> bool:
    """Acquire a session-scoped two-int advisory lock on a specific connection.

    Returns True if granted, False if already held elsewhere. Session-scoped
    (not xact-scoped) so it survives the COMMITs that ``_execute_eval`` issues
    before the Ollama loop; held until explicitly released or the connection is
    closed. Must be taken on a DEDICATED connection — the ORM session returns
    its connection to the pool on commit, which would silently drop the lock.
    """
    return bool(
        conn.execute(
            text("SELECT pg_try_advisory_lock(:ns, :key)"), {"ns": ns, "key": key}
        ).scalar()
    )


def _release_locks_on(conn) -> None:
    """Release ALL session-scoped advisory locks held on this connection.

    Returning a connection to the pool does NOT drop session-level advisory
    locks (the physical connection stays alive and may be reused), so they must
    be unlocked explicitly before the connection is closed.
    """
    try:
        conn.execute(text("SELECT pg_advisory_unlock_all()"))
    except Exception:
        logger.debug("pg_advisory_unlock_all failed during cleanup", exc_info=True)


def _run_eval_sync(eval_run_id: int) -> None:
    """Core evaluation loop. Runs in a background thread."""
    engine = get_engine()
    factory = get_session_factory(engine)
    session = factory()
    lock_conn = None  # dedicated connection holding the serialisation locks

    try:
        run = session.get(BobEvalRun, eval_run_id)
        if run is None:
            logger.error("BobEvalRun %d not found", eval_run_id)
            return

        # --- Fix 1: guard against investigation loop holding its own lock ---
        # Attempt to acquire LOCK_INVESTIGATION_BG (non-blocking). If the
        # investigation loop already holds it, fail fast rather than running
        # Ollama calls that compete with live triage work.
        inv_lock_acquired = _acquire_try_advisory_lock(session, LOCK_INVESTIGATION_BG)
        if not inv_lock_acquired:
            run.status = "failed"
            run.error_message = "investigation loop active — try again later"
            session.commit()
            return
        # Release immediately — we only needed to know the loop wasn't running.
        _release_advisory_lock(session, LOCK_INVESTIGATION_BG)

        # --- Fix 7: per-template + per-run serialisation -------------------
        # Serialise same-template runs (key = template_id, or 0 for "all
        # templates") so two simultaneous POSTs don't each spawn up to 200
        # Ollama calls, plus a per-run lock to prevent re-entry of one run.
        #
        # These locks MUST outlive the COMMITs that _execute_eval issues before
        # the Ollama loop, so they are session-scoped (not pg_advisory_xact_lock,
        # which releases on the next COMMIT) and held on a DEDICATED connection
        # (the ORM session returns its connection to the pool on commit, which
        # would silently drop the lock). Non-blocking: if another worker already
        # holds the lock, skip rather than double-spend the Ollama budget.
        if session.bind is not None and session.bind.dialect.name == "postgresql":
            lock_conn = engine.connect()
            template_lock_key = run.template_id if run.template_id is not None else 0
            if not _try_lock_on(lock_conn, _BPEH_NS, template_lock_key):
                run.status = "skipped"
                run.error_message = "another eval for this template is already running"
                session.commit()
                return
            if not _try_lock_on(lock_conn, _BPEH_RUN_NS, eval_run_id):
                run.status = "skipped"
                run.error_message = "this eval run is already executing"
                session.commit()
                return

        _execute_eval(run, session)

    except Exception as exc:
        logger.exception("BobEvalRun %d failed: %s", eval_run_id, exc)
        try:
            run = session.get(BobEvalRun, eval_run_id)
            if run:
                run.status = "failed"
                run.error_message = str(exc)[:1000]
                session.commit()
        except Exception:
            pass
    finally:
        # Release the serialisation locks BEFORE closing — returning the
        # connection to the pool does not drop session-scoped advisory locks.
        if lock_conn is not None:
            _release_locks_on(lock_conn)
            try:
                lock_conn.close()
            except Exception:
                pass
        try:
            session.close()
        except Exception:
            pass


def _execute_eval(run: BobEvalRun, session: Session) -> None:
    """Inner eval logic — query samples, call Ollama, write results."""
    from ion.models.alert_prompt import AlertPromptTemplate
    from ion.services.ollama_service import get_ollama_service

    # Refresh prompt_body_hash from template (snapshot at run time).
    if run.template_id is not None:
        tmpl = session.get(AlertPromptTemplate, run.template_id)
        if tmpl is None:
            run.status = "failed"
            run.error_message = f"template {run.template_id} deleted before eval ran"
            session.commit()
            return
        run.prompt_body_hash = _prompt_hash(tmpl.prompt_text or "")
        run.template_name = tmpl.name
        session.commit()
    else:
        tmpl = None

    # --- Fetch de-duplicated ai_feedback rows --------------------------------
    feedback_rows = _fetch_deduped_feedback(
        session=session,
        template_id=run.template_id,
        sample_size=run.sample_size,
    )

    if not feedback_rows:
        run.status = "failed"
        run.error_message = "no qualifying ai_feedback rows for this template/sample_size"
        session.commit()
        return

    # --- Evaluate each sample -----------------------------------------------
    svc = get_ollama_service()
    sample_records: List[Dict[str, Any]] = []
    tp = fp = fn = tn = abstentions = skipped = 0

    for fb_row in feedback_rows:
        fb_id = fb_row["id"]
        human_verdict = fb_row["human_verdict"]
        auto_escalated = fb_row.get("auto_escalated", False)

        # Auto-escalated rows are abstentions regardless of fresh Ollama call.
        if auto_escalated or human_verdict == "pending":
            abstentions += 1
            sample_rec = BobEvalRunSample(
                eval_run_id=run.id,
                ai_feedback_id=fb_id,
                bob_verdict=None,
                human_verdict=human_verdict,
                agreement=None,
                confidence_int=None,
                reasoning_text=None,
            )
            session.add(sample_rec)
            sample_records.append({
                "bob_verdict": None,
                "reasoning_text": None,
            })
            continue

        # Fix 2: call Ollama using the live prompt-builder path.
        # Returns skipped=True when the investigation/alert was deleted.
        fresh_verdict, confidence_int, reasoning_text, was_skipped = _call_ollama_for_sample(
            svc=svc,
            fb_row=fb_row,
            run_id=run.id,
            session=session,
        )

        if was_skipped:
            skipped += 1
            continue

        # Classify sample.
        agreement: Optional[bool] = None
        if fresh_verdict is not None and human_verdict not in ("pending", ""):
            agreement = _verdicts_agree(fresh_verdict, human_verdict)

        if agreement is None:
            abstentions += 1
        else:
            # v0.69.0: real confusion matrix against the analyst's verdict.
            #
            # This previously did `tp += 1` on agreement and `fp += 1; fn += 1`
            # on disagreement, which made fp == fn ALWAYS — so precision ==
            # recall == f1 == the agreement rate, and the page showed one number
            # under three different statistical names.
            #
            # Bob's verdict and the human's are both known, so score them
            # properly with "this alert is a real threat" as the positive class:
            #   both say threat            -> TP
            #   Bob says threat, human not -> FP  (Bob over-flagged)
            #   Bob says not, human threat -> FN  (Bob missed a real threat)
            #   neither says threat        -> TN
            # Precision now means "of the alerts Bob escalated, how many were
            # real", and recall "of the real threats, how many Bob caught" —
            # which is what a SOC actually wants to know.
            bob_positive = _is_threat_verdict(fresh_verdict)
            human_positive = _is_threat_verdict(human_verdict)
            if bob_positive and human_positive:
                tp += 1
            elif bob_positive and not human_positive:
                fp += 1
            elif not bob_positive and human_positive:
                fn += 1
            else:
                tn += 1

        sample_rec = BobEvalRunSample(
            eval_run_id=run.id,
            ai_feedback_id=fb_id,
            bob_verdict=fresh_verdict,
            human_verdict=human_verdict,
            agreement=agreement,
            confidence_int=confidence_int,
            reasoning_text=reasoning_text,
        )
        session.add(sample_rec)
        sample_records.append({
            "bob_verdict": fresh_verdict,
            "reasoning_text": reasoning_text,
        })

    # --- Compute metrics and persist ----------------------------------------
    precision, recall, f1 = _compute_metrics(tp, fp, fn, tn)
    hp = _compute_hallucination_proxy(sample_records)

    run.tp_count = tp
    run.fp_count = fp
    run.fn_count = fn
    run.tn_count = tn
    run.abstention_count = abstentions
    run.skipped_count = skipped
    run.precision_score = round(precision, 4) if precision is not None else None
    run.recall_score = round(recall, 4) if recall is not None else None
    run.f1_score = round(f1, 4) if f1 is not None else None
    run.hallucination_proxy = round(hp, 4) if hp is not None else None
    run.status = "completed"
    run.completed_at = datetime.now(timezone.utc).isoformat()
    session.commit()
    logger.info(
        "BobEvalRun %d completed: tp=%d fp=%d fn=%d tn=%d abs=%d skipped=%d "
        "P=%.4f R=%.4f F1=%.4f",
        run.id, tp, fp, fn, tn, abstentions, skipped,
        precision or 0.0, recall or 0.0, f1 or 0.0,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fetch_deduped_feedback(
    session: Session,
    template_id: Optional[int],
    sample_size: int,
) -> List[Dict[str, Any]]:
    """Query ai_feedback, de-dup by (alert_id, template_id), return dicts.

    De-duplication keeps max(id) per (alert_id, alert_prompt_template_id).
    This handles the case where a circuit-breaker "pending" row and a later
    case-close row exist for the same alert.
    """
    is_pg = session.bind is not None and session.bind.dialect.name == "postgresql"

    if template_id is not None:
        if is_pg:
            sql = text("""
                SELECT id, alert_id, alert_prompt_template_id,
                       bob_suggested_verdict, human_verdict, agreement,
                       bob_confidence_int, auto_escalated, investigation_id
                FROM ai_feedback
                WHERE id IN (
                    SELECT MAX(id)
                    FROM ai_feedback
                    WHERE alert_prompt_template_id = :tid
                    GROUP BY alert_id, alert_prompt_template_id
                )
                ORDER BY RANDOM()
                LIMIT :lim
            """)
        else:
            sql = text("""
                SELECT id, alert_id, alert_prompt_template_id,
                       bob_suggested_verdict, human_verdict, agreement,
                       bob_confidence_int, auto_escalated, investigation_id
                FROM ai_feedback
                WHERE id IN (
                    SELECT MAX(id)
                    FROM ai_feedback
                    WHERE alert_prompt_template_id = :tid
                    GROUP BY alert_id, alert_prompt_template_id
                )
                ORDER BY RANDOM()
                LIMIT :lim
            """)
        rows = session.execute(sql, {"tid": template_id, "lim": sample_size}).fetchall()
    else:
        if is_pg:
            sql = text("""
                SELECT id, alert_id, alert_prompt_template_id,
                       bob_suggested_verdict, human_verdict, agreement,
                       bob_confidence_int, auto_escalated, investigation_id
                FROM ai_feedback
                WHERE id IN (
                    SELECT MAX(id)
                    FROM ai_feedback
                    GROUP BY alert_id, alert_prompt_template_id
                )
                ORDER BY RANDOM()
                LIMIT :lim
            """)
        else:
            sql = text("""
                SELECT id, alert_id, alert_prompt_template_id,
                       bob_suggested_verdict, human_verdict, agreement,
                       bob_confidence_int, auto_escalated, investigation_id
                FROM ai_feedback
                WHERE id IN (
                    SELECT MAX(id)
                    FROM ai_feedback
                    GROUP BY alert_id, alert_prompt_template_id
                )
                ORDER BY RANDOM()
                LIMIT :lim
            """)
        rows = session.execute(sql, {"lim": sample_size}).fetchall()

    return [dict(r._mapping) for r in rows]


def _load_prompt_snapshot_for_sample(
    fb_row: Dict[str, Any],
    session: Session,
) -> Optional[Tuple[str, str]]:
    """Load (system_prompt, user_body) for a feedback row from its linked Investigation.

    Strategy (Fix 2):
    - Look up the Investigation linked to fb_row via investigation_id.
    - Use inv.prompt_snapshot as the user body (exact input Bob saw during live triage).
    - Render the system prompt from the current template (fb_row["alert_prompt_template_id"]).

    Returns (system_prompt, user_body) or None if the investigation has been deleted
    or has no prompt snapshot (retention drop / old row pre-v0.10.11).
    """
    from ion.models.investigation import Investigation

    inv_id = fb_row.get("investigation_id")
    if not inv_id:
        return None

    inv = session.get(Investigation, inv_id)
    if inv is None or not inv.prompt_snapshot:
        return None

    # Build system prompt from the template that was matched at investigation time.
    template_id = fb_row.get("alert_prompt_template_id")
    system_prompt = ""
    if template_id is not None:
        try:
            from ion.models.alert_prompt import AlertPromptTemplate
            from ion.services.alert_prompt_service import render_system_prompt
            tmpl = session.get(AlertPromptTemplate, template_id)
            system_prompt = render_system_prompt(tmpl, alert=None, session=session)
        except Exception as exc:
            logger.debug("Could not render system prompt for template %s: %s", template_id, exc)

    if not system_prompt:
        # Fall back to the generic security system prompt.
        try:
            from ion.services.ollama_service import SYSTEM_PROMPTS
            system_prompt = SYSTEM_PROMPTS.get("security", "")
        except Exception:
            system_prompt = ""

    return system_prompt, inv.prompt_snapshot


def _call_ollama_for_sample(
    svc: Any,
    fb_row: Dict[str, Any],
    run_id: int,
    session: Session,
) -> Tuple[Optional[str], Optional[int], Optional[str], bool]:
    """Call Ollama for one sample and return (verdict, confidence_int, reasoning, skipped).

    Fix 2: builds the same prompt the live investigation loop builds by reusing the
    stored prompt_snapshot from the linked Investigation row. Compares the FRESH
    verdict against ai_feedback.human_verdict (ground truth) — NOT against Bob's
    prior output — so the harness measures template accuracy, not consistency.

    Returns skipped=True when the Investigation or its prompt_snapshot is missing
    (retention drop / alert deleted). The caller increments skipped_count and skips
    the sample without failing the whole run.

    Uses the same sampling params as the live loop: temperature=0.2, seed=run_id.
    """
    if svc is None or not getattr(svc, "enabled", False):
        return None, None, None, False

    prompt_pair = _load_prompt_snapshot_for_sample(fb_row, session)
    if prompt_pair is None:
        # Missing investigation or no snapshot — skip gracefully.
        return None, None, None, True

    system_prompt, user_body = prompt_pair

    try:
        result = asyncio.run(
            svc.chat(
                messages=[{"role": "user", "content": user_body}],
                system_prompt=system_prompt,
                context_type="security",
                temperature=0.2,
                max_tokens=4096,
                seed=run_id,
                # Match the live investigation path: force the JSON envelope so
                # the replayed verdict is parsed the same way it was at triage.
                response_format="json",
                bypass_queue=True,
                user_id=0,
            )
        )
        # OllamaService.chat returns the assistant text under top-level "content"
        # (not nested under "message"). Tolerate the raw-Ollama shape too so a
        # future change can't silently zero every verdict (the prior
        # result["message"]["content"] read did exactly that → all abstentions).
        if isinstance(result, dict):
            content = result.get("content") or result.get("message", {}).get("content", "") or ""
        else:
            content = str(result)
        parsed = _parse_eval_response(content)
        verdict = parsed.get("verdict")
        confidence_int = _safe_int(parsed.get("confidence"))
        reasoning = (parsed.get("analyst_explanation") or "")[:2000] or None
        return verdict, confidence_int, reasoning, False

    except Exception as exc:
        logger.debug("Ollama call failed for sample alert=%s: %s", fb_row.get("alert_id"), exc)
        return None, None, None, False


def _parse_eval_response(content: str) -> Dict[str, Any]:
    """Parse JSON from Ollama response, tolerating non-JSON responses."""
    import json
    try:
        return json.loads(content)
    except Exception:
        pass
    # Try to extract JSON object from prose response.
    import re
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    return {}


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _is_threat_verdict(verdict: Optional[str]) -> bool:
    """True when the verdict says "this alert is a real threat".

    The positive class for the eval confusion matrix. Uses the same
    true_positive family as ``_verdicts_agree`` so the two cannot disagree —
    everything else (false_positive, benign_true_positive, duplicate,
    not_applicable, insufficient_data) is treated as not-a-threat.
    """
    if not verdict:
        return False
    v = verdict.lower().strip().replace(" ", "_").replace("-", "_")
    return v in {"true_positive", "tp"}


def _verdicts_agree(bob_verdict: str, human_verdict: str) -> bool:
    """Normalise and compare verdicts."""
    def _norm(v: str) -> str:
        return v.lower().strip().replace(" ", "_").replace("-", "_")

    bv = _norm(bob_verdict)
    hv = _norm(human_verdict)

    # Direct match.
    if bv == hv:
        return True

    # Semantic groupings: true_positive family vs false_positive/benign family.
    _tp_family = {"true_positive", "tp"}
    _fp_family = {"false_positive", "fp", "benign", "tuned_out"}

    if bv in _tp_family and hv in _tp_family:
        return True
    if bv in _fp_family and hv in _fp_family:
        return True

    return False
