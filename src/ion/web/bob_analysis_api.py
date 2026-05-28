"""On-demand Bob case analysis (v0.23.1).

Replaces the v0.22.x auto-comment behaviour. Bob no longer writes a Note
to a case on every investigation completion; instead, the analyst clicks
"Get Bob's Analysis" on the case detail page, which calls this endpoint.

The endpoint gathers five inputs the user asked for:

1. Investigations performed on this case (by alert_id_ref → es_alert_id).
2. The rule snapshot for each linked alert (rule_name + severity from
   AlertTriage; raw rule body via ES when available).
3. Observables on the case.
4. Raw alert data from ES for the lead alert (best-effort — ES may be
   unreachable in dev, the prompt tolerates an absent block).
5. Similar closed cases via pgvector (cosine distance ≥ 0.5 by default).

Bob's response is returned to the UI verbatim; the endpoint does NOT
persist anything. If the analyst wants to keep the analysis, they click
"Save as note", which calls the existing
``POST /api/elasticsearch/alerts/cases/{case_id}/notes`` endpoint with
the analysis text as the body, authored by the analyst (not Bob).

Permission: ``case:read`` — generating an analysis is a read action.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.alert_triage import AlertCase, AlertTriage
from ion.models.investigation import Investigation
from ion.models.user import User
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bob-analysis"])


# ── Response shape ───────────────────────────────────────────────────────


class BobAnalysisResponse(BaseModel):
    analysis: str
    model: Optional[str] = None
    sources: dict
    generated_at: str


# ── Context-gathering helpers ────────────────────────────────────────────


def _gather_investigations(session: Session, alert_ids: list[str]) -> list[dict]:
    """Return completed investigations on this case's alerts (newest first)."""
    if not alert_ids:
        return []
    stmt = (
        select(Investigation)
        .where(
            Investigation.alert_id_ref.in_(alert_ids),
            Investigation.status == "completed",
        )
        .order_by(desc(Investigation.completed_at))
        .limit(20)
    )
    rows = session.execute(stmt).scalars().all()
    out = []
    for inv in rows:
        out.append({
            "id": inv.id,
            "alert_id_ref": inv.alert_id_ref,
            "verdict": inv.verdict,
            "severity": inv.severity_assessment,
            "summary": (inv.summary_text or "").strip()[:1200],
            "confidence_int": inv.confidence_int,
            "completed_at": (
                inv.completed_at.isoformat() if inv.completed_at else None
            ),
        })
    return out


def _gather_similar_cases(
    session: Session, case_id: int, limit: int = 5
) -> list[dict]:
    """Top-N similar closed cases (best-effort via pgvector)."""
    try:
        from ion.models.case_embedding import CaseEmbedding
        target = session.query(CaseEmbedding).filter_by(case_id=case_id).first()
        if target is None:
            return []
        distance = CaseEmbedding.embedding.cosine_distance(target.embedding)
        rows = (
            session.query(AlertCase, distance.label("distance"))
            .join(CaseEmbedding, CaseEmbedding.case_id == AlertCase.id)
            .filter(AlertCase.id != case_id)
            .filter(AlertCase.closure_reason.isnot(None))
            .order_by(distance.asc())
            .limit(limit)
            .all()
        )
        out = []
        for case, dist in rows:
            sim = 1.0 - float(dist)
            if sim < 0.5:
                continue
            out.append({
                "case_number": case.case_number,
                "title": case.title,
                "severity": case.severity,
                "closure_reason": case.closure_reason,
                "similarity": round(sim, 3),
            })
        return out
    except Exception as exc:
        logger.debug("Similar cases lookup failed for case %d: %s", case_id, exc)
        return []


async def _gather_raw_alert(alert_id: str) -> Optional[dict]:
    """Best-effort fetch of the raw ES alert for the lead alert id."""
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es = ElasticsearchService()
        if not es.is_configured:
            return None
        hits = await es.get_alerts_by_ids([alert_id])
        if not hits:
            return None
        h = hits[0]
        return {
            "_id": alert_id,
            "rule_name": getattr(h, "rule_name", None),
            "severity": getattr(h, "severity", None),
            "host": getattr(h, "host_name", None) or getattr(h, "host", None),
            "user": getattr(h, "user_name", None) or getattr(h, "user", None),
            "source_ip": getattr(h, "source_ip", None),
            "dest_ip": getattr(h, "destination_ip", None),
            "mitre_techniques": getattr(h, "mitre_techniques", None) or [],
            "fired_at": getattr(h, "fired_at", None),
        }
    except Exception as exc:
        logger.debug("Raw alert fetch failed for %s: %s", alert_id, exc)
        return None


# ── Prompt builder ───────────────────────────────────────────────────────


_SYSTEM_PROMPT = (
    "You are Bob, ION's autonomous SOC analyst, producing an on-demand "
    "case analysis for a human L1/L2 analyst who has explicitly clicked "
    "\"Get Bob's Analysis\". The analyst wants a tight, evidence-grounded "
    "verdict they can paste into the case as a note if they agree. "
    "Cite the SPECIFIC fields, observables, and prior cases you reference. "
    "Do not speculate beyond what the data shows. "
    "Structure your output as markdown with these sections, in order: "
    "1) **Verdict** — one of true_positive | false_positive | "
    "benign_true_positive | inconclusive, with a one-line rationale. "
    "2) **Evidence** — bulleted list of the specific findings (rule, "
    "host, user, observables, prior investigations) you grounded the "
    "verdict on. "
    "3) **Similar prior cases** — if any were provided, name them and "
    "say whether their closure reasons support or contradict your "
    "verdict. "
    "4) **Recommended next steps** — 3-5 bullet actions the analyst "
    "should take. "
    "Be concise. Aim for under 400 words total."
)


def _build_user_prompt(
    case: AlertCase,
    linked_triages: list[AlertTriage],
    investigations: list[dict],
    similar_cases: list[dict],
    raw_alert: Optional[dict],
) -> str:
    """Construct the markdown context block the analyst expects Bob to use."""
    parts: list[str] = []

    parts.append("## Case under review")
    parts.append(f"- **Case number:** `{case.case_number}`")
    parts.append(f"- **Title:** {case.title or '(no title)'}")
    parts.append(f"- **Severity:** {case.severity or 'unknown'}")
    parts.append(f"- **Status:** {case.status}")
    if getattr(case, "mitre_techniques", None):
        parts.append(f"- **MITRE techniques:** {', '.join(case.mitre_techniques)}")
    parts.append("")

    parts.append(f"## Linked alerts ({len(linked_triages)})")
    if not linked_triages:
        parts.append("_No linked alerts._")
    else:
        for t in linked_triages[:10]:
            # host / user are NOT first-class columns on AlertTriage — they
            # live on the raw ES alert. We surface them via getattr so the
            # prompt remains robust when the columns are absent.
            host = getattr(t, "host", None) or "—"
            user_name = getattr(t, "user_name", None) or "—"
            parts.append(
                f"- `{t.es_alert_id}` — rule: **{t.rule_name or 'unknown'}**, "
                f"severity: {t.priority or 'unknown'}, "
                f"host: {host}, "
                f"user: {user_name}"
            )
        if len(linked_triages) > 10:
            parts.append(f"_…and {len(linked_triages) - 10} more._")
    parts.append("")

    parts.append("## Observables")
    obs = list(getattr(case, "observables", None) or [])
    if not obs:
        parts.append("_No observables on this case._")
    else:
        for o in obs[:20]:
            if isinstance(o, dict):
                parts.append(
                    f"- **{o.get('type', '?')}** = `{o.get('value', '')}` "
                    f"(source: {o.get('source', '?')})"
                )
        if len(obs) > 20:
            parts.append(f"_…and {len(obs) - 20} more._")
    parts.append("")

    parts.append("## Raw lead alert (from Elasticsearch)")
    if raw_alert is None:
        parts.append("_Elasticsearch unavailable or alert not found._")
    else:
        parts.append("```json")
        parts.append(json.dumps(raw_alert, indent=2, default=str))
        parts.append("```")
    parts.append("")

    parts.append(f"## Prior autonomous investigations ({len(investigations)})")
    if not investigations:
        parts.append("_No completed investigations on these alerts._")
    else:
        for inv in investigations[:5]:
            parts.append(
                f"- **Investigation #{inv['id']}** on `{inv['alert_id_ref']}` "
                f"— verdict: `{inv['verdict']}`, "
                f"severity: `{inv['severity']}`, "
                f"confidence: {inv['confidence_int']}"
            )
            if inv.get("summary"):
                parts.append(f"  > {inv['summary'][:400]}")
        if len(investigations) > 5:
            parts.append(f"_…and {len(investigations) - 5} older investigations._")
    parts.append("")

    parts.append(f"## Similar closed cases ({len(similar_cases)})")
    if not similar_cases:
        parts.append("_No similar prior cases found (or pgvector unavailable)._")
    else:
        for sc in similar_cases:
            parts.append(
                f"- `{sc['case_number']}` ({sc['similarity']}) — "
                f"closed: `{sc['closure_reason']}` — {sc['title']}"
            )
    parts.append("")

    parts.append(
        "Produce the verdict + evidence + similar-cases + next-steps "
        "sections defined in the system prompt."
    )
    return "\n".join(parts)


# ── Endpoint ─────────────────────────────────────────────────────────────


@router.post(
    "/elasticsearch/alerts/cases/{case_id}/bob-analysis",
    response_model=BobAnalysisResponse,
)
async def generate_bob_analysis(
    case_id: int,
    user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
) -> BobAnalysisResponse:
    """Generate an on-demand Bob analysis for a case.

    Does NOT persist anything; the analyst saves it themselves via the
    existing notes endpoint if they want a record. See module docstring
    for the data sources gathered.
    """
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Gather linked triages.
    linked_triages: list[AlertTriage] = (
        session.query(AlertTriage)
        .filter(AlertTriage.case_id == case_id)
        .order_by(AlertTriage.id.asc())
        .all()
    )
    alert_ids = [t.es_alert_id for t in linked_triages if t.es_alert_id]

    investigations = _gather_investigations(session, alert_ids)
    similar = _gather_similar_cases(session, case_id)
    raw_alert = await _gather_raw_alert(alert_ids[0]) if alert_ids else None

    user_prompt = _build_user_prompt(
        case, linked_triages, investigations, similar, raw_alert
    )

    try:
        from ion.services.ollama_service import get_ollama_service
        ollama = get_ollama_service()
        if not getattr(ollama, "enabled", True):
            raise HTTPException(
                status_code=503,
                detail="Ollama is disabled — Bob analysis unavailable",
            )
        result = await ollama.chat(
            messages=[{"role": "user", "content": user_prompt}],
            system_prompt=_SYSTEM_PROMPT,
            context_type="case_analysis",
            user_id=user.id,
            temperature=0.4,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Bob analysis Ollama call failed for case %d", case_id)
        raise HTTPException(status_code=503, detail=f"LLM call failed: {exc}")

    analysis_text = (result or {}).get("content") or ""
    if not analysis_text.strip():
        raise HTTPException(
            status_code=503,
            detail="Bob returned an empty response — please retry.",
        )

    return BobAnalysisResponse(
        analysis=analysis_text.strip(),
        model=(result or {}).get("model"),
        sources={
            "investigations_count": len(investigations),
            "alerts_count": len(linked_triages),
            "observables_count": len(case.observables or []),
            "similar_cases_count": len(similar),
            "raw_alert_present": raw_alert is not None,
        },
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
