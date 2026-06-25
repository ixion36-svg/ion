"""On-demand Bob case analysis (v0.23.1).

Replaces the v0.22.x auto-comment behaviour. Bob no longer writes a Note
to a case on every investigation completion; instead, the analyst clicks
"Get Bob's Analysis" on the case detail page, which calls this endpoint.

The endpoint gathers five inputs the user asked for:

1. Investigations performed on this case (by alert_id_ref → es_alert_id).
2. The rule snapshot for each linked alert (rule_name + severity from
   AlertTriage; raw rule body via ES when available).
3. Observables on the case.
4. Well-known fields for EVERY linked alert (best-effort — ES may be
   unreachable in dev, the prompt tolerates an absent block). This is what
   makes a multi-alert case produce one case-wide analysis rather than a
   verdict keyed off the lead alert alone.
5. Similar closed cases via pgvector (cosine distance ≥ 0.5 by default).

Bob's response is returned to the UI verbatim; the endpoint does NOT
persist anything. If the analyst wants to keep the analysis, they click
"Save as note", which calls the existing
``POST /api/elasticsearch/alerts/cases/{case_id}/notes`` endpoint with
the analysis text as the body, authored by the analyst (not Bob).

Permission: ``case:read`` — generating an analysis is a read action.
"""

from __future__ import annotations

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


# Cap how many alerts' field summaries we inline so a noisy cluster can't
# blow the prompt budget; the rest are acknowledged as truncated.
_MAX_ALERTS_IN_PROMPT = 12


async def _gather_alert_field_summaries(alert_ids: list[str]) -> list[dict]:
    """Well-known-field summary for EVERY linked alert (best-effort via ES).

    Returns one dict per alert — ``{es_id, rule_name, fields}`` — where
    ``fields`` is the investigation service's compact well-known-field map
    (rule, host, user, process, network, file, plus the detection rule's
    description / investigation guide). This is what lets a multi-alert case
    get a genuine case-WIDE analysis instead of one keyed off the lead alert
    only: even when no per-alert autonomous investigation has run yet, Bob
    sees the salient fields from each alert in the cluster.
    """
    if not alert_ids:
        return []
    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        from ion.services.investigation_service import InvestigationService

        es = ElasticsearchService()
        if not es.is_configured:
            return []
        hits = await es.get_alerts_by_ids(alert_ids[:_MAX_ALERTS_IN_PROMPT])
        if not hits:
            return []
        inv = InvestigationService()
        out: list[dict] = []
        for h in hits:
            raw = dict(getattr(h, "raw_data", None) or {})
            raw.setdefault("_id", getattr(h, "id", None))
            try:
                summary = inv._build_alert_summary(raw)
            except Exception:  # noqa: BLE001 — one bad doc shouldn't sink the set
                summary = {}
            out.append({
                "es_id": getattr(h, "id", None),
                "rule_name": getattr(h, "rule_name", None),
                "fields": summary,
            })
        return out
    except Exception as exc:
        logger.debug("Per-alert field summary gather failed: %s", exc)
        return []


# ── Prompt builder ───────────────────────────────────────────────────────


_SYSTEM_PROMPT = (
    "You are Bob, ION's autonomous SOC analyst, producing an on-demand "
    "case analysis for a human L1/L2 analyst who has explicitly clicked "
    "\"Get Bob's Analysis\". The analyst wants a tight, evidence-grounded "
    "verdict they can paste into the case as a note if they agree. "
    "A case may bundle MANY alerts — reason over ALL of them together: "
    "treat the alerts as one incident, look for the relationship between "
    "them (shared host/user/process/timeline, a kill-chain across alerts), "
    "and give ONE overall verdict for the case rather than per-alert notes. "
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


def _render_alert_fields_section(alert_summaries: list[dict], total_alerts: int) -> list[str]:
    """Render the per-alert well-known-field block.

    The detection-rule prose (description + investigation guide) is pulled out
    and shown ONCE — alerts in a cluster usually share a rule, so repeating it
    per alert would waste the prompt budget — while each alert lists its own
    salient fields (host/user/process/network/file).
    """
    parts: list[str] = ["## Well-known fields across all alerts"]
    if not alert_summaries:
        parts.append("_Elasticsearch unavailable or alerts not found._")
        parts.append("")
        return parts

    rule_keys = ("rule_description", "rule_investigation_guide")
    rule_desc = next(
        (s["fields"].get("rule_description") for s in alert_summaries
         if s.get("fields", {}).get("rule_description")), None,
    )
    rule_guide = next(
        (s["fields"].get("rule_investigation_guide") for s in alert_summaries
         if s.get("fields", {}).get("rule_investigation_guide")), None,
    )
    if rule_desc or rule_guide:
        parts.append("### Detection rule context")
        if rule_desc:
            parts.append(f"- **What this rule detects:** {rule_desc}")
        if rule_guide:
            parts.append(f"- **Author's investigation guide:** {rule_guide}")
        parts.append("")

    for i, s in enumerate(alert_summaries, 1):
        fields = s.get("fields", {}) or {}
        parts.append(f"### Alert {i} — `{s.get('es_id')}` ({s.get('rule_name') or 'unknown rule'})")
        rendered = False
        for k, v in fields.items():
            if k in rule_keys or v in (None, "", [], {}):
                continue
            parts.append(f"- {k}: {v}")
            rendered = True
        if not rendered:
            parts.append("_No salient fields parsed._")
        parts.append("")

    if total_alerts > len(alert_summaries):
        parts.append(
            f"_…and {total_alerts - len(alert_summaries)} more alert(s) on "
            "this case not inlined above._"
        )
        parts.append("")
    return parts


def _build_user_prompt(
    case: AlertCase,
    linked_triages: list[AlertTriage],
    investigations: list[dict],
    similar_cases: list[dict],
    alert_summaries: list[dict],
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

    parts.extend(_render_alert_fields_section(alert_summaries, len(linked_triages)))

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
    alert_summaries = await _gather_alert_field_summaries(alert_ids)

    user_prompt = _build_user_prompt(
        case, linked_triages, investigations, similar, alert_summaries
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
            "alert_fields_present": len(alert_summaries),
        },
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
