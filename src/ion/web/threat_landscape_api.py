"""Threat Landscape API — high-level threat overview from OpenCTI."""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.services.opencti_service import get_opencti_service, OpenCTIError
from ion.services.ollama_service import get_ollama_service, OllamaError
from ion.core.safe_errors import safe_error

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threat-landscape", tags=["threat-landscape"])


@router.get("/overview")
async def get_overview(
    user: User = Depends(require_permission("observable:read")),
):
    """Return high-level threat landscape: top actors, tactic heatmap, malware trends."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_threat_landscape_overview()
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.get("/actor/{actor_id}")
async def get_actor_deep_dive(
    actor_id: str,
    user: User = Depends(require_permission("observable:read")),
):
    """Return detailed deep-dive data for a single threat actor / intrusion set."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_actor_deep_dive(actor_id)
        return result
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.get("/malware")
async def get_top_malware(
    limit: int = Query(15, ge=1, le=100),
    user: User = Depends(require_permission("observable:read")),
):
    """Return the most recently modified malware from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        result = await service.get_top_malware(limit=limit)
        return {"malware": result}
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.get("/reports")
async def get_recent_reports(
    limit: int = Query(15, ge=1, le=50),
    user: User = Depends(require_permission("observable:read")),
):
    """Return the most recently published threat reports from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        data = await service._graphql("""
            query RecentReports($first: Int) {
                reports(first: $first, orderBy: published, orderMode: desc) {
                    edges {
                        node {
                            id
                            name
                            published
                            report_types
                            description
                            confidence
                            objectLabel { value color }
                            createdBy { name }
                        }
                    }
                }
            }
        """, {"first": limit})
        reports = []
        for edge in data.get("reports", {}).get("edges", []):
            n = edge["node"]
            reports.append({
                "id": n.get("id"),
                "name": n.get("name"),
                "published": n.get("published"),
                "types": n.get("report_types") or [],
                "description": (n.get("description") or "")[:300],
                "confidence": n.get("confidence"),
                "source": (n.get("createdBy") or {}).get("name"),
                "labels": [
                    {"value": l.get("value"), "color": l.get("color")}
                    for l in (n.get("objectLabel") or [])
                ],
            })
        return {"reports": reports}
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.get("/reports/{report_id}")
async def get_report_detail(
    report_id: str,
    user: User = Depends(require_permission("observable:read")),
):
    """Return full report content + related objects from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        data = await service._graphql("""
            query ReportDetail($id: String!) {
                report(id: $id) {
                    id name published report_types description content
                    confidence
                    objectLabel { value color }
                    createdBy { name }
                    objects(first: 100) {
                        edges {
                            node {
                                ... on AttackPattern { entity_type name x_mitre_id }
                                ... on Malware { entity_type name malware_types }
                                ... on IntrusionSet { entity_type name aliases }
                                ... on Indicator { entity_type pattern indicator_types valid_from }
                                ... on Vulnerability { entity_type name }
                                ... on Country { entity_type name }
                                ... on Sector { entity_type name }
                                ... on StixCoreObject { entity_type }
                            }
                        }
                    }
                }
            }
        """, {"id": report_id})
        r = data.get("report")
        if not r:
            raise HTTPException(status_code=404, detail="Report not found")

        body = r.get("content") or r.get("description") or ""

        # Extract related objects by type
        actors, malware, ttps, indicators, vulns, countries, sectors = [], [], [], [], [], [], []
        for edge in (r.get("objects") or {}).get("edges", []):
            obj = edge.get("node") or {}
            et = obj.get("entity_type", "")
            if et == "Intrusion-Set":
                actors.append({"name": obj.get("name"), "aliases": (obj.get("aliases") or [])[:3]})
            elif et == "Malware":
                malware.append({"name": obj.get("name"), "types": obj.get("malware_types") or []})
            elif et == "Attack-Pattern":
                ttps.append({"name": obj.get("name"), "mitre_id": obj.get("x_mitre_id")})
            elif et == "Indicator":
                indicators.append({"pattern": (obj.get("pattern") or "")[:120], "types": obj.get("indicator_types") or []})
            elif et == "Vulnerability":
                vulns.append({"name": obj.get("name")})
            elif et == "Country":
                countries.append(obj.get("name"))
            elif et == "Sector":
                sectors.append(obj.get("name"))

        return {
            "id": r.get("id"),
            "name": r.get("name"),
            "published": r.get("published"),
            "types": r.get("report_types") or [],
            "body": body,
            "confidence": r.get("confidence"),
            "source": (r.get("createdBy") or {}).get("name"),
            "labels": [
                {"value": l.get("value"), "color": l.get("color")}
                for l in (r.get("objectLabel") or [])
            ],
            "related_actors": actors,
            "related_malware": malware,
            "related_ttps": ttps,
            "related_indicators": indicators[:20],
            "related_vulns": vulns,
            "related_countries": countries,
            "related_sectors": sectors,
        }
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.get("/ioc-feed")
async def get_ioc_feed(
    limit: int = Query(30, ge=1, le=100),
    min_score: int = Query(0, ge=0, le=100),
    user: User = Depends(require_permission("observable:read")),
):
    """Live IOC feed — most recently created indicators from OpenCTI."""
    service = get_opencti_service()
    if not service.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI integration is not configured")
    try:
        # Build filter for minimum score if set
        variables = {"first": limit}
        score_filter = ""
        if min_score > 0:
            score_filter = f', filters: {{ mode: and, filters: [{{ key: "x_opencti_score", values: ["{min_score}"], operator: gte }}], filterGroups: [] }}'

        data = await service._graphql(f"""
            query RecentIndicators($first: Int) {{
                indicators(first: $first, orderBy: created, orderMode: desc{score_filter}) {{
                    edges {{
                        node {{
                            id
                            name
                            pattern
                            indicator_types
                            valid_from
                            x_opencti_score
                            created
                            objectLabel {{ value color }}
                            createdBy {{ name }}
                        }}
                    }}
                }}
            }}
        """, variables)

        indicators = []
        for edge in data.get("indicators", {}).get("edges", []):
            n = edge["node"]
            # Parse pattern to extract type + value
            pattern = n.get("pattern") or ""
            ioc_type = ""
            ioc_value = pattern
            if ":" in pattern and "=" in pattern:
                try:
                    parts = pattern.strip("[]").split(":", 1)
                    ioc_type = parts[0].strip()
                    ioc_value = parts[1].split("=", 1)[1].strip().strip("'\"")
                except (IndexError, ValueError):
                    pass

            indicators.append({
                "id": n.get("id"),
                "pattern": pattern,
                "ioc_type": ioc_type,
                "ioc_value": ioc_value,
                "types": n.get("indicator_types") or [],
                "score": n.get("x_opencti_score"),
                "created": n.get("created"),
                "valid_from": n.get("valid_from"),
                "source": (n.get("createdBy") or {}).get("name"),
                "labels": [
                    {"value": l.get("value"), "color": l.get("color")}
                    for l in (n.get("objectLabel") or [])
                ],
            })
        return {"indicators": indicators}
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))


@router.post("/ai-summary")
async def ai_threat_summary(
    user: User = Depends(require_permission("observable:read")),
):
    """AI-generated summary of the current threat landscape."""
    opencti = get_opencti_service()
    if not opencti.is_configured:
        raise HTTPException(status_code=503, detail="OpenCTI is not configured")

    ollama = get_ollama_service()
    if not await ollama.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    try:
        overview = await opencti.get_threat_landscape_overview()
    except OpenCTIError as e:
        raise HTTPException(status_code=502, detail=safe_error(e, "threat_landscape"))

    # Build a compact text summary (not JSON) to keep token count low
    actors = overview.get("actors") or []
    heatmap = overview.get("tactic_heatmap", {})
    malware = overview.get("malware_trends") or []

    lines = ["TOP ACTIVE THREAT ACTORS:"]
    for a in actors[:10]:
        name = a.get("name", "?")
        country = a.get("country_name") or "unknown"
        ttps = a.get("ttp_count", 0)
        mal = a.get("malware_count", 0)
        sectors = ", ".join((a.get("target_sectors") or [])[:3]) or "unknown"
        lines.append(f"- {name} ({country}): {ttps} TTPs, {mal} malware, targets: {sectors}")

    lines.append("\nTACTIC DISTRIBUTION:")
    for k, v in sorted(heatmap.items(), key=lambda x: -x[1])[:8]:
        lines.append(f"- {k}: {v} techniques")

    lines.append("\nTOP MALWARE:")
    for m in malware[:8]:
        lines.append(f"- {m.get('name', '?')} ({m.get('report_count', 0)} reports)")

    context = "\n".join(lines)

    prompt = (
        "You are a senior threat intelligence analyst at a Security Operations Centre. "
        "Write a daily threat intelligence briefing for the SOC manager and analysts.\n\n"
        "FORMAT RULES:\n"
        "- Write in plain prose paragraphs only. No markdown, no bullet points, no headers, no asterisks.\n"
        "- Use the style of a classified intelligence briefing: direct, factual, concise.\n"
        "- Refer to threat actors by their primary name (e.g. FANCY BEAR, WIZARD SPIDER).\n"
        "- Reference specific MITRE ATT&CK tactics by name (e.g. Defense Evasion, Initial Access).\n"
        "- Name specific malware families (e.g. AsyncRAT, TRICKBOT, Cobalt Strike).\n"
        "- End with 2-3 actionable priority recommendations for the SOC team.\n\n"
        "STRUCTURE (4 paragraphs):\n"
        "1. THREAT ACTOR ACTIVITY: Which groups are most active, their attributed nation-state or criminal affiliation, and which sectors they are targeting.\n"
        "2. TTP ANALYSIS: Which ATT&CK tactics dominate the landscape, what this reveals about adversary tradecraft, and any notable shifts.\n"
        "3. MALWARE & TOOLING: Which malware families and offensive tools are most prevalent, and any emerging threats.\n"
        "4. SOC PRIORITIES: Specific detection, hunting, and hardening actions the SOC should take based on this intelligence.\n\n"
        f"Current threat landscape data from our OpenCTI platform:\n{context}"
    )

    try:
        result = await ollama.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="analyst",
            temperature=0.4,
            user_id=user.id,
        )
        return {"summary": result["content"], "model": result["model"]}
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=safe_error(e))
