"""CyAB assessment scoring service (v0.10.15).

Maps questionnaire responses → ranked list of TIDE playbooks (use cases) +
ranked list of relevant threat actors.

Scoring weights (out of 100):
- TA (threat-actor relevance)  0–40
- ST (stack applicability)     0–20
- CG (control gap penalty)     0–20
- CB (concern boost)           0–20

Each playbook in TIDE's catalogue gets a score = TA + ST + CG + CB. The
service returns the top-N sorted descending. Each result carries a
`reasons` array — short strings ("you marked ransomware as a top concern")
so the UI can show *why* a playbook was ranked where it was.

Threat-actor ranking is a separate output: sector × geo → curated
top-actors list, optionally augmented with OpenCTI lookup.

The service is **pure** — no DB writes. It reads:
- TIDE playbook catalogue (via `tide_service.get_playbooks_with_kill_chains`)
- Optionally OpenCTI actors (via `opencti_service.search_threat_actors`)

Caller persists `responses_json` + the returned `computed_profile`,
`ranked_use_cases`, `ranked_actors` onto a CyabAssessment row.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Keyword catalogues — match concern/stack values → playbook text ────────

# Searched against playbook name + description (lowercase, substring match).
_CONCERN_KEYWORDS: Dict[str, List[str]] = {
    "ransomware": ["ransom", "encrypt", "wipe", "data destruction", "shadowcopy"],
    "bec": ["business email", "bec", "vendor invoice", "wire fraud", "executive impersonation"],
    "data_theft": ["exfil", "data theft", "data staging", "collection", "data transfer"],
    "insider": ["insider", "data hoarding", "unusual access", "off-boarded"],
    "nation_state": ["apt", "nation-state", "espionage", "advanced persistent"],
    "supply_chain": ["supply chain", "vendor", "third party", "trusted relationship", "software update"],
    "ddos": ["denial of service", "ddos", "availability"],
    "phishing": ["phish", "spear", "credential harvest", "social engineering", "malicious link"],
    "hacktivism": ["hacktivist", "defacement", "doxx"],
}

# Sector → list of concern keywords typical for that sector. Used to bias
# TA when sector is the primary signal we have.
_SECTOR_DEFAULT_CONCERNS: Dict[str, List[str]] = {
    "finance": ["bec", "ransomware", "data_theft", "phishing"],
    "healthcare": ["ransomware", "data_theft", "insider"],
    "government": ["nation_state", "ransomware", "data_theft", "hacktivism"],
    "defence": ["nation_state", "supply_chain", "data_theft"],
    "energy": ["nation_state", "ransomware", "supply_chain"],
    "critical_infra": ["nation_state", "ransomware", "ddos"],
    "retail": ["ransomware", "data_theft", "bec"],
    "manufacturing": ["ransomware", "supply_chain", "nation_state"],
    "tech": ["supply_chain", "data_theft", "nation_state"],
    "education": ["ransomware", "phishing", "data_theft"],
    "legal": ["bec", "data_theft", "phishing"],
    "media": ["hacktivism", "ddos", "data_theft"],
    "non_profit": ["phishing", "bec"],
    "other": ["ransomware", "phishing"],
}

# Sector → curated threat-actor display names. These are deliberately broad
# (motivation-tagged) so the UI shows "you should care about ransomware-as-
# a-service operators" rather than naming a specific group that may have
# rebranded. The OpenCTI lookup later fills in concrete names.
_SECTOR_ACTOR_TAGS: Dict[str, List[Dict[str, str]]] = {
    "finance": [
        {"name": "Financially-motivated ransomware operators", "why": "Banks and finance are top-paying ransomware targets."},
        {"name": "FIN-tagged groups (FIN7/FIN8 lineage)", "why": "Track record of POS, wire-fraud, and ATM-targeting campaigns."},
        {"name": "BEC fraud rings", "why": "Direct revenue from invoice/payment redirection."},
    ],
    "healthcare": [
        {"name": "Ransomware-as-a-service affiliates", "why": "Healthcare is high-leverage (life-safety pressure → faster payment)."},
        {"name": "PHI-targeting credential-theft groups", "why": "PHI resells well on dark markets."},
    ],
    "government": [
        {"name": "Nation-state intrusion sets (APT)", "why": "Strategic intelligence collection."},
        {"name": "Ransomware operators (high-impact)", "why": "Recent shift to public-sector targeting."},
        {"name": "Hacktivist collectives", "why": "Ideologically-motivated defacement / leak ops."},
    ],
    "defence": [
        {"name": "Nation-state APT groups (cyber-espionage)", "why": "Defence-industrial-base (DIB) is a primary collection target."},
        {"name": "Supply-chain compromise actors", "why": "Trusted relationships are the cheapest entry into hardened defence networks."},
    ],
    "energy": [
        {"name": "Nation-state OT/ICS-capable groups", "why": "Strategic disruption potential — VOLTZITE-style precursors."},
        {"name": "Ransomware operators (Industroyer-adjacent)", "why": "Energy-sector targeting on the rise."},
    ],
    "critical_infra": [
        {"name": "Nation-state OT/ICS groups", "why": "Strategic-disruption pre-positioning."},
        {"name": "DDoS-as-a-service operators", "why": "Availability impact is the cheapest visible disruption."},
    ],
    "retail": [
        {"name": "Magecart-style web-skimming groups", "why": "Direct cardholder-data theft on e-commerce front-ends."},
        {"name": "Ransomware affiliates", "why": "Retail revenue dependence makes them high-leverage."},
        {"name": "BEC fraud rings", "why": "Vendor invoice and supplier payment redirection."},
    ],
    "manufacturing": [
        {"name": "Ransomware operators", "why": "Manufacturing downtime cost makes them likely to pay."},
        {"name": "Nation-state IP-theft groups", "why": "Industrial espionage targeting trade secrets / process knowledge."},
        {"name": "Supply-chain compromise actors", "why": "Vendor relationships into target manufacturers."},
    ],
    "tech": [
        {"name": "Supply-chain compromise actors", "why": "SaaS/dev tooling is the highest-multiplier entry point."},
        {"name": "Nation-state credential-theft groups", "why": "Cloud admin credentials → broad downstream access."},
    ],
    "education": [
        {"name": "Ransomware operators", "why": "Universities have budget pressure + rich PHI/PII."},
        {"name": "Phishing operators (credential theft)", "why": "Large user bases with weaker training cadence."},
    ],
    "legal": [
        {"name": "BEC fraud rings", "why": "Wire-instruction fraud via compromised partner mailboxes."},
        {"name": "Nation-state IP-theft groups", "why": "M&A and litigation strategy is high-value collection."},
    ],
    "media": [
        {"name": "Hacktivist collectives", "why": "Editorial output makes media a public-pressure target."},
        {"name": "DDoS-as-a-service operators", "why": "Availability disruption around publication events."},
    ],
    "non_profit": [
        {"name": "Phishing operators", "why": "Weaker security budgets, cash-gift fraud opportunities."},
        {"name": "BEC fraud rings", "why": "Donation-redirection attacks."},
    ],
    "other": [
        {"name": "Ransomware operators", "why": "Universal threat — every sector targeted in 2024-26."},
        {"name": "BEC fraud rings", "why": "Email-borne fraud is sector-agnostic."},
    ],
}


# Control → playbook keyword mapping. When the org's control is weak/missing
# we boost playbooks whose keywords match — those are the ones the missing
# control was supposed to mitigate.
_CONTROL_GAP_KEYWORDS: Dict[str, List[str]] = {
    "mfa_weak": ["credential", "brute force", "password spray", "token theft", "session hijack", "kerberos", "phish"],
    "edr_weak": ["malware", "execution", "process injection", "living-off-the-land", "lolbin", "powershell", "wmi"],
    "backup_weak": ["ransom", "encrypt", "wipe", "destruction", "shadow"],
    "awareness_weak": ["phish", "social engineering", "credential harvest", "malicious attachment"],
}


# Stack → required platform tag mapping. Used to score ST. Each stack value
# implies the org runs on these platforms; playbooks needing a different
# platform get reduced ST score.
_STACK_PLATFORMS: Dict[str, List[str]] = {
    "windows": ["windows"],
    "macos": ["macos"],
    "linux": ["linux"],
    "chromeos": ["chromeos"],
    "aws": ["aws", "cloud"],
    "azure": ["azure", "cloud"],
    "gcp": ["gcp", "cloud"],
    "onprem": ["onprem"],
    "ad_onprem": ["windows", "ad"],
    "entra": ["azure", "entra", "cloud"],
    "okta": ["okta", "identity"],
    "google": ["google", "cloud"],
    "m365": ["m365", "office", "azure", "cloud"],
    "exchange_onprem": ["exchange", "onprem"],
}


# ── Helpers ────────────────────────────────────────────────────────────────


def _kws_in(text: str, keywords: List[str]) -> int:
    """Count how many `keywords` appear in `text` (case-insensitive)."""
    if not text or not keywords:
        return 0
    lower = text.lower()
    return sum(1 for k in keywords if k in lower)


def _control_weak(answer: str, weak_values: List[str]) -> bool:
    """True when the user's answer indicates the control is weak/absent."""
    return (answer or "").strip() in weak_values


def _list_or(val: Any) -> List[Any]:
    """Coerce maybe-list value to list (for multi-select answers)."""
    if isinstance(val, list):
        return val
    if val is None or val == "":
        return []
    return [val]


# ── Public API ─────────────────────────────────────────────────────────────


def compute_profile(responses: Dict[str, Any]) -> Dict[str, Any]:
    """Distill raw responses into a denormalised profile dict for scoring.

    Pulls out the answers the scoring fns repeatedly need, rather than
    re-walking ``responses`` per playbook. Returns a dict with:
      sector, sector_concerns, geo, public_profile, regulated_data,
      stack_platforms, weak_controls (set of "mfa_weak"/"edr_weak"/...),
      concern_keywords (combined concern_top + sector_concerns),
      prior_incident_keywords, exposure_band, regulated_data_present.
    """
    sector = (responses.get("org_sector") or "other")
    sector_concerns = _SECTOR_DEFAULT_CONCERNS.get(sector, ["ransomware", "phishing"])

    concern_top = _list_or(responses.get("concern_top"))
    prior_incidents = _list_or(responses.get("prior_incident"))

    # Combine explicit + sector-implied concerns into a single keyword bag.
    concern_kw_bag: List[str] = []
    for c in concern_top:
        concern_kw_bag.extend(_CONCERN_KEYWORDS.get(c, [c]))
    for c in sector_concerns:
        concern_kw_bag.extend(_CONCERN_KEYWORDS.get(c, [c]))

    prior_kw_bag: List[str] = []
    for p in prior_incidents:
        # Map prior_incident values to concern keywords (most overlap)
        prior_kw_bag.extend(_CONCERN_KEYWORDS.get(p, [p]))

    # Stack → flat list of platform tags
    platforms: List[str] = []
    for q in ("stack_endpoint_os", "stack_cloud", "stack_identity", "stack_email"):
        for v in _list_or(responses.get(q)):
            platforms.extend(_STACK_PLATFORMS.get(v, []))
    platforms = list(set(platforms))

    weak: List[str] = []
    if _control_weak(responses.get("ctl_mfa", ""), ["partial", "no", "dont_know"]):
        weak.append("mfa_weak")
    if _control_weak(responses.get("ctl_edr", ""), ["some", "no", "dont_know"]):
        weak.append("edr_weak")
    if _control_weak(responses.get("ctl_backup", ""), ["gt_1y", "never", "dont_know"]):
        weak.append("backup_weak")
    if _control_weak(responses.get("ctl_awareness", ""), ["onboarding", "never", "dont_know"]):
        weak.append("awareness_weak")

    regulated_data = _list_or(responses.get("org_regulated_data"))
    regulated_present = any(v for v in regulated_data if v != "none")

    return {
        "sector": sector,
        "sector_concerns": sector_concerns,
        "geo": _list_or(responses.get("org_geo")),
        "public_profile": responses.get("org_public_profile") or "low",
        "regulated_data": regulated_data,
        "regulated_data_present": regulated_present,
        "stack_platforms": platforms,
        "weak_controls": weak,
        "concern_keywords": list(set(concern_kw_bag)),
        "concern_top": concern_top,
        "prior_incident_keywords": list(set(prior_kw_bag)),
        "exposure_band": responses.get("external_exposure") or "lt_5",
        "ot_present": (responses.get("stack_ot") or "no") in ("yes", "partial"),
    }


def _score_one_playbook(
    pb: Dict[str, Any],
    profile: Dict[str, Any],
    sys_overlay: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute a single playbook's score given the org profile (+ optional
    per-system overlay). Returns the playbook dict with score + reasons.

    The playbook's `name` and `description` are the searchable text. Tag
    fields aren't standard in TIDE so name/description is what we have.
    """
    name = pb.get("name") or ""
    desc = pb.get("description") or ""
    text = f"{name} {desc}"

    reasons: List[str] = []

    # ── TA: threat-actor relevance ─────────────────────────────────────────
    ta = 0
    # Sector-implied concerns drive the baseline TA score.
    sector_kws: List[str] = []
    for c in profile.get("sector_concerns") or []:
        sector_kws.extend(_CONCERN_KEYWORDS.get(c, [c]))
    sector_hits = _kws_in(text, list(set(sector_kws)))
    if sector_hits:
        ta += min(20, sector_hits * 7)
        reasons.append(
            f"Aligns with typical threats for sector '{profile.get('sector')}'"
        )

    # Prior incidents are the strongest TA signal.
    prior_hits = _kws_in(text, profile.get("prior_incident_keywords") or [])
    if prior_hits:
        ta += min(15, prior_hits * 6)
        reasons.append("Matches a threat type you've experienced in the last 24 months")

    # Public visibility multiplier.
    if profile.get("public_profile") == "high" and ta > 0:
        ta = min(40, int(ta * 1.2))
        reasons.append("High public visibility — boosted")
    ta = min(40, ta)

    # ── ST: stack applicability ────────────────────────────────────────────
    st = 0
    platforms = profile.get("stack_platforms") or []
    # Coarse heuristic: if the playbook mentions a platform we don't run,
    # cap ST at 5. If it mentions one we do run, score up.
    platform_keywords = {
        "windows": ["windows", "active directory", "kerberos", "powershell"],
        "macos": ["macos", "osx"],
        "linux": ["linux", "ssh"],
        "aws": ["aws", "iam", "ec2", "s3"],
        "azure": ["azure", "entra", "azure ad"],
        "gcp": ["gcp", "google cloud"],
        "m365": ["m365", "exchange online", "office 365"],
    }
    pb_platforms_mentioned = [
        p for p, kws in platform_keywords.items() if _kws_in(text, kws)
    ]
    if not pb_platforms_mentioned:
        # Platform-agnostic playbook — give it a flat moderate ST.
        st = 12
    else:
        overlap = [p for p in pb_platforms_mentioned if p in platforms]
        if overlap:
            st = min(20, 10 + len(overlap) * 4)
        else:
            st = 3
            reasons.append(
                "Targets platforms not in your stack — applicability is low"
            )
    if profile.get("ot_present") and ("ot" in text.lower() or "ics" in text.lower()):
        st = min(20, st + 5)
        reasons.append("OT/ICS environment present — relevant playbook")

    # ── CG: control gap penalty ────────────────────────────────────────────
    cg = 0
    weak = profile.get("weak_controls") or []
    for w in weak:
        kws = _CONTROL_GAP_KEYWORDS.get(w, [])
        hits = _kws_in(text, kws)
        if hits:
            cg += min(8, hits * 3)
            label = w.replace("_weak", "").upper()
            reasons.append(
                f"{label} control is weak — this playbook covers techniques "
                f"that exploit that gap"
            )
    cg = min(20, cg)

    # ── CB: concern boost ──────────────────────────────────────────────────
    cb = 0
    concern_kws = profile.get("concern_keywords") or []
    cb_hits = _kws_in(text, concern_kws)
    if cb_hits:
        cb = min(20, cb_hits * 6)
        # Find which specific concern matched
        for c in profile.get("concern_top") or []:
            if _kws_in(text, _CONCERN_KEYWORDS.get(c, [])):
                reasons.append(f"You marked '{c}' as a top concern")
                break

    # ── Per-system overlay ─────────────────────────────────────────────────
    # System-level signals layer additive boosts on top of the org score.
    if sys_overlay:
        if sys_overlay.get("internet_facing") in ("yes", "vpn_only"):
            if _kws_in(text, ["initial access", "exploit", "external", "remote"]):
                ta = min(40, ta + 6)
                reasons.append("This system is internet-facing")
        if sys_overlay.get("data_sensitivity") in ("regulated", "pii"):
            if _kws_in(text, ["exfil", "data theft", "collection"]):
                ta = min(40, ta + 5)
                reasons.append("This system holds sensitive data")
        if sys_overlay.get("byod") == "yes":
            if _kws_in(text, ["unmanaged", "byod", "personal device"]):
                cg = min(20, cg + 5)
                reasons.append("BYOD allowed on this system")
        if (sys_overlay.get("mfa") == "no") and _kws_in(
            text, _CONTROL_GAP_KEYWORDS["mfa_weak"]
        ):
            cg = min(20, cg + 4)
            reasons.append("This system has no MFA")
        if (sys_overlay.get("monitoring") in ("no", "partial")) and _kws_in(
            text, _CONTROL_GAP_KEYWORDS["edr_weak"]
        ):
            cg = min(20, cg + 4)
            reasons.append("This system has incomplete log monitoring")

    total = ta + st + cg + cb

    return {
        "id": pb.get("id"),
        "name": name,
        "description": desc,
        "score": total,
        "ta_score": ta,
        "st_score": st,
        "cg_score": cg,
        "cb_score": cb,
        "reasons": list(dict.fromkeys(reasons)),  # dedupe, preserve order
    }


def score_use_cases(
    responses: Dict[str, Any],
    playbooks: List[Dict[str, Any]],
    sys_responses: Optional[Dict[str, Any]] = None,
    top_n: int = 10,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Rank TIDE playbooks for the given questionnaire responses.

    ``responses`` is the org-wide answer dict.
    ``playbooks`` is the result of ``tide_service.get_playbooks_with_kill_chains``.
    ``sys_responses`` is optional per-system answer dict for overlay.
    Returns ``(top_n_playbooks, computed_profile)``.
    """
    profile = compute_profile(responses)

    sys_overlay: Optional[Dict[str, Any]] = None
    if sys_responses:
        sys_overlay = {
            "criticality": sys_responses.get("sys_criticality"),
            "data_sensitivity": sys_responses.get("sys_data_sensitivity"),
            "internet_facing": sys_responses.get("sys_internet_facing"),
            "user_access": sys_responses.get("sys_user_access"),
            "byod": sys_responses.get("sys_byod"),
            "mfa": sys_responses.get("sys_mfa"),
            "segmentation": sys_responses.get("sys_segmentation"),
            "monitoring": sys_responses.get("sys_monitoring"),
        }

    scored = [
        _score_one_playbook(pb, profile, sys_overlay)
        for pb in (playbooks or [])
    ]
    scored.sort(key=lambda r: r["score"], reverse=True)
    return scored[:top_n], profile


def rank_actors(
    profile: Dict[str, Any],
    top_n: int = 5,
) -> List[Dict[str, Any]]:
    """Return curated threat-actor categories relevant to the profile.

    For MVP, this is the sector-driven static list (`_SECTOR_ACTOR_TAGS`).
    A future version cross-references OpenCTI's threat-actor inventory and
    TIDE's actor groups (the "both sources" path from the design doc).
    """
    sector = profile.get("sector") or "other"
    base = list(_SECTOR_ACTOR_TAGS.get(sector, _SECTOR_ACTOR_TAGS["other"]))

    # If 'nation_state' isn't in the sector default but the user marked it
    # as a top concern, surface a nation-state row regardless.
    if (
        "nation_state" in (profile.get("concern_top") or [])
        and not any("Nation" in a["name"] for a in base)
    ):
        base.insert(0, {
            "name": "Nation-state APT groups",
            "why": "You marked nation-state actors as a top concern.",
        })

    return base[:top_n]


def rank_for_assessment(
    responses: Dict[str, Any],
    playbooks: List[Dict[str, Any]],
    sys_responses: Optional[Dict[str, Any]] = None,
    top_use_cases: int = 10,
    top_actors: int = 5,
) -> Dict[str, Any]:
    """One-shot helper used by the API endpoints.

    Returns the full dict suitable for persisting to a CyabAssessment row:
        { computed_profile, ranked_use_cases, ranked_actors }
    """
    use_cases, profile = score_use_cases(
        responses, playbooks, sys_responses=sys_responses, top_n=top_use_cases
    )
    actors = rank_actors(profile, top_n=top_actors)
    return {
        "computed_profile": profile,
        "ranked_use_cases": use_cases,
        "ranked_actors": actors,
    }


def parse_json_field(val: Optional[str]) -> Any:
    """Defensive JSON parse for the *_json columns. Returns None on bad input."""
    if not val:
        return None
    try:
        return json.loads(val)
    except (TypeError, ValueError):
        return None


# Marker matches cyab_api._STUDIO_NOTES_MARKER. Duplicated here so
# the service layer doesn't depend on the web layer.
_STUDIO_NOTES_MARKER = "STUDIO_AUTOSAVE"


def load_answers(session, system_id: int) -> Dict[str, Any]:
    """Return the merged intake answers blob for a system.

    Mirrors ``cyab_api.get_system_answers`` — merges the studio
    autosave row over the most-recent legacy wizard row so studio edits
    win on shared keys. Returns ``{}`` when no rows exist or both blobs
    are empty.
    """
    from sqlalchemy import select  # local import to keep top of file lean

    from ion.models.cyab import CyabSystemAssessment

    legacy = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == system_id)
        .where(CyabSystemAssessment.notes != _STUDIO_NOTES_MARKER)
        .order_by(CyabSystemAssessment.submitted_at.desc())
        .limit(1)
    ).first()
    studio = session.scalars(
        select(CyabSystemAssessment)
        .where(CyabSystemAssessment.system_id == system_id)
        .where(CyabSystemAssessment.notes == _STUDIO_NOTES_MARKER)
        .limit(1)
    ).first()
    merged: Dict[str, Any] = {}
    for src in (legacy, studio):
        if src and src.responses_json:
            try:
                merged.update(json.loads(src.responses_json) or {})
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
    return merged
