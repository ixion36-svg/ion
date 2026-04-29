"""CyAB assessment questionnaire schema (v0.10.15).

Single source of truth for the question definitions consumed by the wizard
UI and the scoring service. Bumping ``SCHEMA_VERSION`` is mandatory when
question keys / option values change so old responses can be replayed
correctly through the right scoring code path.

Two question sets:
- ``ORG_QUESTIONS``  — 17 org-wide questions (org_*, stack_*, ctl_*,
                       concern_top, prior_incident, external_exposure)
- ``SYSTEM_QUESTIONS`` — 8 per-system questions (sys_*)

Each question carries the keys the scoring service uses to weight matched
playbooks: ``feeds`` is a list of ``("ta"|"st"|"cg"|"cb", weight_int)``
tuples consumed by ``cyab_assessment_service.score_use_cases``.
"""
from __future__ import annotations

from typing import Any, Dict, List

SCHEMA_VERSION = 2  # v0.12.0 — added sub-profile-namespaced keys (sub_<pillar>_<sub>_*)


def _q(
    key: str,
    section: str,
    text: str,
    answer_type: str,
    options: List[Dict[str, str]] | None = None,
    feeds: List[tuple] | None = None,
    multi_max: int | None = None,
) -> Dict[str, Any]:
    """Build one question dict.

    ``answer_type``: "single" (radio/dropdown), "multi" (multi-select),
    "yesno" (yes / partial / no, no "don't know" by default).
    """
    return {
        "key": key,
        "section": section,
        "text": text,
        "answer_type": answer_type,
        "options": options or [],
        "feeds": feeds or [],
        "multi_max": multi_max,
    }


# ── Common option sets (referenced from multiple questions) ────────────────

_DONT_KNOW = {"value": "dont_know", "label": "Don't know"}


# ── Org-wide questions (17) ────────────────────────────────────────────────

ORG_QUESTIONS: List[Dict[str, Any]] = [
    # Section 1 — Organisation profile (5)
    _q(
        "org_sector", "Organisation profile",
        "Which industry best describes your organisation?",
        "single",
        options=[
            {"value": "finance", "label": "Finance / Banking"},
            {"value": "healthcare", "label": "Healthcare"},
            {"value": "government", "label": "Government / Public sector"},
            {"value": "defence", "label": "Defence / Military"},
            {"value": "energy", "label": "Energy / Utilities"},
            {"value": "critical_infra", "label": "Critical infrastructure (water/transport)"},
            {"value": "retail", "label": "Retail / E-commerce"},
            {"value": "manufacturing", "label": "Manufacturing"},
            {"value": "tech", "label": "Technology / SaaS"},
            {"value": "education", "label": "Education"},
            {"value": "legal", "label": "Legal / Professional services"},
            {"value": "media", "label": "Media / Entertainment"},
            {"value": "non_profit", "label": "Non-profit"},
            {"value": "other", "label": "Other"},
        ],
        feeds=[("ta", 15)],
    ),
    _q(
        "org_size", "Organisation profile",
        "Roughly how many staff (including contractors)?",
        "single",
        options=[
            {"value": "lt_50", "label": "Under 50"},
            {"value": "50_250", "label": "50–250"},
            {"value": "250_1k", "label": "250–1,000"},
            {"value": "1k_5k", "label": "1,000–5,000"},
            {"value": "5k_25k", "label": "5,000–25,000"},
            {"value": "25k_plus", "label": "25,000+"},
        ],
        feeds=[("ta", 5)],
    ),
    _q(
        "org_geo", "Organisation profile",
        "Where do you primarily operate?",
        "multi",
        options=[
            {"value": "uk", "label": "UK"},
            {"value": "eu", "label": "EU"},
            {"value": "us", "label": "US"},
            {"value": "apac", "label": "APAC"},
            {"value": "me", "label": "Middle East"},
            {"value": "africa", "label": "Africa"},
            {"value": "latam", "label": "Latin America"},
            {"value": "global", "label": "Global"},
        ],
        feeds=[("ta", 5)],
    ),
    _q(
        "org_regulated_data", "Organisation profile",
        "Do you handle any of these types of regulated data?",
        "multi",
        options=[
            {"value": "pci", "label": "Cardholder data (PCI)"},
            {"value": "phi", "label": "Health records (HIPAA / UK GDPR)"},
            {"value": "pii", "label": "Personal data (GDPR)"},
            {"value": "gov_classified", "label": "Government classified"},
            {"value": "financial_market", "label": "Financial market data"},
            {"value": "defence_cui", "label": "Defence / CUI"},
            {"value": "none", "label": "None of these"},
        ],
        feeds=[("ta", 8), ("cb", 5)],
    ),
    _q(
        "org_public_profile", "Organisation profile",
        "How publicly visible is your organisation as a target?",
        "single",
        options=[
            {"value": "low", "label": "Low (B2B niche, no media coverage)"},
            {"value": "medium", "label": "Medium (well-known in sector)"},
            {"value": "high", "label": "High (national news, household name)"},
        ],
        feeds=[("ta", 7)],
    ),

    # Section 2 — Tech stack (5)
    _q(
        "stack_endpoint_os", "Tech stack",
        "What operating systems do your staff use day-to-day?",
        "multi",
        options=[
            {"value": "windows", "label": "Windows 10 / 11"},
            {"value": "macos", "label": "macOS"},
            {"value": "linux", "label": "Linux desktop"},
            {"value": "chromeos", "label": "ChromeOS"},
            {"value": "mobile_only", "label": "Mobile only"},
        ],
        feeds=[("st", 5)],
    ),
    _q(
        "stack_cloud", "Tech stack",
        "Which cloud platforms do you run workloads on?",
        "multi",
        options=[
            {"value": "aws", "label": "AWS"},
            {"value": "azure", "label": "Azure"},
            {"value": "gcp", "label": "GCP"},
            {"value": "onprem", "label": "On-prem only"},
            {"value": "other", "label": "Other"},
        ],
        feeds=[("st", 5)],
    ),
    _q(
        "stack_identity", "Tech stack",
        "How do staff sign in to applications?",
        "single",
        options=[
            {"value": "ad_onprem", "label": "Active Directory (on-prem)"},
            {"value": "entra", "label": "Entra ID / Azure AD"},
            {"value": "okta", "label": "Okta"},
            {"value": "google", "label": "Google Workspace"},
            {"value": "mix", "label": "Mix of several"},
            _DONT_KNOW,
        ],
        feeds=[("st", 4)],
    ),
    _q(
        "stack_email", "Tech stack",
        "Which email platform?",
        "single",
        options=[
            {"value": "m365", "label": "Microsoft 365 (Exchange Online)"},
            {"value": "google", "label": "Google Workspace"},
            {"value": "exchange_onprem", "label": "On-prem Exchange"},
            {"value": "other", "label": "Other"},
            _DONT_KNOW,
        ],
        feeds=[("st", 3)],
    ),
    _q(
        "stack_ot", "Tech stack",
        "Do you operate Operational Technology (OT), industrial control, or IoT environments?",
        "single",
        options=[
            {"value": "yes", "label": "Yes"},
            {"value": "partial", "label": "Partial"},
            {"value": "no", "label": "No"},
        ],
        feeds=[("st", 3), ("ta", 5)],
    ),

    # Section 3 — Existing controls (4)
    _q(
        "ctl_mfa", "Existing controls",
        "Is multi-factor authentication required for all staff to log in?",
        "single",
        options=[
            {"value": "all", "label": "Yes — everyone"},
            {"value": "most", "label": "Mostly (>80%)"},
            {"value": "partial", "label": "Partial (some apps/roles)"},
            {"value": "no", "label": "No"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 8)],
    ),
    _q(
        "ctl_edr", "Existing controls",
        "Do all staff laptops/desktops run an endpoint detection (EDR) tool?",
        "single",
        options=[
            {"value": "full", "label": "Yes — full coverage"},
            {"value": "most", "label": "Mostly (>80%)"},
            {"value": "some", "label": "Some"},
            {"value": "no", "label": "No / AV only"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 6)],
    ),
    _q(
        "ctl_backup", "Existing controls",
        "When did you last successfully test restoring from backup?",
        "single",
        options=[
            {"value": "lt_3m", "label": "Within 3 months"},
            {"value": "lt_1y", "label": "Within 1 year"},
            {"value": "gt_1y", "label": "Over 1 year ago"},
            {"value": "never", "label": "Never tested"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 3)],
    ),
    _q(
        "ctl_awareness", "Existing controls",
        "How often do staff receive security awareness training?",
        "single",
        options=[
            {"value": "quarterly", "label": "Quarterly or more"},
            {"value": "annual", "label": "Annually"},
            {"value": "onboarding", "label": "Onboarding only"},
            {"value": "never", "label": "Never"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 3)],
    ),

    # Section 4 — Concerns & exposures (3)
    _q(
        "concern_top", "Concerns & exposures",
        "Which threats worry you the most? (pick up to 3)",
        "multi",
        options=[
            {"value": "ransomware", "label": "Ransomware"},
            {"value": "bec", "label": "Business Email Compromise (BEC)"},
            {"value": "data_theft", "label": "Data theft / leaks"},
            {"value": "insider", "label": "Insider threat"},
            {"value": "nation_state", "label": "Nation-state actors"},
            {"value": "supply_chain", "label": "Supply chain attacks"},
            {"value": "ddos", "label": "DDoS / availability"},
            {"value": "phishing", "label": "Phishing of staff"},
            {"value": "hacktivism", "label": "Hacktivism"},
            _DONT_KNOW,
        ],
        feeds=[("cb", 20)],
        multi_max=3,
    ),
    _q(
        "prior_incident", "Concerns & exposures",
        "In the last 24 months, have you suffered any of these?",
        "multi",
        options=[
            {"value": "none", "label": "None"},
            {"value": "phishing_creds", "label": "Phishing → credential theft"},
            {"value": "ransomware", "label": "Ransomware / extortion"},
            {"value": "bec", "label": "BEC fraud"},
            {"value": "public_breach", "label": "Public data breach"},
            {"value": "insider_theft", "label": "Insider data theft"},
            {"value": "ddos", "label": "DDoS"},
            {"value": "supply_chain", "label": "Supply chain compromise"},
            _DONT_KNOW,
        ],
        feeds=[("ta", 5), ("cb", 8)],
    ),
    _q(
        "external_exposure", "Concerns & exposures",
        "Roughly how many internet-facing services do you run?",
        "single",
        options=[
            {"value": "lt_5", "label": "Under 5"},
            {"value": "5_25", "label": "5–25"},
            {"value": "25_100", "label": "25–100"},
            {"value": "100_plus", "label": "100+"},
            _DONT_KNOW,
        ],
        feeds=[("ta", 5)],
    ),
]


# ── Per-system questions (8) ───────────────────────────────────────────────

SYSTEM_QUESTIONS: List[Dict[str, Any]] = [
    # System purpose (2)
    _q(
        "sys_criticality", "System purpose",
        "How critical is this system to operations?",
        "single",
        options=[
            {"value": "tier1", "label": "Tier 1 — revenue-impacting if down"},
            {"value": "tier2", "label": "Tier 2 — significant disruption"},
            {"value": "tier3", "label": "Tier 3 — recoverable disruption"},
            {"value": "tier4", "label": "Tier 4 — low impact"},
        ],
        feeds=[("cg", 6), ("cb", 4)],
    ),
    _q(
        "sys_data_sensitivity", "System purpose",
        "What's the most sensitive data this system processes?",
        "single",
        options=[
            {"value": "regulated", "label": "Regulated (PCI / PHI / classified)"},
            {"value": "pii", "label": "Personal / PII"},
            {"value": "internal", "label": "Internal confidential"},
            {"value": "public", "label": "Public / non-sensitive"},
            _DONT_KNOW,
        ],
        feeds=[("ta", 6), ("cg", 4)],
    ),

    # Exposure (3)
    _q(
        "sys_internet_facing", "Exposure",
        "Is this system reachable from the public internet?",
        "single",
        options=[
            {"value": "yes", "label": "Yes"},
            {"value": "vpn_only", "label": "Partial (VPN only)"},
            {"value": "no", "label": "No"},
        ],
        feeds=[("ta", 8), ("cb", 5)],
    ),
    _q(
        "sys_user_access", "Exposure",
        "Who can access this system?",
        "single",
        options=[
            {"value": "whole_org", "label": "Whole organisation"},
            {"value": "team", "label": "A specific team / department"},
            {"value": "admins_only", "label": "Privileged admins only"},
            {"value": "third_parties", "label": "Includes third parties / contractors"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 4)],
    ),
    _q(
        "sys_byod", "Exposure",
        "Can staff access this system from personal devices (BYOD)?",
        "single",
        options=[
            {"value": "yes", "label": "Yes"},
            {"value": "partial", "label": "Partial"},
            {"value": "no", "label": "No"},
        ],
        feeds=[("ta", 4), ("cg", 4)],
    ),

    # System-specific controls (3)
    _q(
        "sys_mfa", "System-specific controls",
        "Does this system require MFA at login?",
        "single",
        options=[
            {"value": "yes", "label": "Yes"},
            {"value": "partial", "label": "Partial"},
            {"value": "no", "label": "No"},
            {"value": "na", "label": "N/A — not user-facing"},
        ],
        feeds=[("cg", 6)],
    ),
    _q(
        "sys_segmentation", "System-specific controls",
        "Is this system network-isolated from the rest of the corporate environment?",
        "single",
        options=[
            {"value": "full", "label": "Fully segmented"},
            {"value": "partial", "label": "Partial / per-VLAN"},
            {"value": "flat", "label": "Flat network"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 4)],
    ),
    _q(
        "sys_monitoring", "System-specific controls",
        "Are this system's logs going into your SIEM / log platform?",
        "single",
        options=[
            {"value": "full", "label": "Yes — full coverage"},
            {"value": "partial", "label": "Partial"},
            {"value": "no", "label": "No"},
            _DONT_KNOW,
        ],
        feeds=[("cg", 5)],
    ),
]


def get_org_questions() -> List[Dict[str, Any]]:
    """Return the org-wide question list (defensive copy).

    Mutating the returned list does not affect the canonical schema.
    """
    return [dict(q) for q in ORG_QUESTIONS]


def get_system_questions() -> List[Dict[str, Any]]:
    """Return the per-system question list (defensive copy)."""
    return [dict(q) for q in SYSTEM_QUESTIONS]
