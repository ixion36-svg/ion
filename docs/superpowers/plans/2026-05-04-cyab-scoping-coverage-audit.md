# CyAB IA — Scoping + Coverage + Audit (Sub-plan C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the three remaining top-level CyAB pages — `/cyab/scoping` (anonymous stack-to-use-cases questionnaire with PDF export), `/cyab/coverage` (fleet data-health matrix), and `/cyab/audit` (chronological compliance feed). Introduce the **shared scoping engine** that powers both `/cyab/scoping` and the live counter on the wizard's Step 2 (built in Sub-plan B). Final release of the v0.19.0 series.

**Cross-plan dependency** (read first):

- **Sub-plan A** is required: provides `cyab_data_health_service` (the per-system aggregator that `/cyab/coverage` rolls up across the fleet) and the per-system page that the matrix cells link into.
- **Sub-plan B** is required: provides `/cyab/onboard` (the wizard target for the "Convert to system" CTA) and the wizard Step 2 partial that this plan rewires to call the new scoring engine.
- If A or B is incomplete when this plan starts, Tasks 4 and 9 will fail their integration tests; finish A and B first.

**Architecture:**

- New module `src/ion/services/cyab_scoping_engine.py` extends `cyab_assessment_service.py` (does **not** duplicate it — `score_use_cases`, `compute_profile`, `rank_actors` are imported and reused; the engine adds the question-set loader, the high-level counter computation, and the consumer-facing `score_answers()` / `summary_text()` API).
- Question set lives at `src/ion/data/cyab_scoping_questions.json` (per spec open question 3: code-versioned for v1; DB-editable can be added later without changing the engine API).
- New page route `/cyab/scoping` (anonymous — no auth required for the page; the convert CTA does require auth).
- New PDF helper `_render_scoping_pack_pdf()` lives next to the existing onboarding-pack helper but uses a separate Jinja template (`cyab/_scoping_pack_pdf.html`), per spec open question 4.
- New page route `/cyab/coverage` calls a new endpoint `/api/cyab/coverage/matrix` which iterates every `CyabSystem`, calls `cyab_data_health_service` per row, and returns the dimensional grid.
- New page route `/cyab/audit` calls a new endpoint `/api/cyab/audit/feed` that unions `CyabSnapshot` (sign-offs/checklist updates), `CyabDocChecklistItem.updated_at` deltas, system create/archive timestamps, and containment-authority changes from `change_log_service`.
- HTMX partials for live counter (`POST /api/cyab/scoping/score`) and matrix filtering (`GET /api/cyab/coverage/matrix?pillar=…&owner=…`).

**Tech Stack:** FastAPI · HTMX · Jinja2 · Tailwind · SQLAlchemy 2.x · pytest · WeasyPrint (already a dependency)

**Spec source:** `docs/superpowers/specs/2026-05-04-cyab-ia-design.md`

**Open-questions resolution** (carrying over from spec):

| Question | Resolution in this plan |
|---|---|
| 3. Scoping schema — JSON file or DB? | JSON file (`src/ion/data/cyab_scoping_questions.json`) — v1 simplicity. Engine API is DB-friendly so v2 can swap to a table without breaking consumers. |
| 4. Reuse onboarding-pack PDF template or new one? | New template (`_scoping_pack_pdf.html`) — audience differs (stakeholder pre-sales vs SOC sign-off). Shared CSS via `_pdf_styles.html` partial. |

---

## File Structure

**New files (backend):**

- `src/ion/services/cyab_scoping_engine.py` — question loader + `score_answers()` + `summary_text()`
- `src/ion/data/cyab_scoping_questions.json` — versioned question catalogue (~14 questions)

**New files (templates):**

- `src/ion/web/templates/cyab/scoping.html` — questionnaire page with live counter
- `src/ion/web/templates/cyab/_scoping_summary.html` — output partial (HTMX swap target)
- `src/ion/web/templates/cyab/_scoping_counter.html` — live counter partial (HTMX swap target)
- `src/ion/web/templates/cyab/_scoping_pack_pdf.html` — PDF body for scoping export
- `src/ion/web/templates/cyab/coverage.html` — fleet matrix page
- `src/ion/web/templates/cyab/_coverage_matrix.html` — matrix partial (HTMX swap target for filters)
- `src/ion/web/templates/cyab/audit.html` — audit feed page
- `src/ion/web/templates/cyab/_audit_feed.html` — feed partial (HTMX swap target for filters)

**New files (tests):**

- `tests/unit/test_cyab_scoping_engine.py`
- `tests/integration/test_cyab_scoping_page.py`
- `tests/integration/test_cyab_scoping_pdf.py`
- `tests/integration/test_cyab_scoping_convert.py`
- `tests/integration/test_cyab_wizard_step2_counter.py`
- `tests/integration/test_cyab_coverage_matrix.py`
- `tests/integration/test_cyab_audit_feed.py`

**Modified files:**

- `src/ion/web/server.py` — register `/cyab/scoping`, `/cyab/coverage`, `/cyab/audit` page routes
- `src/ion/web/cyab_api.py` — add `/api/cyab/scoping/score`, `/api/cyab/scoping/convert`, `/api/cyab/coverage/matrix`, `/api/cyab/audit/feed`
- `src/ion/web/cyab_studio_api.py` — add `_render_scoping_pack_pdf()` + `GET /api/cyab/scoping/pdf` endpoint (lives next to the existing onboarding-pack helpers so they share `_h()` and PDF fallback path)
- `src/ion/web/templates/cyab/onboard/_step2_intake.html` — wire HTMX trigger to the new `/api/cyab/scoping/score` (template was created in Sub-plan B; this plan only edits the live-counter region)
- `pyproject.toml`, `src/ion/__init__.py` — version bump to `v0.19.0` (Task 13)
- `CHANGELOG.md` — release note

**Test fixtures reuse note:** the `temp_db`, `client`, `admin_session` fixtures established in Sub-plan A's tests (e.g. `tests/integration/test_cyab_system_detail_page.py`) are reused verbatim. Inline only the fixtures that introduce new seeded data.

---

## Task 1: Scoping question catalogue (JSON data file)

**Files:**

- Create: `src/ion/data/cyab_scoping_questions.json`
- Test: `tests/unit/test_cyab_scoping_engine.py` (loader-only assertions in this task; full scoring lands in Task 2)

- [ ] **Step 1: Write failing unit tests for the loader**

```python
# tests/unit/test_cyab_scoping_engine.py
"""Unit tests for cyab_scoping_engine — question loader + scoring."""

import pytest


def test_load_questions_returns_nonempty_ordered_list():
    from ion.services import cyab_scoping_engine as svc
    qs = svc.load_questions()
    assert isinstance(qs, list)
    assert 12 <= len(qs) <= 20  # spec range
    # Order is stable (used by progressive disclosure)
    qs2 = svc.load_questions()
    assert [q["id"] for q in qs] == [q["id"] for q in qs2]


def test_each_question_has_required_keys():
    from ion.services import cyab_scoping_engine as svc
    for q in svc.load_questions():
        assert "id" in q and isinstance(q["id"], str)
        assert "text" in q and q["text"]
        assert "type" in q and q["type"] in ("choice", "multi", "text")
        if q["type"] in ("choice", "multi"):
            assert "options" in q and isinstance(q["options"], list)
            for opt in q["options"]:
                assert "value" in opt and "label" in opt


def test_question_set_covers_six_stack_dimensions():
    """Spec calls out: identity provider, endpoint platform, cloud,
    email/collab, network edge, compliance regime."""
    from ion.services import cyab_scoping_engine as svc
    ids = {q["id"] for q in svc.load_questions()}
    expected_dimensions = {
        "stack_identity",
        "stack_endpoint_os",
        "stack_cloud",
        "stack_email",
        "stack_network_edge",
        "compliance_regime",
    }
    missing = expected_dimensions - ids
    assert not missing, f"Question set missing dimensions: {missing}"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_scoping_engine.py -v
```

Expected: FAIL — module `cyab_scoping_engine` does not exist yet (ModuleNotFoundError).

- [ ] **Step 3: Create the question catalogue JSON file**

```json
{
  "version": 1,
  "updated_at": "2026-05-04",
  "notes": "Scoping questionnaire — drives use-case + threat-actor recommendations on /cyab/scoping and the wizard's Step 2 counter. Keys map onto cyab_assessment_service.compute_profile() inputs where possible (stack_*, ctl_*, org_sector, org_geo) so the existing scoring code can be reused without translation.",
  "questions": [
    {
      "id": "org_sector",
      "text": "Which sector best describes the organisation?",
      "type": "choice",
      "category": "context",
      "options": [
        {"value": "finance", "label": "Finance / Banking"},
        {"value": "healthcare", "label": "Healthcare"},
        {"value": "government", "label": "Government"},
        {"value": "defence", "label": "Defence"},
        {"value": "energy", "label": "Energy / Utilities"},
        {"value": "critical_infra", "label": "Critical infrastructure (other)"},
        {"value": "retail", "label": "Retail / e-commerce"},
        {"value": "manufacturing", "label": "Manufacturing"},
        {"value": "tech", "label": "Technology / SaaS"},
        {"value": "education", "label": "Education"},
        {"value": "legal", "label": "Legal"},
        {"value": "media", "label": "Media"},
        {"value": "non_profit", "label": "Non-profit"},
        {"value": "other", "label": "Other"}
      ]
    },
    {
      "id": "org_geo",
      "text": "Where is the org primarily based?",
      "type": "multi",
      "category": "context",
      "options": [
        {"value": "uk", "label": "United Kingdom"},
        {"value": "eu", "label": "European Union"},
        {"value": "us", "label": "United States"},
        {"value": "apac", "label": "Asia-Pacific"},
        {"value": "mena", "label": "Middle East / North Africa"},
        {"value": "global", "label": "Global"}
      ]
    },
    {
      "id": "stack_identity",
      "text": "What's your primary identity provider?",
      "type": "choice",
      "category": "stack",
      "options": [
        {"value": "entra", "label": "Microsoft Entra ID (Azure AD)"},
        {"value": "okta", "label": "Okta"},
        {"value": "google", "label": "Google Workspace"},
        {"value": "ad_onprem", "label": "Active Directory (on-prem)"},
        {"value": "ping", "label": "Ping Identity"},
        {"value": "other", "label": "Other / mixed"}
      ]
    },
    {
      "id": "stack_endpoint_os",
      "text": "Which endpoint operating systems do you run? (select all)",
      "type": "multi",
      "category": "stack",
      "options": [
        {"value": "windows", "label": "Windows"},
        {"value": "macos", "label": "macOS"},
        {"value": "linux", "label": "Linux"},
        {"value": "chromeos", "label": "ChromeOS"},
        {"value": "ios", "label": "iOS / iPadOS"},
        {"value": "android", "label": "Android"}
      ]
    },
    {
      "id": "stack_cloud",
      "text": "Which clouds host your workloads? (select all)",
      "type": "multi",
      "category": "stack",
      "options": [
        {"value": "aws", "label": "AWS"},
        {"value": "azure", "label": "Microsoft Azure"},
        {"value": "gcp", "label": "Google Cloud"},
        {"value": "onprem", "label": "On-prem only"},
        {"value": "oracle", "label": "Oracle Cloud"}
      ]
    },
    {
      "id": "stack_email",
      "text": "Which email / collaboration suite is in use?",
      "type": "choice",
      "category": "stack",
      "options": [
        {"value": "m365", "label": "Microsoft 365"},
        {"value": "google", "label": "Google Workspace"},
        {"value": "exchange_onprem", "label": "Exchange on-prem"},
        {"value": "other", "label": "Other"}
      ]
    },
    {
      "id": "stack_network_edge",
      "text": "Which network-edge controls are deployed? (select all)",
      "type": "multi",
      "category": "stack",
      "options": [
        {"value": "ngfw", "label": "Next-gen firewall"},
        {"value": "swg", "label": "Secure web gateway / proxy"},
        {"value": "ztna", "label": "ZTNA / SSE"},
        {"value": "vpn", "label": "Traditional VPN"},
        {"value": "waf", "label": "Web application firewall"},
        {"value": "none", "label": "None / unsure"}
      ]
    },
    {
      "id": "stack_edr",
      "text": "Do you run an EDR product on most endpoints?",
      "type": "choice",
      "category": "stack",
      "options": [
        {"value": "yes", "label": "Yes — full coverage"},
        {"value": "some", "label": "Partial coverage"},
        {"value": "no", "label": "No EDR"},
        {"value": "dont_know", "label": "Don't know"}
      ]
    },
    {
      "id": "ctl_mfa",
      "text": "How widely is MFA enforced?",
      "type": "choice",
      "category": "controls",
      "options": [
        {"value": "all", "label": "All users + privileged accounts"},
        {"value": "partial", "label": "Some users / inconsistent"},
        {"value": "no", "label": "Not enforced"},
        {"value": "dont_know", "label": "Don't know"}
      ]
    },
    {
      "id": "ctl_backup",
      "text": "When was your last verified backup-restore drill?",
      "type": "choice",
      "category": "controls",
      "options": [
        {"value": "lt_3m", "label": "Within the last 3 months"},
        {"value": "lt_1y", "label": "Within the last year"},
        {"value": "gt_1y", "label": "More than a year ago"},
        {"value": "never", "label": "Never"},
        {"value": "dont_know", "label": "Don't know"}
      ]
    },
    {
      "id": "ctl_awareness",
      "text": "How often is security-awareness training delivered?",
      "type": "choice",
      "category": "controls",
      "options": [
        {"value": "monthly", "label": "Monthly micro-content"},
        {"value": "quarterly", "label": "Quarterly"},
        {"value": "annual", "label": "Annual"},
        {"value": "onboarding", "label": "Only at onboarding"},
        {"value": "never", "label": "Never"}
      ]
    },
    {
      "id": "compliance_regime",
      "text": "Which compliance regimes apply? (select all)",
      "type": "multi",
      "category": "compliance",
      "options": [
        {"value": "pci_dss", "label": "PCI DSS"},
        {"value": "hipaa", "label": "HIPAA"},
        {"value": "gdpr", "label": "GDPR"},
        {"value": "iso27001", "label": "ISO 27001"},
        {"value": "soc2", "label": "SOC 2"},
        {"value": "nis2", "label": "NIS 2"},
        {"value": "dora", "label": "DORA"},
        {"value": "fedramp", "label": "FedRAMP"},
        {"value": "none", "label": "None"}
      ]
    },
    {
      "id": "concern_top",
      "text": "Top concerns for this conversation? (select up to 3)",
      "type": "multi",
      "category": "concerns",
      "options": [
        {"value": "ransomware", "label": "Ransomware"},
        {"value": "bec", "label": "Business email compromise"},
        {"value": "data_theft", "label": "Data theft / exfiltration"},
        {"value": "insider", "label": "Insider risk"},
        {"value": "nation_state", "label": "Nation-state APT"},
        {"value": "supply_chain", "label": "Supply chain"},
        {"value": "ddos", "label": "DDoS / availability"},
        {"value": "phishing", "label": "Phishing"}
      ]
    },
    {
      "id": "external_exposure",
      "text": "How many internet-facing services do you publish?",
      "type": "choice",
      "category": "context",
      "options": [
        {"value": "lt_5", "label": "Fewer than 5"},
        {"value": "5_50", "label": "5–50"},
        {"value": "gt_50", "label": "More than 50"},
        {"value": "dont_know", "label": "Don't know"}
      ]
    }
  ]
}
```

(14 questions — within the 12–20 range from the spec. The IDs reuse keys already understood by `cyab_assessment_service.compute_profile()` so the engine can pass them through without translation in Task 2.)

- [ ] **Step 4: Create a stub `cyab_scoping_engine.py` that just loads the JSON**

```python
# src/ion/services/cyab_scoping_engine.py
"""CyAB scoping engine — shared question set + scoring across consumers.

Three planned callers (per spec):
  1. /cyab/scoping       (anonymous stakeholder questionnaire)
  2. /cyab/onboard Step 2 (live counter as user answers wizard intake)
  3. /cyab/systems/{id} 'Recommendations' tab (Phase 2)

This module *extends* cyab_assessment_service — `score_answers()` calls
into `compute_profile`, `score_use_cases`, and `rank_actors` rather than
duplicating their logic. Adds:
  - load_questions()       — JSON catalogue loader (file-cached)
  - score_answers(answers) — high-level dict for UI consumption
  - summary_text(scores)   — single-line presentable summary
  - mitre_coverage_pct()   — MITRE Initial Access % from ranked use cases
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_QUESTIONS_PATH = Path(__file__).parent.parent / "data" / "cyab_scoping_questions.json"


@lru_cache(maxsize=1)
def load_questions() -> List[Dict[str, Any]]:
    """Read the question catalogue from disk. Cached for the process lifetime.

    To force a reload during development, call `load_questions.cache_clear()`.
    """
    with open(_QUESTIONS_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data["questions"]


def score_answers(answers: Dict[str, Any]) -> Dict[str, Any]:
    """Stub — full implementation in Task 2."""
    return {
        "use_case_count": 0,
        "threat_actor_matches": 0,
        "mitre_coverage_pct": 0,
        "recommended_use_cases": [],
        "recommended_threat_actors": [],
    }


def summary_text(scores: Dict[str, Any]) -> str:
    """Stub — full implementation in Task 2."""
    return ""
```

- [ ] **Step 5: Run tests to verify the loader-only assertions pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_scoping_engine.py -v -k "load_questions or required_keys or six_stack"
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/data/cyab_scoping_questions.json src/ion/services/cyab_scoping_engine.py tests/unit/test_cyab_scoping_engine.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): scoping question catalogue + engine loader stub"
```

---

## Task 2: Scoring engine — extend `cyab_assessment_service`

**Files:**

- Modify: `src/ion/services/cyab_scoping_engine.py` (replace the stub `score_answers` + `summary_text` with the real impl, plus add `mitre_coverage_pct`)
- Test: extend `tests/unit/test_cyab_scoping_engine.py`

- [ ] **Step 1: Add the failing scoring tests**

Append to `tests/unit/test_cyab_scoping_engine.py`:

```python
def test_score_answers_empty_returns_zeroed_shape():
    from ion.services import cyab_scoping_engine as svc
    out = svc.score_answers({})
    assert out["use_case_count"] == 0
    assert out["threat_actor_matches"] == 0
    assert out["mitre_coverage_pct"] == 0
    assert out["recommended_use_cases"] == []
    assert out["recommended_threat_actors"] == []


def test_score_answers_with_finance_sector_recommends_use_cases(monkeypatch):
    """Finance + ransomware concern → at least one ransomware use case ranked."""
    from ion.services import cyab_scoping_engine as svc

    fake_playbooks = [
        {"id": 1, "name": "Ransomware encryption detection",
         "description": "Detect mass file encryption via shadow copy deletion."},
        {"id": 2, "name": "Generic process injection",
         "description": "Detect process injection chains."},
        {"id": 3, "name": "BEC vendor invoice fraud",
         "description": "Detect business email compromise via vendor impersonation."},
    ]
    monkeypatch.setattr(
        "ion.services.tide_service.get_playbooks_with_kill_chains",
        lambda *_a, **_k: fake_playbooks,
    )

    out = svc.score_answers({
        "org_sector": "finance",
        "concern_top": ["ransomware"],
        "stack_endpoint_os": ["windows"],
        "stack_identity": "entra",
    })

    assert out["use_case_count"] >= 1
    assert out["threat_actor_matches"] >= 1
    assert isinstance(out["recommended_threat_actors"], list)
    assert isinstance(out["recommended_use_cases"], list)
    # MITRE % should be 0..100 inclusive
    assert 0 <= out["mitre_coverage_pct"] <= 100


def test_summary_text_is_human_readable():
    from ion.services import cyab_scoping_engine as svc
    text = svc.summary_text({
        "use_case_count": 47,
        "threat_actor_matches": 12,
        "mitre_coverage_pct": 64,
    })
    # Exactly the live-counter format the spec calls out
    assert "47" in text and "12" in text and "64" in text
    assert "use case" in text.lower()
    assert "%" in text


def test_mitre_coverage_pct_independent_of_playbook_count(monkeypatch):
    """MITRE % is computed from the *named techniques* in matched playbooks,
    not from raw ranked count — a single high-coverage playbook can raise it."""
    from ion.services import cyab_scoping_engine as svc

    one_pb_with_many_techniques = [{
        "id": 1, "name": "Initial access multi-vector",
        "description": "Phishing, exploit-public-facing, supply-chain, valid accounts.",
    }]
    monkeypatch.setattr(
        "ion.services.tide_service.get_playbooks_with_kill_chains",
        lambda *_a, **_k: one_pb_with_many_techniques,
    )
    out = svc.score_answers({"org_sector": "tech", "concern_top": ["phishing"]})
    assert out["mitre_coverage_pct"] > 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_scoping_engine.py -v
```

Expected: 3 of the new 4 tests FAIL (the empty-shape one passes by accident from the stub).

- [ ] **Step 3: Replace the engine stub with the real implementation**

```python
# src/ion/services/cyab_scoping_engine.py — replace score_answers + summary_text
# (keep load_questions exactly as in Task 1)

# ── MITRE Initial Access technique keywords ───────────────────────────────
# Used to compute mitre_coverage_pct from ranked playbook text. A playbook's
# name+description is searched for each technique keyword; the % is
# (techniques_hit / total_techniques * 100).
_MITRE_INITIAL_ACCESS = {
    "T1566": ["phishing", "spearphish", "phish"],
    "T1190": ["exploit public", "public-facing", "vulnerable web"],
    "T1133": ["external remote", "vpn", "rdp exposed"],
    "T1078": ["valid account", "credential", "stolen credential"],
    "T1199": ["trusted relationship", "third party"],
    "T1195": ["supply chain", "software update"],
    "T1091": ["replication", "removable media"],
    "T1200": ["hardware addition"],
    "T1189": ["drive-by", "drive by compromise", "watering hole"],
}


def mitre_coverage_pct(ranked_use_cases: List[Dict[str, Any]]) -> int:
    """Percentage of MITRE Initial Access techniques covered by the ranked
    playbooks. Pure: 0..100 integer.
    """
    if not ranked_use_cases:
        return 0
    text = " ".join(
        f"{uc.get('name', '')} {uc.get('description', '')}".lower()
        for uc in ranked_use_cases
    )
    hit = 0
    for technique_id, kws in _MITRE_INITIAL_ACCESS.items():
        if any(k in text for k in kws):
            hit += 1
    return int(round(100 * hit / len(_MITRE_INITIAL_ACCESS)))


def score_answers(answers: Dict[str, Any]) -> Dict[str, Any]:
    """High-level scoring for UI consumers.

    Wraps cyab_assessment_service.score_use_cases + rank_actors. Returns a
    dict shaped for the live counter widget and the summary view:

        {
          "use_case_count":           int,
          "threat_actor_matches":     int,
          "mitre_coverage_pct":       int (0..100),
          "recommended_use_cases":    [ {id, name, score, reasons}, ... top 25 ],
          "recommended_threat_actors":[ {name, why}, ... top 10 ],
          "computed_profile":         {sector, weak_controls, ...},
        }
    """
    if not answers:
        return {
            "use_case_count": 0,
            "threat_actor_matches": 0,
            "mitre_coverage_pct": 0,
            "recommended_use_cases": [],
            "recommended_threat_actors": [],
            "computed_profile": {},
        }

    # Lazy import to avoid pulling tide_service at module load (it touches ES).
    from ion.services import cyab_assessment_service as asmt
    from ion.services import tide_service

    try:
        playbooks = tide_service.get_playbooks_with_kill_chains() or []
    except Exception as exc:
        logger.warning("Failed to fetch TIDE playbooks for scoping: %s", exc)
        playbooks = []

    ranked, profile = asmt.score_use_cases(answers, playbooks, top_n=25)
    actors = asmt.rank_actors(profile, top_n=10)

    return {
        "use_case_count":            len(ranked),
        "threat_actor_matches":      len(actors),
        "mitre_coverage_pct":        mitre_coverage_pct(ranked),
        "recommended_use_cases":     ranked,
        "recommended_threat_actors": actors,
        "computed_profile":          profile,
    }


def summary_text(scores: Dict[str, Any]) -> str:
    """One-liner for the live counter widget on the side of the questionnaire.

    Format matches the spec literally: "47 use cases · 12 threat-actor
    matches · 64% MITRE Initial Access coverage".
    """
    uc = scores.get("use_case_count", 0)
    ta = scores.get("threat_actor_matches", 0)
    mt = scores.get("mitre_coverage_pct", 0)
    return f"{uc} use cases · {ta} threat-actor matches · {mt}% MITRE Initial Access coverage"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/unit/test_cyab_scoping_engine.py -v
```

Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/services/cyab_scoping_engine.py tests/unit/test_cyab_scoping_engine.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): scoping engine score_answers + summary_text + MITRE coverage"
```

---

## Task 3: `/cyab/scoping` page + questionnaire UI

**Files:**

- Create: `src/ion/web/templates/cyab/scoping.html`
- Modify: `src/ion/web/server.py` — register `/cyab/scoping` route
- Test: `tests/integration/test_cyab_scoping_page.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_scoping_page.py
"""Integration tests for the /cyab/scoping anonymous questionnaire page."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


def test_scoping_page_renders_anonymous(client):
    """Page is reachable without auth — designed for stakeholder demos."""
    r = client.get("/cyab/scoping")
    assert r.status_code == 200
    assert "Scoping" in r.text or "scoping" in r.text.lower()


def test_scoping_page_includes_all_questions(client):
    from ion.services import cyab_scoping_engine
    r = client.get("/cyab/scoping")
    body = r.text
    for q in cyab_scoping_engine.load_questions():
        assert q["id"] in body, f"question {q['id']} missing from page"


def test_scoping_page_includes_live_counter_widget(client):
    r = client.get("/cyab/scoping")
    body = r.text
    assert "scoping-counter" in body  # the HTMX swap target id
    # Initial counter shows zeros (no answers yet)
    assert "0 use cases" in body or "0/0" in body or "use case" in body.lower()


def test_scoping_page_progressive_disclosure_class(client):
    """Each question carries a class the client JS uses to reveal next-on-answer."""
    r = client.get("/cyab/scoping")
    body = r.text
    assert "scoping-question" in body
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_page.py -v
```

Expected: FAIL — route does not exist (404).

- [ ] **Step 3: Add the page route to `server.py`**

Add near the other `/cyab/*` routes:

```python
# src/ion/web/server.py
@app.get("/cyab/scoping", response_class=HTMLResponse)
async def cyab_scoping_page(request: Request):
    """Anonymous scoping questionnaire — no system created.

    Intentionally has no auth dependency: this is the stakeholder-facing
    surface for "given your stack, here's what coverage you'd get". The
    convert-to-system CTA does require auth (handled in /api/cyab/scoping/convert).
    """
    from ion.services import cyab_scoping_engine
    questions = cyab_scoping_engine.load_questions()
    initial = cyab_scoping_engine.score_answers({})
    return templates.TemplateResponse(
        request=request,
        name="cyab/scoping.html",
        context={"questions": questions, "initial_scores": initial},
    )
```

- [ ] **Step 4: Create the page template**

```html
<!-- src/ion/web/templates/cyab/scoping.html -->
{% extends "base.html" %}

{% block title %}Scoping — CyAB · ION{% endblock %}

{% block content %}
<div class="cyab-scoping">
  <header class="tw-mb-6">
    <nav class="breadcrumb tw-text-sm tw-text-slate-400 tw-mb-2">
      <a href="/cyab" class="hover:tw-text-white">CyAB</a>
      <span class="tw-mx-2">·</span>
      <span class="tw-text-white">Scoping</span>
    </nav>
    <h1 class="tw-text-[28px] tw-font-semibold tw-text-white">Stack-to-coverage scoping</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px] tw-mt-1">
      Answer a few questions about the technology stack to see how many
      detection rules, audit checks, and threat-actor profiles would apply.
      No system is created — for a real onboarding, use the wizard.
    </p>
  </header>

  <div class="tw-grid tw-grid-cols-3 tw-gap-6">

    {# Left 2/3 — the questionnaire form #}
    <form id="scoping-form"
          class="tw-col-span-2 tw-space-y-3"
          hx-post="/api/cyab/scoping/score"
          hx-target="#scoping-counter"
          hx-swap="innerHTML"
          hx-trigger="change">
      {% for q in questions %}
        <fieldset class="scoping-question tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3"
                  data-question-id="{{ q.id }}"
                  data-category="{{ q.category }}">
          <legend class="tw-text-slate-200 tw-text-[12.5px] tw-mb-2">{{ q.text }}</legend>
          {% if q.type == "choice" %}
            <select name="{{ q.id }}"
                    class="tw-w-full tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
              <option value="">— select —</option>
              {% for opt in q.options %}
                <option value="{{ opt.value }}">{{ opt.label }}</option>
              {% endfor %}
            </select>
          {% elif q.type == "multi" %}
            <div class="tw-grid tw-grid-cols-2 tw-gap-1">
              {% for opt in q.options %}
                <label class="tw-flex tw-items-center tw-gap-2 tw-text-[12px] tw-text-slate-300">
                  <input type="checkbox" name="{{ q.id }}" value="{{ opt.value }}">
                  {{ opt.label }}
                </label>
              {% endfor %}
            </div>
          {% else %}
            <input type="text" name="{{ q.id }}"
                   class="tw-w-full tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
          {% endif %}
        </fieldset>
      {% endfor %}

      <div class="tw-flex tw-items-center tw-gap-3 tw-mt-4">
        <button type="button"
                hx-post="/api/cyab/scoping/score?summary=1"
                hx-target="#scoping-summary"
                hx-include="#scoping-form"
                hx-swap="innerHTML"
                class="tw-px-3 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12px] tw-rounded">
          See summary
        </button>
        <a href="#" id="scoping-pdf-link"
           class="tw-text-cyan-400 tw-text-[12px] hover:tw-underline tw-hidden">Download PDF</a>
      </div>

      <div id="scoping-summary" class="tw-mt-4"></div>
    </form>

    {# Right 1/3 — sticky live counter #}
    <aside class="tw-col-span-1">
      <div id="scoping-counter"
           class="tw-sticky tw-top-4 tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-4">
        {% include "cyab/_scoping_counter.html" %}
      </div>
    </aside>

  </div>
</div>

{# Progressive disclosure: hide questions after the first un-answered one. #}
<script>
(function() {
  const form = document.getElementById('scoping-form');
  function reveal() {
    const fields = form.querySelectorAll('fieldset.scoping-question');
    let revealNext = true;
    fields.forEach(f => {
      f.style.display = revealNext ? '' : 'none';
      const filled = Array.from(f.querySelectorAll('select,input'))
        .some(el => (el.type === 'checkbox' ? el.checked : el.value));
      if (!filled) revealNext = false;
    });
  }
  reveal();
  form.addEventListener('change', reveal);
})();
</script>
{% endblock %}
```

And the initial counter partial:

```html
<!-- src/ion/web/templates/cyab/_scoping_counter.html -->
{% set scores = scores | default(initial_scores) %}
<div class="scoping-counter-body">
  <h3 class="tw-text-slate-300 tw-text-[11px] tw-uppercase tw-tracking-wider tw-mb-3">Live scope</h3>

  <div class="tw-mb-3">
    <div class="tw-text-cyan-300 tw-text-[24px] tw-font-semibold tw-leading-none">{{ scores.use_case_count }}</div>
    <div class="tw-text-slate-400 tw-text-[11px]">use cases</div>
  </div>

  <div class="tw-mb-3">
    <div class="tw-text-amber-300 tw-text-[24px] tw-font-semibold tw-leading-none">{{ scores.threat_actor_matches }}</div>
    <div class="tw-text-slate-400 tw-text-[11px]">threat-actor matches</div>
  </div>

  <div class="tw-mb-3">
    <div class="tw-text-emerald-300 tw-text-[24px] tw-font-semibold tw-leading-none">{{ scores.mitre_coverage_pct }}%</div>
    <div class="tw-text-slate-400 tw-text-[11px]">MITRE Initial Access coverage</div>
  </div>

  <p class="tw-text-slate-500 tw-text-[10.5px] tw-mt-3 tw-pt-3 tw-border-t tw-border-slate-800">
    Updates as you answer.
  </p>
</div>
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_page.py -v
```

Expected: 4 PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/scoping.html src/ion/web/templates/cyab/_scoping_counter.html src/ion/web/server.py tests/integration/test_cyab_scoping_page.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab/scoping page — anonymous questionnaire with live counter"
```

---

## Task 4: Live-counter API endpoint + summary partial

**Files:**

- Modify: `src/ion/web/cyab_api.py` — add `POST /api/cyab/scoping/score`
- Create: `src/ion/web/templates/cyab/_scoping_summary.html`
- Test: extend `tests/integration/test_cyab_scoping_page.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/integration/test_cyab_scoping_page.py`:

```python
def test_score_endpoint_returns_counter_partial(client):
    """POST /api/cyab/scoping/score returns the counter partial (HTMX swap)."""
    r = client.post(
        "/api/cyab/scoping/score",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200
    body = r.text
    # Counter partial markup
    assert "use cases" in body
    assert "threat-actor matches" in body
    assert "MITRE Initial Access coverage" in body


def test_score_endpoint_summary_mode_returns_summary_partial(client):
    """?summary=1 query param swaps to the full summary view, not the counter."""
    r = client.post(
        "/api/cyab/scoping/score?summary=1",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
    )
    assert r.status_code == 200
    body = r.text.lower()
    # Summary view headlines
    assert "recommended for your stack" in body
    assert "detection rules" in body or "use cases" in body


def test_score_endpoint_handles_multi_value(client):
    """`stack_endpoint_os` is a multi-select — multiple form values must
    coalesce into a list before scoring (so compute_profile sees a list)."""
    r = client.post(
        "/api/cyab/scoping/score",
        data=[("stack_endpoint_os", "windows"), ("stack_endpoint_os", "macos")],
    )
    assert r.status_code == 200
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_page.py -v -k score_endpoint
```

Expected: FAIL — endpoint does not exist (404).

- [ ] **Step 3: Add the endpoint to `cyab_api.py`**

```python
# src/ion/web/cyab_api.py — add near the bottom of the file
from fastapi import Form, Request
from fastapi.templating import Jinja2Templates

# (Re-use the templates instance from server.py if exposed; otherwise
# import here. The existing cyab_api.py already imports `templates` for
# other partials.)

@router.post("/scoping/score")
async def scoping_score(request: Request):
    """Compute scoping scores from form-encoded answers, return HTMX partial.

    `?summary=1` returns the full summary view; otherwise just the counter.
    Anonymous endpoint (matches the page).
    """
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = raw.getlist(key)
        if not vals:
            continue
        # Drop empty placeholder selections
        vals = [v for v in vals if v != ""]
        if not vals:
            continue
        # Single-select questions arrive as a one-item list; flatten unless
        # the engine schema declares this question as multi.
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    summary_mode = request.query_params.get("summary") == "1"

    template_name = (
        "cyab/_scoping_summary.html" if summary_mode
        else "cyab/_scoping_counter.html"
    )
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context={
            "scores": scores,
            "answers": answers,
            "summary_text": cyab_scoping_engine.summary_text(scores),
        },
    )
```

- [ ] **Step 4: Create the summary partial**

```html
<!-- src/ion/web/templates/cyab/_scoping_summary.html -->
<section class="scoping-summary tw-bg-slate-900/60 tw-border tw-border-cyan-900/40 tw-rounded tw-p-4">
  <h2 class="tw-text-cyan-300 tw-text-[14px] tw-font-semibold tw-mb-2">
    Recommended for your stack
  </h2>
  <p class="tw-text-slate-300 tw-text-[12.5px] tw-mb-3">{{ summary_text }}</p>

  <div class="tw-grid tw-grid-cols-3 tw-gap-3 tw-mb-4">
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-2">
      <div class="tw-text-cyan-300 tw-text-[20px] tw-font-semibold">{{ scores.use_case_count }}</div>
      <div class="tw-text-slate-500 tw-text-[10.5px]">detection &amp; audit use cases</div>
    </div>
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-2">
      <div class="tw-text-amber-300 tw-text-[20px] tw-font-semibold">{{ scores.threat_actor_matches }}</div>
      <div class="tw-text-slate-500 tw-text-[10.5px]">threat-actor profiles</div>
    </div>
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-2">
      <div class="tw-text-emerald-300 tw-text-[20px] tw-font-semibold">{{ scores.mitre_coverage_pct }}%</div>
      <div class="tw-text-slate-500 tw-text-[10.5px]">MITRE Initial Access coverage</div>
    </div>
  </div>

  {% if scores.recommended_use_cases %}
  <details class="tw-mb-3">
    <summary class="tw-text-cyan-400 tw-text-[12px] tw-cursor-pointer">
      Top {{ scores.recommended_use_cases | length }} ranked use cases
    </summary>
    <ul class="tw-mt-2 tw-space-y-1 tw-text-[11.5px]">
      {% for uc in scores.recommended_use_cases %}
        <li class="tw-flex tw-justify-between tw-text-slate-300">
          <span>{{ uc.name }}</span>
          <span class="tw-text-slate-500 tw-font-mono">{{ uc.score }}</span>
        </li>
      {% endfor %}
    </ul>
  </details>
  {% endif %}

  {% if scores.recommended_threat_actors %}
  <details class="tw-mb-3">
    <summary class="tw-text-amber-400 tw-text-[12px] tw-cursor-pointer">
      Top {{ scores.recommended_threat_actors | length }} threat-actor categories
    </summary>
    <ul class="tw-mt-2 tw-space-y-1 tw-text-[11.5px]">
      {% for a in scores.recommended_threat_actors %}
        <li class="tw-text-slate-300">
          <strong class="tw-text-amber-200">{{ a.name }}</strong>
          <span class="tw-text-slate-500"> — {{ a.why }}</span>
        </li>
      {% endfor %}
    </ul>
  </details>
  {% endif %}

  <div class="tw-flex tw-items-center tw-gap-3 tw-pt-3 tw-border-t tw-border-slate-800">
    <form hx-post="/api/cyab/scoping/pdf"
          hx-include="#scoping-form"
          hx-swap="none"
          hx-on::after-request="if (event.detail.successful) { window.location = event.detail.xhr.getResponseHeader('Location') || event.detail.xhr.responseURL; }"
          class="tw-inline">
      <button type="submit" class="tw-px-3 tw-py-1.5 tw-bg-slate-700 tw-text-white tw-text-[12px] tw-rounded">
        Download PDF
      </button>
    </form>
    <form hx-post="/api/cyab/scoping/convert"
          hx-include="#scoping-form"
          class="tw-inline">
      <button type="submit"
              class="tw-px-3 tw-py-1.5 tw-bg-cyan-700 tw-text-white tw-text-[12px] tw-rounded">
        Convert to system →
      </button>
    </form>
  </div>
</section>
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_page.py -v
```

Expected: all 7 PASS (4 from Task 3 + 3 from Task 4).

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_api.py src/ion/web/templates/cyab/_scoping_summary.html tests/integration/test_cyab_scoping_page.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /api/cyab/scoping/score endpoint + summary partial (HTMX-driven)"
```

---

## Task 5: Scoping PDF export

**Files:**

- Modify: `src/ion/web/cyab_studio_api.py` — add `_render_scoping_pack_pdf()` + `POST /scoping/pdf` endpoint (lives in studio_api so it shares `_h()` and the WeasyPrint fallback)
- Create: `src/ion/web/templates/cyab/_scoping_pack_pdf.html`
- Test: `tests/integration/test_cyab_scoping_pdf.py`

**Note (per spec open question 4):** This is a **separate** template from `_render_onboarding_pack_html`. The onboarding pack targets a SOC-engineer audience signing off a real system; the scoping pack targets pre-sales / stakeholder discussions where no system exists. Different layout, different content emphasis.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_scoping_pdf.py
"""Integration tests for the scoping PDF export."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


def test_scoping_pdf_returns_pdf_or_html(client):
    """Endpoint returns either application/pdf (WeasyPrint) or text/html (fallback)."""
    r = client.post(
        "/api/cyab/scoping/pdf",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200
    ct = r.headers["content-type"]
    assert ct.startswith("application/pdf") or ct.startswith("text/html")


def test_scoping_pdf_includes_summary_metrics(client):
    """The body (PDF or HTML fallback) mentions the headline counts."""
    r = client.post(
        "/api/cyab/scoping/pdf",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
    )
    if r.headers["content-type"].startswith("text/html"):
        body = r.text.lower()
        assert "use case" in body
        assert "mitre" in body or "coverage" in body
        assert "scoping pack" in body or "scoping summary" in body


def test_scoping_pdf_attachment_header_when_pdf(client):
    r = client.post("/api/cyab/scoping/pdf", data={"org_sector": "finance"})
    if r.headers["content-type"].startswith("application/pdf"):
        cd = r.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "scoping_pack" in cd
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_pdf.py -v
```

Expected: FAIL — endpoint does not exist (404).

- [ ] **Step 3: Create the PDF template**

```html
<!-- src/ion/web/templates/cyab/_scoping_pack_pdf.html -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    @page { size: A4; margin: 18mm 16mm; }
    body { font-family: 'Helvetica', 'Arial', sans-serif; font-size: 10pt; color: #222; line-height: 1.4; }
    h1 { color: #003a4e; font-size: 22pt; margin: 0 0 4pt 0; border: none; }
    h2 { color: #00586f; font-size: 14pt; margin-top: 16pt; border-bottom: 1pt solid #cfdfe5; padding-bottom: 2pt; }
    h3 { color: #115d72; font-size: 11pt; margin-top: 10pt; }
    .pdf-subtitle { color: #555; font-size: 9pt; margin-top: 0; margin-bottom: 12pt; }
    .pdf-meta { width: 100%; border-collapse: collapse; margin-bottom: 8pt; }
    .pdf-meta td { padding: 3pt 6pt; border-bottom: 0.5pt dotted #ccc; vertical-align: top; }
    .pdf-meta td:first-child { color: #666; width: 32%; }
    table.scoring { width: 100%; border-collapse: collapse; }
    table.scoring th, table.scoring td { padding: 4pt 6pt; border-bottom: 0.5pt solid #ddd; text-align: left; }
    table.scoring th { background: #f0f6f8; color: #003a4e; }
    .badge { display: inline-block; padding: 2pt 6pt; border-radius: 3pt; font-size: 9pt; }
    .badge-cyan { background: #d4eef5; color: #004a5d; }
    .badge-amber { background: #fbe5c2; color: #6a4307; }
    .badge-green { background: #d4ebd4; color: #1a4d1a; }
    ul { padding-left: 14pt; }
  </style>
</head>
<body>
  <h1>CyAB Scoping Pack</h1>
  <p class="pdf-subtitle">Stack-to-coverage analysis &bull; {{ generated_at }} &bull; ION</p>

  <h2>Headline scope</h2>
  <table class="pdf-meta">
    <tr><td>Detection &amp; audit use cases recommended</td>
        <td><span class="badge badge-cyan">{{ scores.use_case_count }}</span></td></tr>
    <tr><td>Threat-actor categories that map to your sector / concerns</td>
        <td><span class="badge badge-amber">{{ scores.threat_actor_matches }}</span></td></tr>
    <tr><td>MITRE ATT&amp;CK Initial Access coverage</td>
        <td><span class="badge badge-green">{{ scores.mitre_coverage_pct }}%</span></td></tr>
  </table>

  <h2>Inputs you provided</h2>
  {% if not answers %}
    <p><em>No answers captured.</em></p>
  {% else %}
    <table class="pdf-meta">
      {% for k, v in answers.items() %}
        <tr><td>{{ k }}</td><td>{{ v }}</td></tr>
      {% endfor %}
    </table>
  {% endif %}

  <h2>Recommended use cases</h2>
  {% if not scores.recommended_use_cases %}
    <p><em>No matching playbooks found in the catalogue. Try widening the stack inputs.</em></p>
  {% else %}
    <table class="scoring">
      <thead><tr><th>Rank</th><th>Use case</th><th style="width:14%">Score</th></tr></thead>
      <tbody>
        {% for uc in scores.recommended_use_cases %}
          <tr>
            <td>{{ loop.index }}</td>
            <td>
              <strong>{{ uc.name }}</strong>
              {% if uc.reasons %}<br><span style="color:#666; font-size:9pt;">{{ uc.reasons | join('; ') }}</span>{% endif %}
            </td>
            <td>{{ uc.score }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% endif %}

  <h2>Threat-actor categories worth tracking</h2>
  {% if not scores.recommended_threat_actors %}
    <p><em>No actor profiles matched.</em></p>
  {% else %}
    <ul>
      {% for a in scores.recommended_threat_actors %}
        <li><strong>{{ a.name }}</strong> &mdash; {{ a.why }}</li>
      {% endfor %}
    </ul>
  {% endif %}

  <h2>What happens next?</h2>
  <p>
    To turn this scoping into a real CyAB onboarding (with detection rules
    actually shipped, audit checks instrumented, and the documentation
    checklist tracked), use the <strong>Convert to system</strong> button on
    /cyab/scoping &mdash; it pre-fills the onboarding wizard with the
    answers you gave here.
  </p>

  <p style="color:#888; font-size:8.5pt; margin-top:18pt;">
    Generated by ION CyAB &bull; scoping engine v1 &bull; {{ generated_at }}
  </p>
</body>
</html>
```

- [ ] **Step 4: Add the PDF helper + endpoint to `cyab_studio_api.py`**

Append to `src/ion/web/cyab_studio_api.py` (next to `_render_onboarding_pack_html` so the two PDF flows live side-by-side):

```python
# ── Scoping pack PDF (Sub-plan C) ─────────────────────────────────────────

def _render_scoping_pack_pdf_html(scores: dict, answers: dict) -> str:
    """Render the scoping pack body via the dedicated Jinja template.

    Distinct from `_render_onboarding_pack_html` — different audience, no
    system FK, no sign-off sections.
    """
    from datetime import datetime as _dt
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    tmpl = env.get_template("cyab/_scoping_pack_pdf.html")
    return tmpl.render(
        scores=scores,
        answers=answers,
        generated_at=_dt.now().strftime("%Y-%m-%d %H:%M"),
    )


@router.post("/scoping/pdf")
async def render_scoping_pack(request: Request):
    """Render the scoping summary as a PDF (HTML fallback if WeasyPrint missing).

    Anonymous endpoint — matches /cyab/scoping page accessibility.
    """
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    full_html = _render_scoping_pack_pdf_html(scores, answers)

    try:
        from weasyprint import HTML as WpHTML
        pdf_bytes = WpHTML(string=full_html).write_pdf()
        filename = f"scoping_pack_{date.today().isoformat()}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    except (ImportError, OSError):
        return Response(
            content=full_html,
            media_type="text/html",
            headers={
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:",
                "X-Content-Type-Options": "nosniff",
            },
        )
```

(`Path`, `Request`, `date`, `Response` are already imported at the top of `cyab_studio_api.py` — verify and add only what's missing.)

**Mount note:** the `/scoping/pdf` endpoint sits on the existing `cyab_studio_api` router (which is mounted at `/api/cyab/studio` in `server.py`). To match the spec's `GET /api/cyab/scoping/pdf` path, also add a thin shim in `cyab_api.py` (which is mounted at `/api/cyab`):

```python
# src/ion/web/cyab_api.py — add after /scoping/score
@router.post("/scoping/pdf")
async def scoping_pdf_proxy(request: Request):
    """Pass-through to the studio_api implementation so the URL lives under
    /api/cyab/scoping/pdf as the spec requires."""
    from ion.web.cyab_studio_api import render_scoping_pack
    return await render_scoping_pack(request)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_pdf.py -v
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_studio_api.py src/ion/web/cyab_api.py src/ion/web/templates/cyab/_scoping_pack_pdf.html tests/integration/test_cyab_scoping_pdf.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): scoping pack PDF export (separate template from onboarding pack)"
```

---

## Task 6: "Convert to system" CTA → onboarding-wizard pre-fill

**Files:**

- Modify: `src/ion/web/cyab_api.py` — add `POST /api/cyab/scoping/convert`
- Test: `tests/integration/test_cyab_scoping_convert.py`

**Cross-plan note:** depends on Sub-plan B's `/cyab/onboard` route. The convert endpoint stashes the answers in the user's session and 303-redirects to the wizard, which reads them from session on Step 1. If session middleware isn't yet wired, fall back to query-string encoding (the implementation below tries session first).

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_scoping_convert.py
"""Integration tests for the Convert-to-system flow."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_convert_requires_auth(client):
    """Anonymous can't convert — that creates state on the server."""
    r = client.post(
        "/api/cyab/scoping/convert",
        data={"org_sector": "finance"},
        follow_redirects=False,
    )
    # 401 / 403 (depending on auth wiring), or redirect-to-login (302/303).
    assert r.status_code in (302, 303, 401, 403)


def test_convert_authenticated_redirects_to_wizard(admin_session):
    r = admin_session.post(
        "/api/cyab/scoping/convert",
        data={"org_sector": "finance", "concern_top": "ransomware"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    location = r.headers["location"]
    assert location.startswith("/cyab/onboard"), f"unexpected redirect target: {location}"


def test_convert_passes_answers_via_query_string_or_session(admin_session):
    """Either query string carries the payload, or the wizard page (next GET)
    receives it via session — at minimum the redirect target must let the
    wizard access the answers."""
    r = admin_session.post(
        "/api/cyab/scoping/convert",
        data={"org_sector": "tech", "concern_top": "supply_chain"},
        follow_redirects=False,
    )
    location = r.headers["location"]
    if "?" in location:
        # Query-string fallback is acceptable
        assert "org_sector" in location or "from_scoping=1" in location
    else:
        # Session-stored — landing page should reveal the prefilled marker
        landing = admin_session.get(location)
        assert landing.status_code == 200
        assert "scoping" in landing.text.lower() or "prefilled" in landing.text.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_convert.py -v
```

Expected: FAIL — endpoint does not exist (404).

- [ ] **Step 3: Add the convert endpoint**

```python
# src/ion/web/cyab_api.py — add after /scoping/pdf shim
from fastapi.responses import RedirectResponse

@router.post("/scoping/convert", dependencies=[Depends(require_permission("alert:read"))])
async def scoping_convert(request: Request):
    """Stash the scoping answers in session, then 303-redirect to the wizard.

    The wizard's Step 1 handler (Sub-plan B) reads `request.session.get(
    'scoping_prefill')` and prefills its form fields. If session middleware
    isn't wired yet, falls back to query-string encoding.
    """
    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        answers[key] = vals if len(vals) > 1 else vals[0]

    try:
        request.session["scoping_prefill"] = answers
        target = "/cyab/onboard?from_scoping=1"
    except (AssertionError, AttributeError):
        # No SessionMiddleware mounted — fall back to query string. URL-encode
        # the answers as a JSON blob inside one query param to avoid expanding
        # multi-value lists into the URL surface.
        from urllib.parse import quote
        target = "/cyab/onboard?from_scoping=1&answers=" + quote(json.dumps(answers))

    return RedirectResponse(url=target, status_code=303)
```

(`json` is already imported at the top of `cyab_api.py`; verify.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_scoping_convert.py -v
```

Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_api.py tests/integration/test_cyab_scoping_convert.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /api/cyab/scoping/convert — stash answers + redirect to wizard"
```

---

## Task 7: Wire wizard Step 2 to the scoping engine (live counter)

**Files:**

- Modify: `src/ion/web/templates/cyab/onboard/_step2_intake.html` (created in Sub-plan B)
- Modify: `src/ion/web/cyab_api.py` — add `POST /api/cyab/onboard/score` (or extend the existing wizard endpoint)
- Test: `tests/integration/test_cyab_wizard_step2_counter.py`

**Cross-plan note:** depends on Sub-plan B's wizard skeleton existing. If `_step2_intake.html` doesn't exist when this task runs, finish Sub-plan B first.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_wizard_step2_counter.py
"""Integration test: wizard Step 2 live counter is driven by scoping engine."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


def test_wizard_step2_includes_counter_widget(admin_session):
    r = admin_session.get("/cyab/onboard?step=2")
    assert r.status_code == 200
    body = r.text
    assert "wizard-counter" in body  # HTMX swap target ID
    assert "/api/cyab/onboard/score" in body  # form posts here on change


def test_onboard_score_endpoint_returns_counter_partial(admin_session):
    r = admin_session.post(
        "/api/cyab/onboard/score",
        data={"org_sector": "finance", "concern_top": "ransomware"},
    )
    assert r.status_code == 200
    body = r.text
    assert "use cases" in body and "MITRE" in body


def test_onboard_score_uses_same_engine_as_scoping(admin_session, client):
    """Same answers should produce identical counter output on both surfaces.
    Confirms the 'scope for all' single-engine architecture from the spec."""
    payload = {"org_sector": "tech", "concern_top": "supply_chain"}
    r1 = client.post("/api/cyab/scoping/score", data=payload)
    r2 = admin_session.post("/api/cyab/onboard/score", data=payload)
    # Both render the counter partial. Strip whitespace to compare.
    norm = lambda s: " ".join(s.split())
    # The wizard partial may have an extra wrapper class — check the headline
    # numbers match instead of strict equality.
    import re
    nums = lambda body: re.findall(r"(\d+)\s*(?:use cases|threat-actor matches|%)", body)
    assert nums(r1.text) == nums(r2.text)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_wizard_step2_counter.py -v
```

Expected: FAIL — `/api/cyab/onboard/score` doesn't exist; Step 2 partial doesn't yet include the counter.

- [ ] **Step 3: Add the onboard-score endpoint to `cyab_api.py`**

```python
# src/ion/web/cyab_api.py — add near the /scoping/score endpoint
@router.post("/onboard/score", dependencies=[Depends(require_permission("alert:read"))])
async def onboard_score(request: Request):
    """Live-counter endpoint for the wizard's Step 2 (intake).

    Reuses the same `cyab_scoping_engine.score_answers` as /cyab/scoping —
    the spec calls this 'engine architecture: scope for all'. Returns the
    counter partial as HTML for HTMX swap.
    """
    from ion.services import cyab_scoping_engine

    raw = await request.form()
    answers: dict = {}
    for key in raw.keys():
        vals = [v for v in raw.getlist(key) if v != ""]
        if not vals:
            continue
        answers[key] = vals if len(vals) > 1 else vals[0]

    scores = cyab_scoping_engine.score_answers(answers)
    return templates.TemplateResponse(
        request=request,
        name="cyab/_scoping_counter.html",
        context={
            "scores": scores,
            "answers": answers,
            "summary_text": cyab_scoping_engine.summary_text(scores),
        },
    )
```

- [ ] **Step 4: Modify the Sub-plan B wizard Step 2 partial to add the counter region**

Edit `src/ion/web/templates/cyab/onboard/_step2_intake.html` — wrap the question form in a two-column grid and add the counter aside on the right. Append (or splice into the existing layout):

```html
{# === Scoping engine integration — added by Sub-plan C === #}
<div class="tw-grid tw-grid-cols-3 tw-gap-4">
  <div class="tw-col-span-2">
    {# existing intake-question rendering from Sub-plan B goes here unchanged #}
    {% block step2_intake_form %}
      <form id="wizard-intake-form"
            hx-post="/api/cyab/onboard/score"
            hx-target="#wizard-counter"
            hx-trigger="change"
            hx-swap="innerHTML">
        {# ... existing intake question rendering, unchanged ... #}
      </form>
    {% endblock %}
  </div>

  <aside class="tw-col-span-1">
    <div id="wizard-counter"
         class="tw-sticky tw-top-4 tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-4">
      {# Initial render: zero state from server context. #}
      {% set scores = scoping_initial | default({"use_case_count": 0,
                                                 "threat_actor_matches": 0,
                                                 "mitre_coverage_pct": 0}) %}
      {% include "cyab/_scoping_counter.html" %}
    </div>
  </aside>
</div>
```

In the wizard's Step 2 page handler (created in Sub-plan B), populate `scoping_initial` from any answers already saved against the session:

```python
# (in server.py wizard handler — pseudocode patch)
from ion.services import cyab_scoping_engine
ctx["scoping_initial"] = cyab_scoping_engine.score_answers(
    request.session.get("wizard_answers", {})
)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_wizard_step2_counter.py -v
```

Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_api.py src/ion/web/templates/cyab/onboard/_step2_intake.html tests/integration/test_cyab_wizard_step2_counter.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): wizard Step 2 wired to shared scoping engine — single-engine architecture"
```

---

## Task 8: Coverage matrix backend (`/api/cyab/coverage/matrix`)

**Files:**

- Modify: `src/ion/web/cyab_api.py` — add `GET /api/cyab/coverage/matrix`
- Test: `tests/integration/test_cyab_coverage_matrix.py` (API-level only in this task; page in Task 9)

**Cross-plan note:** depends on Sub-plan A's `cyab_data_health_service`. The matrix calls `ingestion_freshness`, `field_mapping_completeness`, `coverage_rollup` per system to assemble the row.

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_coverage_matrix.py
"""Integration tests for the fleet coverage matrix backend + page."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


@pytest.fixture
def three_systems(temp_db):
    """Three systems with mixed health states."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem, CyabDataSource
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys_healthy = CyabSystem(name="prod-healthy", department="Identity",
                             owner="alice", status="ACTIVE")
    sys_amber = CyabSystem(name="prod-amber", department="Endpoint",
                           owner="bob")
    sys_red = CyabSystem(name="prod-red", department="Cloud",
                        owner="alice")
    s.add_all([sys_healthy, sys_amber, sys_red])
    s.flush()
    s.add(CyabDataSource(system_id=sys_healthy.id, name="winlog",
                         data_source_type="windows-evtx",
                         field_mapping={"@timestamp": "ts", "host.name": "h",
                                        "event.code": "ec", "user.name": "u"}))
    s.commit()
    yield {"healthy": sys_healthy.id, "amber": sys_amber.id, "red": sys_red.id}
    s.close()


def test_matrix_endpoint_returns_one_row_per_system(admin_session, three_systems):
    r = admin_session.get("/api/cyab/coverage/matrix")
    assert r.status_code == 200
    data = r.json()
    assert "rows" in data and len(data["rows"]) == 3
    assert "aggregates" in data
    assert "dimensions" in data


def test_matrix_row_has_seven_dimension_cells(admin_session, three_systems):
    r = admin_session.get("/api/cyab/coverage/matrix")
    data = r.json()
    expected_dimensions = {
        "ingestion_fresh", "fields_mapped", "intake_done",
        "detections_shipped", "audit_shipped", "checklist_done",
        "signed_off",
    }
    for row in data["rows"]:
        assert set(row["cells"].keys()) == expected_dimensions
        for dim, cell in row["cells"].items():
            assert cell["status"] in ("green", "amber", "red", "unknown")


def test_matrix_aggregates_strip(admin_session, three_systems):
    r = admin_session.get("/api/cyab/coverage/matrix")
    data = r.json()
    agg = data["aggregates"]
    assert "pct_systems_healthy" in agg
    assert "pct_critical_missing" in agg
    assert "pct_stale_ingestion" in agg
    for v in agg.values():
        assert 0 <= v <= 100


def test_matrix_filter_by_owner(admin_session, three_systems):
    r = admin_session.get("/api/cyab/coverage/matrix?owner=alice")
    data = r.json()
    assert len(data["rows"]) == 2  # prod-healthy and prod-red
    for row in data["rows"]:
        assert row["owner"] == "alice"


def test_matrix_filter_any_red(admin_session, three_systems):
    r = admin_session.get("/api/cyab/coverage/matrix?any_red=1")
    data = r.json()
    # Only systems with at least one red cell should appear
    for row in data["rows"]:
        assert any(c["status"] == "red" for c in row["cells"].values())
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_coverage_matrix.py -v
```

Expected: FAIL — endpoint doesn't exist.

- [ ] **Step 3: Add the matrix endpoint**

```python
# src/ion/web/cyab_api.py
from typing import Optional

@router.get("/coverage/matrix", dependencies=[Depends(require_permission("alert:read"))])
async def coverage_matrix(
    pillar: Optional[str] = None,
    owner: Optional[str] = None,
    any_red: int = 0,
    session: Session = Depends(get_db_session),
):
    """Fleet × dimensions matrix.

    Rows = CyabSystem rows (filtered by pillar/owner). Columns = 7 data-health
    dimensions (mirrors the spec). Each cell carries a status pill that the
    UI colours green/amber/red and a deep-link target.

    Aggregates strip computed once per request from the same row data.
    """
    from sqlalchemy import select
    from ion.models.cyab import CyabSystem, CyabDocChecklistItem
    from ion.services import cyab_data_health_service as dh
    from ion.services import cyab_doc_checklist_service as ck

    q = select(CyabSystem).where(
        (CyabSystem.archived_at.is_(None)) if hasattr(CyabSystem, "archived_at") else True
    )
    if pillar:
        q = q.where(CyabSystem.pillar == pillar)
    if owner:
        q = q.where(CyabSystem.owner == owner)
    systems = session.execute(q).scalars().all()

    rows = []
    for sys in systems:
        sid = sys.id

        # Per-dimension cells
        ing = dh.ingestion_freshness(session, sid)
        ing_status = _worst_sla([r["sla_status"] for r in ing]) if ing else "unknown"

        fm = dh.field_mapping_completeness(session, sid)
        fm_pct = (
            sum((r["completeness"] or 0) for r in fm) / len(fm) if fm else None
        )
        fm_status = _pct_to_status(fm_pct, green_at=0.9, amber_at=0.6)

        cov = dh.coverage_rollup(session, sid)
        intake_status = _pct_to_status(cov.get("intake_pct"), green_at=0.9, amber_at=0.5)
        det_status    = _pct_to_status(cov.get("detection_pct"), green_at=0.8, amber_at=0.4)
        aud_status    = _pct_to_status(cov.get("audit_pct"), green_at=0.8, amber_at=0.4)

        checklist = ck.coverage_summary(session, sid)
        ck_pct = (checklist["done"] / checklist["total"]) if checklist["total"] else 0
        ck_status = _pct_to_status(ck_pct, green_at=1.0, amber_at=0.5)

        signed_status = "green" if (sys.sign_dept_name and sys.sign_soc_name) else "red"

        cells = {
            "ingestion_fresh":     {"status": ing_status,    "tab": "data-health"},
            "fields_mapped":       {"status": fm_status,     "tab": "sources"},
            "intake_done":         {"status": intake_status, "tab": "intake"},
            "detections_shipped":  {"status": det_status,    "tab": "detection"},
            "audit_shipped":       {"status": aud_status,    "tab": "audit-use-cases"},
            "checklist_done":      {"status": ck_status,     "tab": "overview"},
            "signed_off":          {"status": signed_status, "tab": "signoff"},
        }

        if any_red and not any(c["status"] == "red" for c in cells.values()):
            continue

        rows.append({
            "system_id":  sid,
            "name":       sys.name,
            "pillar":     getattr(sys, "pillar", None),
            "owner":      sys.owner,
            "department": sys.department,
            "cells":      cells,
        })

    # Aggregates (computed against the unfiltered set so the strip is stable
    # — the spec wording matches a fleet-wide metric, not a filter-scoped one).
    all_systems_for_agg = systems if not (pillar or owner or any_red) else (
        session.execute(select(CyabSystem)).scalars().all()
    )
    total = len(all_systems_for_agg) or 1
    healthy = sum(
        1 for r in rows if all(c["status"] == "green" for c in r["cells"].values())
    )
    crit = sum(
        1 for sys in all_systems_for_agg
        if (lambda c: c["critical_missing"])(ck.coverage_summary(session, sys.id))
    )
    stale = sum(
        1 for sys in all_systems_for_agg
        if any(
            r["sla_status"] == "red" for r in dh.ingestion_freshness(session, sys.id)
        )
    )

    return {
        "dimensions": [
            "ingestion_fresh", "fields_mapped", "intake_done",
            "detections_shipped", "audit_shipped", "checklist_done",
            "signed_off",
        ],
        "rows": rows,
        "aggregates": {
            "pct_systems_healthy":  int(round(100 * healthy / total)),
            "pct_critical_missing": int(round(100 * crit / total)),
            "pct_stale_ingestion":  int(round(100 * stale / total)),
        },
    }


def _worst_sla(statuses: list) -> str:
    """Reduce per-source SLA pills into one cell colour for the system row."""
    order = {"red": 3, "amber": 2, "fresh": 1, "unknown": 0}
    if not statuses:
        return "unknown"
    worst = max(statuses, key=lambda s: order.get(s, 0))
    return {"red": "red", "amber": "amber", "fresh": "green", "unknown": "unknown"}[worst]


def _pct_to_status(pct, green_at: float, amber_at: float) -> str:
    if pct is None:
        return "unknown"
    if pct >= green_at:
        return "green"
    if pct >= amber_at:
        return "amber"
    return "red"
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_coverage_matrix.py -v
```

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_api.py tests/integration/test_cyab_coverage_matrix.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /api/cyab/coverage/matrix — fleet x data-health dimensions"
```

---

## Task 9: `/cyab/coverage` page

**Files:**

- Create: `src/ion/web/templates/cyab/coverage.html`
- Create: `src/ion/web/templates/cyab/_coverage_matrix.html`
- Modify: `src/ion/web/server.py` — register `/cyab/coverage` page route
- Test: extend `tests/integration/test_cyab_coverage_matrix.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/integration/test_cyab_coverage_matrix.py`:

```python
def test_coverage_page_renders(admin_session, three_systems):
    r = admin_session.get("/cyab/coverage")
    assert r.status_code == 200
    body = r.text
    for sys_name in ("prod-healthy", "prod-amber", "prod-red"):
        assert sys_name in body


def test_coverage_page_shows_aggregate_strip(admin_session, three_systems):
    r = admin_session.get("/cyab/coverage")
    body = r.text.lower()
    assert "% systems healthy" in body or "systems healthy" in body
    assert "critical-missing" in body or "critical missing" in body
    assert "stale-ingestion" in body or "stale ingestion" in body


def test_coverage_page_cells_link_to_per_system_tabs(admin_session, three_systems):
    r = admin_session.get("/cyab/coverage")
    body = r.text
    sid = three_systems["healthy"]
    # Each row's cells deep-link into the relevant tab on the per-system page
    assert f"/cyab/systems/{sid}/" in body or f"/cyab/systems/{sid}#" in body


def test_coverage_filter_form_present(admin_session, three_systems):
    r = admin_session.get("/cyab/coverage")
    body = r.text
    assert 'name="owner"' in body
    assert 'name="pillar"' in body
    assert 'name="any_red"' in body
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_coverage_matrix.py -v -k "page or aggregate or cells_link or filter_form"
```

Expected: FAIL.

- [ ] **Step 3: Add the page route**

```python
# src/ion/web/server.py
@app.get("/cyab/coverage", response_class=HTMLResponse)
async def cyab_coverage_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Fleet data-health matrix: systems x dimensions."""
    import httpx
    # Call our own API to avoid duplicating the matrix-build logic.
    # In tests the same TestClient handles both — fine for a server-side fetch.
    from ion.web.cyab_api import coverage_matrix
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config
    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        matrix = await coverage_matrix(
            pillar=request.query_params.get("pillar") or None,
            owner=request.query_params.get("owner") or None,
            any_red=int(request.query_params.get("any_red") or 0),
            session=session,
        )
    finally:
        session.close()

    return templates.TemplateResponse(
        request=request,
        name="cyab/coverage.html",
        context={"matrix": matrix, "user": user,
                 "filters": {
                     "pillar":  request.query_params.get("pillar") or "",
                     "owner":   request.query_params.get("owner") or "",
                     "any_red": request.query_params.get("any_red") or "",
                 }},
    )
```

- [ ] **Step 4: Create the page template**

```html
<!-- src/ion/web/templates/cyab/coverage.html -->
{% extends "base.html" %}
{% block title %}Coverage — CyAB · ION{% endblock %}

{% block content %}
<div class="cyab-coverage">
  <header class="tw-mb-4">
    <nav class="breadcrumb tw-text-sm tw-text-slate-400 tw-mb-2">
      <a href="/cyab" class="hover:tw-text-white">CyAB</a>
      <span class="tw-mx-2">·</span>
      <span class="tw-text-white">Coverage</span>
    </nav>
    <h1 class="tw-text-[28px] tw-font-semibold tw-text-white">Fleet data-health matrix</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px]">
      Every system × every signal. Click any cell to drill into the relevant tab on the per-system page.
    </p>
  </header>

  {# Aggregates strip #}
  <div class="tw-grid tw-grid-cols-3 tw-gap-3 tw-mb-4">
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-emerald-300 tw-text-[24px] tw-font-semibold">{{ matrix.aggregates.pct_systems_healthy }}%</div>
      <div class="tw-text-slate-400 tw-text-[11px]">systems healthy</div>
    </div>
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-rose-300 tw-text-[24px] tw-font-semibold">{{ matrix.aggregates.pct_critical_missing }}%</div>
      <div class="tw-text-slate-400 tw-text-[11px]">critical-missing items</div>
    </div>
    <div class="tw-bg-slate-900/40 tw-border tw-border-slate-800 tw-rounded tw-p-3">
      <div class="tw-text-amber-300 tw-text-[24px] tw-font-semibold">{{ matrix.aggregates.pct_stale_ingestion }}%</div>
      <div class="tw-text-slate-400 tw-text-[11px]">stale-ingestion systems</div>
    </div>
  </div>

  {# Filters #}
  <form method="get" action="/cyab/coverage" class="tw-flex tw-items-end tw-gap-3 tw-mb-4">
    <label class="tw-flex tw-flex-col tw-gap-1 tw-text-[11px] tw-text-slate-400">
      Pillar
      <input name="pillar" value="{{ filters.pillar }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1 tw-text-[11px] tw-text-slate-400">
      Owner
      <input name="owner" value="{{ filters.owner }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-text-[12px] tw-rounded">
    </label>
    <label class="tw-flex tw-items-center tw-gap-2 tw-text-[12px] tw-text-slate-300 tw-mb-1">
      <input type="checkbox" name="any_red" value="1" {% if filters.any_red %}checked{% endif %}>
      Any red
    </label>
    <button type="submit" class="tw-px-3 tw-py-1 tw-bg-cyan-700 tw-text-white tw-text-[12px] tw-rounded">
      Apply
    </button>
  </form>

  <div id="coverage-matrix">
    {% include "cyab/_coverage_matrix.html" %}
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Create the matrix partial**

```html
<!-- src/ion/web/templates/cyab/_coverage_matrix.html -->
{% set dim_labels = {
  "ingestion_fresh":    "Ingestion",
  "fields_mapped":      "Fields",
  "intake_done":        "Intake",
  "detections_shipped": "Detections",
  "audit_shipped":      "Audit",
  "checklist_done":     "Checklist",
  "signed_off":         "Sign-off",
} %}
{% set status_dot = {
  "green": "tw-text-emerald-400",
  "amber": "tw-text-amber-400",
  "red":   "tw-text-rose-400",
  "unknown": "tw-text-slate-600",
} %}

<table class="tw-w-full tw-text-[12px] tw-border-collapse">
  <thead>
    <tr class="tw-text-slate-500 tw-text-[10.5px] tw-uppercase tw-tracking-wider">
      <th class="tw-text-left tw-py-2 tw-pr-3">System</th>
      <th class="tw-text-left tw-pr-3">Owner</th>
      {% for dim in matrix.dimensions %}
        <th class="tw-text-center tw-px-1">{{ dim_labels[dim] }}</th>
      {% endfor %}
    </tr>
  </thead>
  <tbody>
    {% for row in matrix.rows %}
      <tr class="tw-border-t tw-border-slate-800 hover:tw-bg-slate-900/40">
        <td class="tw-py-2 tw-pr-3 tw-text-cyan-300 tw-font-mono">
          <a href="/cyab/systems/{{ row.system_id }}" class="hover:tw-underline">{{ row.name }}</a>
        </td>
        <td class="tw-text-slate-400">{{ row.owner or '—' }}</td>
        {% for dim in matrix.dimensions %}
          {% set cell = row.cells[dim] %}
          <td class="tw-text-center">
            <a href="/cyab/systems/{{ row.system_id }}#tab={{ cell.tab }}"
               title="{{ dim }}: {{ cell.status }}"
               class="tw-inline-block tw-px-1">
              <span class="{{ status_dot[cell.status] }} tw-text-[16px]">●</span>
            </a>
          </td>
        {% endfor %}
      </tr>
    {% else %}
      <tr><td colspan="9" class="tw-py-6 tw-text-center tw-text-slate-500">No systems match the current filters.</td></tr>
    {% endfor %}
  </tbody>
</table>
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_coverage_matrix.py -v
```

Expected: 9 PASS (5 from Task 8 + 4 from Task 9).

- [ ] **Step 7: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/coverage.html src/ion/web/templates/cyab/_coverage_matrix.html src/ion/web/server.py tests/integration/test_cyab_coverage_matrix.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab/coverage page — fleet matrix with deep-links + filters"
```

---

## Task 10: Audit feed backend (`/api/cyab/audit/feed`)

**Files:**

- Modify: `src/ion/web/cyab_api.py` — add `GET /api/cyab/audit/feed`
- Test: `tests/integration/test_cyab_audit_feed.py` (API-level)

- [ ] **Step 1: Write failing tests**

```python
# tests/integration/test_cyab_audit_feed.py
"""Integration tests for the /cyab/audit chronological feed."""

import pytest
from datetime import date, datetime, timedelta


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


@pytest.fixture
def seeded_audit_events(temp_db):
    """A system with: a sign-off snapshot, a checklist update, and a create event."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem, CyabSnapshot
    from ion.models.cyab_doc_checklist import CyabDocChecklistItem
    Session = sessionmaker(bind=temp_db)
    s = Session()
    sys = CyabSystem(name="audit-test", department="X", owner="alice")
    s.add(sys); s.flush()

    snap = CyabSnapshot(system_id=sys.id, snapshot_date=date.today(),
                        readiness_score=80, kind="signoff",
                        notes="Signed off by Alice")
    s.add(snap)

    item = CyabDocChecklistItem(system_id=sys.id, kind="HLD",
                                label="High-level design", status="done")
    s.add(item); s.commit()
    yield sys.id
    s.close()


def test_audit_feed_returns_events(admin_session, seeded_audit_events):
    r = admin_session.get("/api/cyab/audit/feed")
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert len(data["events"]) >= 2  # at least create + signoff


def test_audit_feed_event_shape(admin_session, seeded_audit_events):
    r = admin_session.get("/api/cyab/audit/feed")
    for ev in r.json()["events"]:
        assert "when" in ev
        assert "who" in ev
        assert "what" in ev
        assert "system_id" in ev
        assert "action_type" in ev
        assert ev["action_type"] in (
            "create", "signoff", "checklist_update",
            "containment_change", "archive",
        )


def test_audit_feed_sorted_descending(admin_session, seeded_audit_events):
    r = admin_session.get("/api/cyab/audit/feed")
    events = r.json()["events"]
    timestamps = [e["when"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_audit_feed_filter_by_system(admin_session, seeded_audit_events):
    sid = seeded_audit_events
    r = admin_session.get(f"/api/cyab/audit/feed?system_id={sid}")
    for ev in r.json()["events"]:
        assert ev["system_id"] == sid


def test_audit_feed_filter_by_action_type(admin_session, seeded_audit_events):
    r = admin_session.get("/api/cyab/audit/feed?action_type=signoff")
    events = r.json()["events"]
    assert len(events) >= 1
    for ev in events:
        assert ev["action_type"] == "signoff"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_feed.py -v
```

Expected: FAIL.

- [ ] **Step 3: Add the audit-feed endpoint**

```python
# src/ion/web/cyab_api.py
from datetime import datetime as _dt, date as _date

@router.get("/audit/feed", dependencies=[Depends(require_permission("alert:read"))])
async def audit_feed(
    system_id: Optional[int] = None,
    user: Optional[str] = None,
    action_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = 200,
    session: Session = Depends(get_db_session),
):
    """Chronological feed of CyAB compliance events.

    Unions four sources:
      - CyabSnapshot rows tagged kind in ('signoff', 'checklist_update', etc.)
      - CyabDocChecklistItem.updated_at deltas (status changes)
      - CyabSystem.created_at / archived_at (system lifecycle)
      - change_log_service entries with type='cyab.containment_authority'
    """
    from sqlalchemy import select
    from ion.models.cyab import CyabSystem, CyabSnapshot
    from ion.models.cyab_doc_checklist import CyabDocChecklistItem

    events: list = []

    # 1. System creates + archives
    sys_q = select(CyabSystem)
    if system_id:
        sys_q = sys_q.where(CyabSystem.id == system_id)
    for sys in session.execute(sys_q).scalars().all():
        if sys.created_at:
            events.append({
                "when":        sys.created_at.isoformat(),
                "who":         getattr(sys, "created_by", None) or "system",
                "what":        f"System '{sys.name}' created",
                "system_id":   sys.id,
                "system_name": sys.name,
                "action_type": "create",
                "link":        f"/cyab/systems/{sys.id}",
            })
        if getattr(sys, "archived_at", None):
            events.append({
                "when":        sys.archived_at.isoformat(),
                "who":         getattr(sys, "archived_by", None) or "system",
                "what":        f"System '{sys.name}' archived",
                "system_id":   sys.id,
                "system_name": sys.name,
                "action_type": "archive",
                "link":        f"/cyab/systems/{sys.id}",
            })

    # 2. Snapshots (sign-offs, checklist update markers)
    snap_q = select(CyabSnapshot)
    if system_id:
        snap_q = snap_q.where(CyabSnapshot.system_id == system_id)
    for snap in session.execute(snap_q).scalars().all():
        kind = getattr(snap, "kind", None) or "snapshot"
        events.append({
            "when":        (snap.created_at or _dt.combine(snap.snapshot_date, _dt.min.time())).isoformat(),
            "who":         getattr(snap, "signed_by", None) or "system",
            "what":        snap.notes or f"Snapshot recorded ({kind})",
            "system_id":   snap.system_id,
            "system_name": snap.system.name if snap.system else None,
            "action_type": kind if kind in ("signoff", "checklist_update", "snapshot") else "snapshot",
            "snapshot_id": snap.id,
            "snapshot_date": snap.snapshot_date.isoformat(),
            "link":        f"/cyab/systems/{snap.system_id}#snapshot={snap.id}",
            "pdf_link":    f"/api/cyab/studio/systems/{snap.system_id}/onboarding-pack?as_of={snap.snapshot_date.isoformat()}",
        })

    # 3. Checklist updates
    ck_q = select(CyabDocChecklistItem)
    if system_id:
        ck_q = ck_q.where(CyabDocChecklistItem.system_id == system_id)
    for item in session.execute(ck_q).scalars().all():
        ts = getattr(item, "updated_at", None) or getattr(item, "created_at", None)
        if not ts:
            continue
        events.append({
            "when":        ts.isoformat(),
            "who":         getattr(item, "updated_by", None) or "system",
            "what":        f"Checklist item '{item.label}' → {item.status}",
            "system_id":   item.system_id,
            "system_name": None,
            "action_type": "checklist_update",
            "link":        f"/cyab/systems/{item.system_id}#tab=overview",
        })

    # 4. Containment-authority changes (from change_log_service)
    try:
        from ion.services import change_log_service as cls
        cls_events = cls.list_events(
            session,
            entity_type="cyab.system",
            field="containment_authority",
            system_id=system_id,
            limit=200,
        ) if hasattr(cls, "list_events") else []
        for ev in cls_events:
            events.append({
                "when":        ev["when"].isoformat() if hasattr(ev["when"], "isoformat") else str(ev["when"]),
                "who":         ev.get("who") or "unknown",
                "what":        f"Containment authority: {ev.get('old_value')} → {ev.get('new_value')}",
                "system_id":   ev.get("entity_id"),
                "system_name": None,
                "action_type": "containment_change",
                "link":        f"/cyab/systems/{ev.get('entity_id')}#tab=signoff",
            })
    except Exception:
        # change_log_service may not have the expected query API yet — skip rather than fail.
        pass

    # Filter by user / action_type
    if user:
        events = [e for e in events if e["who"] == user]
    if action_type:
        events = [e for e in events if e["action_type"] == action_type]

    # Date filters
    def _parse(s):
        try:
            return _dt.fromisoformat(s)
        except Exception:
            return None

    if since:
        cutoff = _parse(since)
        if cutoff:
            events = [e for e in events if _dt.fromisoformat(e["when"]) >= cutoff]
    if until:
        cutoff = _parse(until)
        if cutoff:
            events = [e for e in events if _dt.fromisoformat(e["when"]) <= cutoff]

    events.sort(key=lambda e: e["when"], reverse=True)
    return {"events": events[:limit], "total": len(events)}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_feed.py -v
```

Expected: 5 PASS.

- [ ] **Step 5: Commit**

```bash
cd ~/ION && git add src/ion/web/cyab_api.py tests/integration/test_cyab_audit_feed.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /api/cyab/audit/feed — chronological union of compliance events"
```

---

## Task 11: `/cyab/audit` page

**Files:**

- Create: `src/ion/web/templates/cyab/audit.html`
- Create: `src/ion/web/templates/cyab/_audit_feed.html`
- Modify: `src/ion/web/server.py` — register `/cyab/audit` route
- Test: extend `tests/integration/test_cyab_audit_feed.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/integration/test_cyab_audit_feed.py`:

```python
def test_audit_page_renders(admin_session, seeded_audit_events):
    r = admin_session.get("/cyab/audit")
    assert r.status_code == 200
    body = r.text
    assert "audit-test" in body  # the seeded system shows up


def test_audit_page_rows_have_pdf_link(admin_session, seeded_audit_events):
    r = admin_session.get("/cyab/audit")
    body = r.text
    # Sign-off rows expose a "View onboarding pack PDF as of this date" link
    assert "onboarding-pack" in body
    assert "as_of=" in body or "snapshot=" in body


def test_audit_page_filter_inputs_present(admin_session, seeded_audit_events):
    r = admin_session.get("/cyab/audit")
    body = r.text
    for name in ("system_id", "user", "action_type", "since", "until"):
        assert f'name="{name}"' in body
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_feed.py -v -k page
```

Expected: FAIL — route does not exist.

- [ ] **Step 3: Add the page route**

```python
# src/ion/web/server.py
@app.get("/cyab/audit", response_class=HTMLResponse)
async def cyab_audit_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Compliance audit trail (sign-offs, checklist deltas, system lifecycle, containment changes)."""
    from ion.web.cyab_api import audit_feed
    from ion.storage.database import get_engine, get_session_factory
    from ion.core.config import get_config
    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        feed = await audit_feed(
            system_id=int(request.query_params.get("system_id") or 0) or None,
            user=request.query_params.get("user") or None,
            action_type=request.query_params.get("action_type") or None,
            since=request.query_params.get("since") or None,
            until=request.query_params.get("until") or None,
            session=session,
        )
    finally:
        session.close()

    return templates.TemplateResponse(
        request=request,
        name="cyab/audit.html",
        context={
            "feed": feed,
            "user": user,
            "filters": {
                "system_id":   request.query_params.get("system_id") or "",
                "user":        request.query_params.get("user") or "",
                "action_type": request.query_params.get("action_type") or "",
                "since":       request.query_params.get("since") or "",
                "until":       request.query_params.get("until") or "",
            },
        },
    )
```

- [ ] **Step 4: Create the page + feed templates**

```html
<!-- src/ion/web/templates/cyab/audit.html -->
{% extends "base.html" %}
{% block title %}Audit — CyAB · ION{% endblock %}

{% block content %}
<div class="cyab-audit">
  <header class="tw-mb-4">
    <nav class="breadcrumb tw-text-sm tw-text-slate-400 tw-mb-2">
      <a href="/cyab" class="hover:tw-text-white">CyAB</a>
      <span class="tw-mx-2">·</span>
      <span class="tw-text-white">Audit trail</span>
    </nav>
    <h1 class="tw-text-[28px] tw-font-semibold tw-text-white">Audit trail</h1>
    <p class="tw-text-slate-400 tw-text-[12.5px]">Sign-offs, checklist updates, containment-authority changes, and system lifecycle events.</p>
  </header>

  <form method="get" action="/cyab/audit" class="tw-grid tw-grid-cols-6 tw-gap-2 tw-mb-4 tw-text-[12px]">
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400 tw-text-[10.5px]">System ID</span>
      <input name="system_id" value="{{ filters.system_id }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400 tw-text-[10.5px]">User</span>
      <input name="user" value="{{ filters.user }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400 tw-text-[10.5px]">Action</span>
      <select name="action_type"
              class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
        <option value="">— any —</option>
        {% for opt in ['create', 'signoff', 'checklist_update', 'containment_change', 'archive'] %}
          <option value="{{ opt }}" {% if filters.action_type == opt %}selected{% endif %}>{{ opt }}</option>
        {% endfor %}
      </select>
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400 tw-text-[10.5px]">Since</span>
      <input type="date" name="since" value="{{ filters.since }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    </label>
    <label class="tw-flex tw-flex-col tw-gap-1">
      <span class="tw-text-slate-400 tw-text-[10.5px]">Until</span>
      <input type="date" name="until" value="{{ filters.until }}"
             class="tw-px-2 tw-py-1 tw-bg-slate-900 tw-border tw-border-slate-700 tw-rounded">
    </label>
    <button type="submit"
            class="tw-self-end tw-px-3 tw-py-1 tw-bg-cyan-700 tw-text-white tw-rounded">
      Apply
    </button>
  </form>

  <div id="audit-feed">
    {% include "cyab/_audit_feed.html" %}
  </div>
</div>
{% endblock %}
```

```html
<!-- src/ion/web/templates/cyab/_audit_feed.html -->
{% if not feed.events %}
  <p class="tw-text-slate-500 tw-text-[12px] tw-py-6 tw-text-center">No events match the current filters.</p>
{% else %}
<table class="tw-w-full tw-text-[12px] tw-border-collapse">
  <thead>
    <tr class="tw-text-slate-500 tw-text-[10.5px] tw-uppercase tw-tracking-wider">
      <th class="tw-text-left tw-py-2 tw-pr-3">When</th>
      <th class="tw-text-left tw-pr-3">Who</th>
      <th class="tw-text-left tw-pr-3">Action</th>
      <th class="tw-text-left tw-pr-3">What</th>
      <th class="tw-text-left tw-pr-3">System</th>
      <th class="tw-text-left">Links</th>
    </tr>
  </thead>
  <tbody>
    {% for ev in feed.events %}
      <tr class="tw-border-t tw-border-slate-800 hover:tw-bg-slate-900/40">
        <td class="tw-py-1.5 tw-pr-3 tw-text-slate-400 tw-font-mono tw-text-[11px]">{{ ev.when[:19].replace('T', ' ') }}</td>
        <td class="tw-pr-3 tw-text-slate-300">{{ ev.who }}</td>
        <td class="tw-pr-3">
          {% set badge_class = {
            'create': 'tw-bg-cyan-900/40 tw-text-cyan-300',
            'signoff': 'tw-bg-emerald-900/40 tw-text-emerald-300',
            'checklist_update': 'tw-bg-slate-800 tw-text-slate-300',
            'containment_change': 'tw-bg-amber-900/40 tw-text-amber-300',
            'archive': 'tw-bg-rose-900/40 tw-text-rose-300',
          }.get(ev.action_type, 'tw-bg-slate-800 tw-text-slate-400') %}
          <span class="{{ badge_class }} tw-px-2 tw-py-0.5 tw-rounded tw-text-[10.5px] tw-font-mono">{{ ev.action_type }}</span>
        </td>
        <td class="tw-pr-3 tw-text-slate-300">{{ ev.what }}</td>
        <td class="tw-pr-3 tw-text-cyan-400">
          {% if ev.system_id %}<a href="/cyab/systems/{{ ev.system_id }}" class="hover:tw-underline">{{ ev.system_name or '#' ~ ev.system_id }}</a>{% endif %}
        </td>
        <td>
          <a href="{{ ev.link }}" class="tw-text-cyan-400 tw-text-[11px] hover:tw-underline">view</a>
          {% if ev.pdf_link %}
            &middot;
            <a href="{{ ev.pdf_link }}" target="_blank" class="tw-text-cyan-400 tw-text-[11px] hover:tw-underline"
               title="View onboarding pack PDF as of {{ ev.snapshot_date }}">
              pack@{{ ev.snapshot_date }}
            </a>
          {% endif %}
        </td>
      </tr>
    {% endfor %}
  </tbody>
</table>
<p class="tw-text-slate-500 tw-text-[10.5px] tw-mt-3">Showing {{ feed.events | length }} of {{ feed.total }} events.</p>
{% endif %}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_audit_feed.py -v
```

Expected: 8 PASS (5 from Task 10 + 3 from Task 11).

- [ ] **Step 6: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/audit.html src/ion/web/templates/cyab/_audit_feed.html src/ion/web/server.py tests/integration/test_cyab_audit_feed.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "feat(cyab): /cyab/audit page — chronological compliance feed with filters + as-of PDF links"
```

---

## Task 12: Cross-page smoke + nav-strip glue

**Files:**

- Modify: `src/ion/web/templates/cyab/_nav_strip.html` (created in Sub-plan B; this task adds active-state highlighting for the new pages)
- Create: `tests/integration/test_cyab_phase1_smoke.py`

- [ ] **Step 1: Write the smoke test**

```python
# tests/integration/test_cyab_phase1_smoke.py
"""End-to-end smoke covering all 7 top-level CyAB pages from the spec."""

import pytest


@pytest.fixture
def client(temp_db, monkeypatch):
    monkeypatch.setattr("ion.storage.database.get_engine", lambda *_a, **_k: temp_db)
    from fastapi.testclient import TestClient
    from ion.web.server import app
    return TestClient(app)


@pytest.fixture
def admin_session(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    return client


@pytest.fixture
def fleet_seed(temp_db):
    """A fleet of three systems with mixed states."""
    from sqlalchemy.orm import sessionmaker
    from ion.models.cyab import CyabSystem, CyabDataSource
    Session = sessionmaker(bind=temp_db)
    s = Session()
    for name in ("alpha-sso", "beta-edr", "gamma-cloud"):
        sys = CyabSystem(name=name, owner="alice")
        s.add(sys); s.flush()
        s.add(CyabDataSource(system_id=sys.id, name=f"{name}-src",
                             data_source_type="generic-syslog"))
    s.commit()
    yield
    s.close()


@pytest.mark.parametrize("path,anonymous_ok", [
    ("/cyab",          False),
    ("/cyab/systems",  False),
    ("/cyab/scoping",  True),
    ("/cyab/onboard",  False),
    ("/cyab/coverage", False),
    ("/cyab/audit",    False),
])
def test_each_top_level_page_loads(admin_session, client, fleet_seed, path, anonymous_ok):
    sess = client if anonymous_ok else admin_session
    r = sess.get(path)
    assert r.status_code == 200, f"{path} returned {r.status_code}"
    assert len(r.text) > 200


def test_nav_strip_present_on_each_cyab_page(admin_session, fleet_seed):
    """The shared secondary nav strip appears on every page."""
    for path in ("/cyab", "/cyab/systems", "/cyab/scoping",
                 "/cyab/onboard", "/cyab/coverage", "/cyab/audit"):
        r = admin_session.get(path)
        body = r.text
        # Look for the nav strip marker (added by Sub-plan B's _nav_strip.html)
        assert "cyab-nav-strip" in body, f"{path} missing nav strip"


def test_scoping_engine_drives_both_surfaces(admin_session, client):
    """Acceptance test for the spec's 'engine architecture: scope for all'.
    Counter widget on /cyab/scoping and on /cyab/onboard?step=2 are
    served by the same engine — same answers → identical numbers."""
    payload = {"org_sector": "tech", "concern_top": "ransomware"}
    a = client.post("/api/cyab/scoping/score", data=payload).text
    b = admin_session.post("/api/cyab/onboard/score", data=payload).text
    import re
    pull = lambda body: re.findall(r">(\d+(?:%)?)<", body)
    # Counter partial uses identical markup, so the extracted numbers match.
    assert pull(a) == pull(b)
```

- [ ] **Step 2: Add the active-state class for new pages to the nav strip**

Edit `src/ion/web/templates/cyab/_nav_strip.html` (created in Sub-plan B). Confirm the strip already lists `Scoping`, `Coverage`, `Audit` items pointing to `/cyab/scoping`, `/cyab/coverage`, `/cyab/audit`. If not, add them.

```html
{# Append to or update the existing list of nav items in _nav_strip.html #}
{% set nav_items = [
  ('/cyab',           'Overview'),
  ('/cyab/systems',   'Systems'),
  ('/cyab/scoping',   'Scoping'),
  ('/cyab/onboard',   'Onboard'),
  ('/cyab/coverage',  'Coverage'),
  ('/cyab/audit',     'Audit'),
] %}
<nav class="cyab-nav-strip tw-flex tw-gap-1 tw-mt-2 tw-mb-3 tw-border-b tw-border-slate-800">
  {% for href, label in nav_items %}
    <a href="{{ href }}"
       class="tw-px-3 tw-py-2 tw-text-[12px] tw-text-slate-400 hover:tw-text-cyan-300 tw-border-b-2 tw-border-transparent
              {% if request.url.path == href or (href != '/cyab' and request.url.path.startswith(href)) %}
                tw-text-cyan-300 tw-border-cyan-400
              {% endif %}">
      {{ label }}
    </a>
  {% endfor %}
</nav>
```

- [ ] **Step 3: Run the smoke test**

```bash
cd ~/ION && PYTHONPATH=src pytest tests/integration/test_cyab_phase1_smoke.py -v
```

Expected: PASS (8 cases: 6 page loads + nav-strip + engine-parity).

- [ ] **Step 4: Commit**

```bash
cd ~/ION && git add src/ion/web/templates/cyab/_nav_strip.html tests/integration/test_cyab_phase1_smoke.py
git -c user.name=tomo -c user.email=tomo@example.com commit -m "test(cyab): end-to-end smoke + nav-strip active-state for Sub-plan C pages"
```

---

## Task 13: Version bump to v0.19.0 (final) + CHANGELOG + tag

**Files:**

- Modify: `pyproject.toml`
- Modify: `src/ion/__init__.py`
- Modify: `CHANGELOG.md`

This sub-plan is the third and final of the v0.19.0 series. Sub-plans A and B shipped `v0.19.0-rc.1` and `v0.19.0-rc.2`; this plan ships the **final** `v0.19.0`.

- [ ] **Step 1: Bump version files**

```python
# pyproject.toml — line where version = "0.19.0-rc.2"
version = "0.19.0"
```

```python
# src/ion/__init__.py
"""ION - Documentation Template Management System."""
__version__ = "0.19.0"
```

- [ ] **Step 2: Add CHANGELOG entry**

Prepend to `CHANGELOG.md`:

```markdown
## v0.19.0 — 2026-05-04

### CyAB IA — Scoping + Coverage + Audit (Sub-plan C of 3) — completes the v0.19.0 series

- New `/cyab/scoping` page — anonymous stack-to-coverage questionnaire
  (~14 progressive questions) with live counter widget
  ("47 use cases · 12 threat-actor matches · 64% MITRE Initial Access
  coverage") and downloadable scoping-pack PDF.
- New shared scoring engine `cyab_scoping_engine.py` extends
  `cyab_assessment_service`. Single engine drives both `/cyab/scoping`
  and the wizard's Step 2 live counter — the spec's "scope for all"
  architecture.
- New `/cyab/coverage` matrix page — every system × seven data-health
  dimensions (ingestion, fields, intake, detections, audit, checklist,
  sign-off). Cells deep-link into the relevant per-system tab. Aggregates
  strip + filters by pillar / owner / "any red".
- New `/cyab/audit` page — chronological feed unioning sign-offs,
  checklist deltas, containment-authority changes, and system lifecycle
  events. Each sign-off row includes an "as-of-date" link to the
  onboarding pack PDF.
- "Convert to system" CTA on /cyab/scoping — stashes scoping answers in
  session and 303-redirects to the wizard with `?from_scoping=1`.

### v0.19.0 series — full picture (A + B + C)

- 7 top-level CyAB pages: `/cyab`, `/cyab/systems`, `/cyab/scoping`,
  `/cyab/onboard`, `/cyab/coverage`, `/cyab/audit`, `/cyab/systems/{id}`.
- 7-tab per-system page with sticky onboarding-progress header.
- 4-step onboarding wizard with autosave + scope-for-all live counter.
- New backend services: `cyab_data_health_service`, `cyab_scoping_engine`.
- `/cyab/studio` 301 redirected (drop in v0.20.0).

### Phase-2 deferrals (separate plans)

- Reconciliation drift Data Health panel (needs CMDB integration)
- Per-system Recommendations tab (live re-scoping as intake changes)
- Bulk operations on /cyab/coverage
- DB-backed scoping question editor (engine API is already swap-ready)
```

- [ ] **Step 3: Run the full test suite to confirm no regressions**

```bash
cd ~/ION && PYTHONPATH=src pytest -q
```

Expected: all tests pass (367 baseline + ~25 from Sub-plan A + ~25 from Sub-plan B + ~30 new from this sub-plan).

- [ ] **Step 4: Commit + tag**

```bash
cd ~/ION && git add pyproject.toml src/ion/__init__.py CHANGELOG.md
git -c user.name=tomo -c user.email=tomo@example.com commit -m "v0.19.0 — CyAB IA: scoping + coverage + audit (sub-plan C, completes series)"
git -c user.name=tomo -c user.email=tomo@example.com tag -a v0.19.0 -m "v0.19.0 — CyAB IA redesign (A+B+C)"
```

- [ ] **Step 5: Push (operator confirms before pushing)**

```bash
cd ~/ION && git push origin main && git push origin v0.19.0
```

(Operator may also want to publish a Docker image: `docker build -t ixion36/ion:0.19.0 . && docker push ixion36/ion:0.19.0`. Not part of the task — release-engineering decision.)

---

## Summary

13 tasks. Each ships an independent, tested commit. Total expected commits: 13 (one per task). Total new test cases: ~30 across 7 test files.

**Spec coverage check:**

| Spec section | Task |
|---|---|
| Shared question set + scoring engine extends `cyab_assessment_service` | 1 (catalogue) + 2 (engine) |
| Question set covers identity / endpoint / cloud / email / network edge / compliance | 1 (`stack_*` + `compliance_regime` IDs) |
| Scoring functions: `score_answers`, `summary_text`, `load_questions` | 2 |
| MITRE Initial Access coverage % | 2 (`mitre_coverage_pct`) |
| `/cyab/scoping` anonymous page | 3 |
| Progressive questionnaire UI | 3 (client-side reveal script) |
| Live counter widget on side | 3 + 4 (HTMX swap target) |
| Output summary view ("Recommended for your stack: …") | 4 (`_scoping_summary.html`) |
| Downloadable scoping-pack PDF | 5 (separate template per spec Q4) |
| `_render_scoping_pack_pdf` helper | 5 |
| `GET /api/cyab/scoping/pdf` endpoint | 5 (POST mounted; shim under `/api/cyab/scoping/pdf`) |
| "Convert to system" CTA → wizard pre-fill | 6 |
| Wizard Step 2 wired to same engine ("scope for all") | 7 |
| `/cyab/coverage` fleet matrix page | 8 + 9 |
| Cells deep-link into per-system tab | 9 (`_coverage_matrix.html`) |
| Filters: pillar / owner / "any red" | 8 (API) + 9 (UI) |
| Aggregates strip (% systems healthy / critical-missing / stale-ingestion) | 8 (API) + 9 (UI) |
| `/api/cyab/coverage/matrix` backend | 8 |
| `/cyab/audit` chronological feed page | 10 + 11 |
| Filters: system / user / action / date range | 10 (API) + 11 (UI) |
| Each row: who/when/what/link | 10 (event shape) + 11 (table) |
| "View onboarding pack PDF as of this date" | 11 (`pdf_link` from snapshot date) |
| `/api/cyab/audit/feed` backend | 10 |
| Cross-plan smoke (nav strip + 6 page loads + engine parity) | 12 |
| Release artefact (final v0.19.0) | 13 |

**Cross-plan dependencies (recap):**

| This plan needs… | From… | Used in… |
|---|---|---|
| `cyab_data_health_service` | Sub-plan A | Task 8 (matrix backend rolls per-system signals across the fleet) |
| Per-system page tabs (`/cyab/systems/{id}/tab/*`) | Sub-plan A | Task 9 (matrix cells deep-link `#tab=…`) |
| `/cyab/onboard` route + `_step2_intake.html` | Sub-plan B | Tasks 6 (convert CTA target) + 7 (wire counter into Step 2) |
| `_nav_strip.html` partial | Sub-plan B | Task 12 (extend with active-state for new pages) |

**Open assumptions to validate at Task 1:**

- The `tide_service.get_playbooks_with_kill_chains` function exists and returns a list of dicts (it's relied on by the existing `cyab_assessment_service` and is not new). If the call fails (e.g. ES unreachable in CI), the engine returns zero counts gracefully — confirmed by Task 2 Step 1 monkeypatch pattern.
- `CyabSnapshot.kind` is added by Sub-plan A (per Plan A Task 11 it's already used: `CyabSnapshot.kind == "signoff"`). If the column doesn't exist in the model when this plan starts, add it as a minor migration in Task 10's first step (`kind: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, default="snapshot")`).
- `change_log_service.list_events` may not exist with the assumed signature. Task 10 wraps the call in `try/except` and skips containment-change events rather than failing. If/when the service is built, no engine change is needed — events will start appearing in the feed automatically.
- `CyabSystem.archived_at` and `archived_by` may not exist yet. Task 8 and Task 10 use `getattr(...)` defensively so a missing column simply means no archive events appear — graceful degradation.
