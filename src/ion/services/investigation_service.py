"""Autonomous investigation service.

End-to-end pipeline that pulls OPEN alerts from Elasticsearch and runs:

    IOC extraction  →  TI enrichment (VirusTotal / Shodan / OpenCTI +
    optional AbuseIPDB)  →  MITRE tagging  →  LLM analysis (per-rule
    prompt template + memory context)  →  severity verdict  →  writeback
    to the Investigation row + the source alert.

The service is designed to sit behind a single-worker Postgres advisory
lock (``LOCK_INVESTIGATION_BG``) so uvicorn's N worker processes don't
duplicate each other's work.

Design notes
------------

* The ``Investigation`` table from ``ion.models.investigation`` is the
  job tracker; we never create a second "jobs" table.
* Every external call is best-effort — a VT rate-limit or an OpenCTI
  timeout never crashes the sweep. The alert either gets partial
  enrichment or an ``inconclusive`` verdict and moves on.
* PII anonymisation is wired via ``pii_anon_service``; when enabled, the
  redacted copy of the alert is what the LLM sees, and the resulting
  ``anon_map`` is threaded through the Ollama call so detokenisation is
  applied symmetrically.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ion.models.investigation import Investigation
from ion.storage import investigation_memory_repository as inv_repo
from ion.storage.database import (
    get_engine,
    get_session_factory,
    run_locked,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public exception
# ---------------------------------------------------------------------------


class InvestigationError(Exception):
    """Raised when an investigation cannot proceed (e.g. alert not found)."""


# ---------------------------------------------------------------------------
# Bob-authored post-investigation writebacks
# ---------------------------------------------------------------------------


_BOB_IOC_TYPE_MAP = {
    # Output-contract IOC types → ObservableType values
    "sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "url": "url",
    "file_path": "filename",
    "email": "email",
    "user": "user_account",
    "host": "hostname",
    "command_line": None,  # no Observable type; skip
    "registry_key": None,
    "process_name": None,
}


def _render_bob_alert_note(parsed: Dict[str, Any]) -> str:
    """Render a markdown Note body from the JSON envelope.

    Keeps it short and scannable — the full investigation row still has the
    detail; this is the timeline hook so analysts see Bob's take inline.
    """
    verdict = parsed.get("verdict", "inconclusive")
    confidence = parsed.get("confidence_level") or parsed.get("confidence") or "low"
    severity = parsed.get("severity", "low")
    summary = parsed.get("summary", "").strip()
    analyst = (parsed.get("analyst_explanation") or "").strip()

    mitre = parsed.get("mitre") or {}
    techs = mitre.get("techniques") or []
    tactics = mitre.get("tactics") or []

    actions = parsed.get("recommended_actions_structured") or []
    iocs = parsed.get("iocs") or []
    observations = parsed.get("key_observations") or []
    tuning = parsed.get("tuning_recommendation") or {}

    lines: list[str] = [
        f"**🤖 Bob (AI analyst) — `{verdict}`** · confidence `{confidence}` · severity `{severity}`",
    ]
    if summary:
        lines.extend(["", summary])
    if analyst:
        lines.extend(["", analyst])

    # v0.10.12: grounded evidence bullets. Each cites a specific field from
    # the alert payload so the verdict is auditable, not opaque.
    if observations:
        lines.extend(["", "**Key observations:**"])
        for obs in observations[:10]:
            if not isinstance(obs, dict):
                continue
            field = obs.get("field") or ""
            value = (obs.get("value") or "")[:200]
            sig = obs.get("significance") or ""
            if field and sig:
                lines.append(f"- `{field}` = `{value}` — {sig}")
            elif field:
                lines.append(f"- `{field}` = `{value}`")

    if techs or tactics:
        bits = []
        if techs:
            bits.append("Techniques: " + ", ".join(f"`{t}`" for t in techs))
        if tactics:
            bits.append("Tactics: " + ", ".join(f"`{t}`" for t in tactics))
        lines.extend(["", "**MITRE:** " + " · ".join(bits)])

    if iocs:
        lines.extend(["", "**IOCs:**"])
        for ioc in iocs[:10]:
            if not isinstance(ioc, dict):
                continue
            t = ioc.get("type") or "?"
            v = ioc.get("value") or "?"
            c = ioc.get("confidence") or "?"
            lines.append(f"- `{t}` `{v}` ({c})")

    if actions:
        lines.extend(["", "**Recommended actions:**"])
        for a in actions[:10]:
            if not isinstance(a, dict):
                continue
            p = a.get("priority", "p2")
            act = a.get("action", "")
            owner = a.get("owner", "soc")
            lines.append(f"- [{p}] ({owner}) {act}")

    if tuning.get("rule_needs_tuning"):
        sc = tuning.get("suggested_change") or "(none)"
        rat = tuning.get("rationale") or ""
        lines.extend([
            "",
            "**Tuning recommendation:** " + sc,
            rat,
        ])

    return "\n".join(l for l in lines if l is not None)


def _write_bob_outputs(
    *,
    db,
    alert_id: str,
    investigation_id: int,
    parsed: Dict[str, Any],
) -> None:
    """Write Bob's three post-investigation artefacts in one transaction.

    Runs inside the caller's transaction (does not commit). Best-effort —
    callers wrap this in try/except because a post-hook failure must not
    mark the investigation itself as failed.

    1. Alert Note (entity_type=ALERT, entity_id=alert_id) authored by Bob.
    2. AlertTriage.suggested_verdict / suggested_verdict_confidence.
    3. Observable rows for high-confidence IOCs, tagged source:bob.
    4. TuningProposal on FP verdict with a concrete suggested_change.

    v0.10.5: short-circuits when the alert's triage is already CLOSED or
    its case is CLOSED — prevents Bob from polluting closed-case timelines
    when an investigation is re-run (force=True, manual retrigger, etc.).
    """
    from ion.models.alert_triage import (
        AlertCase,
        AlertCaseStatus,
        AlertTriage,
        AlertTriageStatus,
        Note,
        NoteEntityType,
    )
    from ion.models.observable import Observable, ObservableType
    from ion.services.ai_user import get_bob_user_id

    # Closed-case / closed-triage guard. Bob should NOT append notes or
    # mutate observables for alerts whose triage or parent case has been
    # closed — those timelines are considered "done" and additional AI
    # commentary is noise.
    triage_guard = (
        db.query(AlertTriage)
        .filter(AlertTriage.es_alert_id == alert_id)
        .one_or_none()
    )
    if triage_guard is not None:
        if triage_guard.status == AlertTriageStatus.CLOSED:
            logger.info(
                "Skipping Bob writebacks for alert %s — triage is CLOSED",
                alert_id,
            )
            return
        if triage_guard.case_id:
            parent_case = (
                db.query(AlertCase)
                .filter(AlertCase.id == triage_guard.case_id)
                .one_or_none()
            )
            if parent_case is not None and parent_case.status == AlertCaseStatus.CLOSED:
                logger.info(
                    "Skipping Bob writebacks for alert %s — parent case %d is CLOSED",
                    alert_id, parent_case.id,
                )
                return

    bob_id = get_bob_user_id(db)
    if bob_id is None:
        logger.debug(
            "Bob service account not yet seeded; skipping AI-authored writebacks"
        )
        return

    # 1) Alert Note ---------------------------------------------------------
    note_body = _render_bob_alert_note(parsed)
    if note_body:
        note = Note(
            entity_type=NoteEntityType.ALERT,
            entity_id=str(alert_id),
            user_id=bob_id,
            content=note_body,
        )
        db.add(note)

    # 2) AlertTriage.suggested_verdict -------------------------------------
    triage = (
        db.query(AlertTriage)
        .filter(AlertTriage.es_alert_id == alert_id)
        .one_or_none()
    )
    verdict = parsed.get("verdict")
    conf = parsed.get("confidence_level") or "low"
    if triage is not None and verdict and verdict != "inconclusive":
        # Only write non-inconclusive verdicts with medium+ confidence so
        # the hint badge doesn't shout at analysts on weak signals.
        if conf in ("medium", "high"):
            # suggested_verdict uses CaseClosureReason naming — the
            # LLM contract already emits those exact values.
            triage.suggested_verdict = verdict
            triage.suggested_verdict_confidence = conf

    # 3) TuningProposal when Bob flagged FP with a concrete change ---------
    tuning = parsed.get("tuning_recommendation") or {}
    if (
        parsed.get("verdict") == "false_positive"
        and tuning.get("rule_needs_tuning")
        and (tuning.get("suggested_change") or "").strip()
    ):
        from ion.models.tuning_proposal import TuningProposal

        rule_id: Optional[str] = None
        # Prefer the triage row's rule_id via the investigation record later;
        # for now derive from the alert id if looks like a rule id, else None.
        proposal = TuningProposal(
            investigation_id=investigation_id,
            alert_id=str(alert_id),
            rule_id=rule_id,
            alert_prompt_template_id=None,
            rationale=(tuning.get("rationale") or None),
            suggested_change=str(tuning.get("suggested_change")),
            created_by_id=bob_id,
        )
        db.add(proposal)

    # 4) Observables for high-confidence IOCs ------------------------------
    iocs = parsed.get("iocs") or []
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        if ioc.get("confidence") != "high":
            continue
        raw_type = (ioc.get("type") or "").lower()
        obs_type_val = _BOB_IOC_TYPE_MAP.get(raw_type)
        if not obs_type_val:
            continue
        try:
            obs_type = ObservableType(obs_type_val)
        except ValueError:
            continue
        raw_value = (ioc.get("value") or "").strip()
        if not raw_value:
            continue
        try:
            normalized = Observable.normalize_value(obs_type, raw_value)
        except Exception:
            normalized = raw_value.lower()
        existing = (
            db.query(Observable)
            .filter(
                Observable.type == obs_type,
                Observable.normalized_value == normalized,
            )
            .one_or_none()
        )
        if existing is not None:
            existing.sighting_count = (existing.sighting_count or 0) + 1
            existing.last_seen = datetime.now(timezone.utc)
            tags = list(existing.tags or [])
            if "source:bob" not in tags:
                tags.append("source:bob")
                existing.tags = tags
            continue
        obs = Observable(
            type=obs_type,
            value=raw_value,
            normalized_value=normalized,
            tags=["source:bob", f"investigation:{investigation_id}"],
            notes=ioc.get("note") or None,
        )
        db.add(obs)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MITRE ATT&CK technique id pattern (T1234 or T1234.567)
_MITRE_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

# First-JSON-object extractor for LLM-response parsing — greedy so it
# grabs the whole outer object even if the model pads prose before/after.
_FIRST_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)

# Default sweep batch — kept in sync with the env-var default documented
# in the Integration Checklist.
_DEFAULT_MAX_PER_SWEEP = 50
_DEFAULT_SWEEP_INTERVAL_S = 900
# v0.17.3: bumped 120 → 300. Real investigation prompts on llama3.1:8b
# (full alert context + observables + history + MITRE chain) routinely
# take 130-180s; the previous 120s gate was firing in the middle of a
# legitimate response. Chat prompts are shorter and weren't affected.
# Override per-deployment via ION_INVESTIGATION_LLM_TIMEOUT_S env or the
# matching config attribute.
_DEFAULT_LLM_TIMEOUT_S = 300

# v0.19.3: memory-context guards. The v0.18.1 sanity sweep rescued a
# silent NameError that had been zeroing memory_ctx_md since v0.10.x;
# once the fix landed, accumulated investigation history started bloating
# the prompt. On 7-8B models that bloat tipped the balance and the model
# either timed out mid-inference or surrendered with `{}`. These two
# knobs bound the damage:
#   ION_INVESTIGATION_MEMORY_ENABLED — kill switch (default true)
#   ION_INVESTIGATION_MEMORY_MAX_CHARS — hard cap (default 1500)
_DEFAULT_MEMORY_MAX_CHARS = 1500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _build_memory_ctx(memory, alert: dict) -> str:
    """Build memory context for an alert with env-flag + length-bound guards.

    Returns "" when memory is None, when the env flag is false, when the
    builder raises, or when the output is empty. Otherwise truncates to
    ``ION_INVESTIGATION_MEMORY_MAX_CHARS`` (default 1500) so large
    accumulated histories don't blow past small-model context budgets.
    """
    enabled = os.environ.get("ION_INVESTIGATION_MEMORY_ENABLED", "true").lower()
    if enabled in ("false", "0", "no"):
        return ""
    if memory is None:
        return ""
    try:
        raw = memory.build_context_block_for_alert(alert) or ""
    except Exception as exc:
        logger.debug("memory context build failed: %s", exc)
        return ""
    try:
        max_chars = int(os.environ.get("ION_INVESTIGATION_MEMORY_MAX_CHARS",
                                       str(_DEFAULT_MEMORY_MAX_CHARS)))
    except ValueError:
        max_chars = _DEFAULT_MEMORY_MAX_CHARS
    if len(raw) > max_chars:
        return raw[:max_chars].rstrip() + "\n\n…(memory truncated for prompt budget)"
    return raw


def _get(alert: dict, *keys: str) -> Any:
    """Dot-path getter tolerating flat + nested + ``_source`` alert shapes."""
    if not isinstance(alert, dict):
        return None
    source = alert.get("_source") if isinstance(alert, dict) else None
    for key in keys:
        # Flat dotted key (ES 8.x alert indices commonly use these)
        if key in alert and alert[key] is not None:
            return alert[key]
        if isinstance(source, dict) and key in source and source[key] is not None:
            return source[key]
        # Nested traversal
        for root in (alert, source):
            if not isinstance(root, dict):
                continue
            cur: Any = root
            for part in key.split("."):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    cur = None
                    break
            if cur is not None:
                return cur
    return None


def _normalise_extracted_iocs(raw: Dict[str, Any]) -> Dict[str, List[str]]:
    """Map ``ioc_text_extractor`` output keys to the canonical ION shape.

    The extractor returns ``ipv4``/``ipv6``/``domains``/``urls``/``sha256``
    /``sha1``/``md5``/``emails``; this service exposes them as ``ips``
    (v4 + v6), ``domains``, ``urls``, ``sha256``, ``sha1``, ``md5`` and
    ``emails`` to match the contract documented in the service spec.
    """
    out: Dict[str, List[str]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "sha256": [],
        "sha1": [],
        "md5": [],
        "emails": [],
    }
    if not isinstance(raw, dict):
        return out

    v4 = raw.get("ipv4") or []
    v6 = raw.get("ipv6") or []
    out["ips"] = sorted({*(v4 or []), *(v6 or [])})
    for key in ("domains", "urls", "sha256", "sha1", "md5", "emails"):
        vals = raw.get(key) or []
        if isinstance(vals, list):
            out[key] = sorted({v for v in vals if v})
    return out


def _alert_to_text_blob(alert: dict) -> str:
    """Flatten an alert dict into a single text blob for IOC extraction.

    The text IOC extractor works on freeform text; we concatenate the
    most useful alert fields so hostnames, URLs, and hashes embedded in
    message/reason fields all get picked up.
    """
    try:
        return json.dumps(alert, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(alert)


def _extract_mitre_tags(alert: dict) -> List[str]:
    """Thin shim over ``mitre_navigator_service.tag_alert`` — kept so older
    call-sites in this module keep working without edits."""
    from ion.services.mitre_navigator_service import tag_alert
    return tag_alert(alert)


def _parse_llm_json(content: str) -> Dict[str, Any]:
    """Extract the first top-level JSON object out of a raw LLM response.

    Returns the canonical Output Contract envelope with all new fields plus
    backward-compatible ``verdict / severity / summary / recommended_actions
    / confidence`` aliases. Falls back to defaults when parsing fails so the
    investigation always has something to write back.
    """
    defaults: Dict[str, Any] = {
        "verdict": "inconclusive",
        "severity": "low",
        "summary": (content or "").strip()[:2000] or "LLM returned no content.",
        "recommended_actions": [],
        "recommended_actions_structured": [],
        "confidence": 0,
        "confidence_level": "low",
        "analyst_explanation": "",
        "technical_details": "",
        "mitre": {"tactics": [], "techniques": []},
        "iocs": [],
        "affected_assets": [],
        "timeline": [],
        "kill_chain_phase": "unknown",
        "containment_state": "not_applicable",
        "blast_radius": None,
        "references": [],
        "key_observations": [],
        "suggested_closure_reason": "insufficient_data",
        "tuning_recommendation": {
            "rule_needs_tuning": False,
            "rationale": None,
            "suggested_change": None,
        },
        "template_specific": {},
    }
    if not content:
        return defaults

    match = _FIRST_JSON_RE.search(content)
    if not match:
        return defaults

    raw_block = match.group(0)
    try:
        parsed = json.loads(raw_block)
    except (json.JSONDecodeError, ValueError):
        # Try a best-effort salvage — trim to the last closing brace that
        # balances the first opening one. LLMs sometimes emit trailing
        # commentary that breaks JSON parsing.
        depth = 0
        end = -1
        for i, ch in enumerate(raw_block):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end > 0:
            try:
                parsed = json.loads(raw_block[:end])
            except (json.JSONDecodeError, ValueError):
                return defaults
        else:
            return defaults

    if not isinstance(parsed, dict):
        return defaults

    verdict = str(parsed.get("verdict") or defaults["verdict"]).lower()
    severity = str(parsed.get("severity") or defaults["severity"]).lower()
    summary = parsed.get("summary") or defaults["summary"]

    # recommended_actions: old shape = list[str]; new shape = list[dict with
    # priority/action/owner]. Preserve the structured list and flatten to
    # strings for back-compat callers.
    actions_raw = parsed.get("recommended_actions") or []
    if isinstance(actions_raw, str):
        actions_raw = [actions_raw]
    if not isinstance(actions_raw, list):
        actions_raw = []
    actions_structured: list[dict] = []
    actions_flat: list[str] = []
    for a in actions_raw:
        if isinstance(a, dict):
            actions_structured.append({
                "priority": str(a.get("priority", "")).lower() or "p2",
                "action": str(a.get("action", "")).strip(),
                "owner": str(a.get("owner", "")).lower() or "soc",
            })
            if a.get("action"):
                actions_flat.append(str(a.get("action")).strip())
        elif a:
            s = str(a).strip()
            actions_flat.append(s)
            actions_structured.append({"priority": "p2", "action": s, "owner": "soc"})

    # Confidence: accept int 0-100 (old) or string low/medium/high (new).
    conf_raw = parsed.get("confidence", parsed.get("confidence_level", 0))
    conf_level = "low"
    conf_int = 0
    if isinstance(conf_raw, str):
        s = conf_raw.strip().lower()
        conf_level = {"low": "low", "medium": "medium", "med": "medium",
                      "high": "high"}.get(s, "low")
        conf_int = {"low": 30, "medium": 60, "high": 90}[conf_level]
    else:
        try:
            conf_int = max(0, min(100, int(conf_raw)))
        except (TypeError, ValueError):
            conf_int = 0
        if conf_int >= 75:
            conf_level = "high"
        elif conf_int >= 40:
            conf_level = "medium"
        else:
            conf_level = "low"

    verdict_map = {
        "true_positive": "true_positive",
        "true-positive": "true_positive",
        "tp": "true_positive",
        "false_positive": "false_positive",
        "false-positive": "false_positive",
        "fp": "false_positive",
        # Align "benign" legacy output with the new canonical
        # benign_true_positive so detection-engineering metrics stay coherent.
        "benign": "benign_true_positive",
        "benign_true_positive": "benign_true_positive",
        "benign-true-positive": "benign_true_positive",
        "btp": "benign_true_positive",
        "inconclusive": "inconclusive",
        "unknown": "inconclusive",
    }
    severity_map = {
        "info": "info",
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "med": "medium",
        "moderate": "medium",
        "high": "high",
        "critical": "critical",
        "crit": "critical",
    }
    verdict = verdict_map.get(verdict, "inconclusive")
    severity = severity_map.get(severity, "low")

    # Closure reason — default-derived from verdict so every investigation has
    # a tuning-pipeline-ready value even if the LLM skips the field.
    closure_default = {
        "true_positive": "true_positive",
        "false_positive": "false_positive",
        "benign_true_positive": "benign_true_positive",
        "inconclusive": "insufficient_data",
    }.get(verdict, "insufficient_data")
    closure = str(parsed.get("suggested_closure_reason") or closure_default).lower()
    valid_closures = {
        "true_positive", "false_positive", "benign_true_positive",
        "duplicate", "insufficient_data", "not_applicable",
    }
    if closure not in valid_closures:
        closure = closure_default

    # Tuning recommendation — object with rule_needs_tuning/rationale/
    # suggested_change. Guaranteed structure even when the LLM returns None.
    tuning = parsed.get("tuning_recommendation") or {}
    if not isinstance(tuning, dict):
        tuning = {}
    tuning_out = {
        "rule_needs_tuning": bool(tuning.get("rule_needs_tuning",
                                              verdict == "false_positive")),
        "rationale": tuning.get("rationale") or None,
        "suggested_change": tuning.get("suggested_change") or None,
    }

    mitre = parsed.get("mitre") or {}
    if not isinstance(mitre, dict):
        mitre = {}
    mitre_out = {
        "tactics": [str(t) for t in (mitre.get("tactics") or []) if t],
        "techniques": [str(t) for t in (mitre.get("techniques") or []) if t],
    }

    def _list_of(key: str) -> list:
        val = parsed.get(key) or []
        return val if isinstance(val, list) else []

    def _dict_or_none(key: str):
        val = parsed.get(key)
        return val if isinstance(val, dict) else None

    return {
        # --- Back-compat envelope keys (existing callers) ---
        "verdict": verdict,
        "severity": severity,
        "summary": str(summary)[:4000],
        "recommended_actions": actions_flat,
        "confidence": conf_int,
        # --- New envelope keys ---
        "confidence_level": conf_level,
        "recommended_actions_structured": actions_structured,
        "analyst_explanation": str(parsed.get("analyst_explanation") or "")[:4000],
        "technical_details": str(parsed.get("technical_details") or "")[:8000],
        "mitre": mitre_out,
        "iocs": _list_of("iocs"),
        "affected_assets": _list_of("affected_assets"),
        "timeline": _list_of("timeline"),
        "kill_chain_phase": str(parsed.get("kill_chain_phase") or "unknown").lower(),
        "containment_state": str(parsed.get("containment_state") or "not_applicable").lower(),
        "blast_radius": _dict_or_none("blast_radius"),
        "references": _list_of("references"),
        "key_observations": [
            {
                "field": str(o.get("field", "")).strip(),
                "value": str(o.get("value", ""))[:500],
                "significance": str(o.get("significance", ""))[:500],
            }
            for o in _list_of("key_observations")
            if isinstance(o, dict) and o.get("field")
        ],
        "suggested_closure_reason": closure,
        "tuning_recommendation": tuning_out,
        "template_specific": _dict_or_none("template_specific") or {},
    }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class InvestigationService:
    """Autonomous investigation pipeline for OPEN ES alerts."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._loop_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ #
    # Dependency accessors (lazy, so missing services fail softly)
    # ------------------------------------------------------------------ #

    def _get_es(self):
        from ion.services.elasticsearch_service import ElasticsearchService
        return ElasticsearchService()

    def _get_ollama(self):
        from ion.services.ollama_service import get_ollama_service
        return get_ollama_service()

    def _get_vt(self):
        try:
            from ion.services.virustotal_service import get_virustotal_service
            return get_virustotal_service()
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("VirusTotal service unavailable: %s", exc)
            return None

    def _get_shodan(self):
        try:
            from ion.services.shodan_service import get_shodan_service
            return get_shodan_service()
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("Shodan service unavailable: %s", exc)
            return None

    def _get_opencti(self):
        try:
            from ion.services.opencti_service import get_opencti_service
            return get_opencti_service()
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("OpenCTI service unavailable: %s", exc)
            return None

    def _get_abuseipdb(self):
        """Best-effort probe for an AbuseIPDB module — returns (service, fn) or None.

        The spec says "check if a module/function exists via importlib" —
        AbuseIPDB is enabled in .env but the dedicated service module may
        not have landed yet. We accept a handful of naming conventions and
        degrade gracefully when none are found.
        """
        import importlib

        for mod_name, factory_name, method_name in (
            ("ion.services.abuseipdb_service", "get_abuseipdb_service", "lookup_ip"),
            ("ion.services.abuse_ipdb_service", "get_abuseipdb_service", "lookup_ip"),
            ("ion.services.abuseipdb_service", "get_abuse_ipdb_service", "check_ip"),
        ):
            try:
                mod = importlib.import_module(mod_name)
            except ImportError:
                continue
            factory = getattr(mod, factory_name, None)
            if factory is None:
                continue
            try:
                service = factory()
            except Exception:  # pragma: no cover — defensive
                continue
            fn = getattr(service, method_name, None)
            if callable(fn):
                return service, fn
        return None

    def _get_pii_anon(self):
        try:
            from ion.services.pii_anon_service import get_pii_anon_service
            return get_pii_anon_service()
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("PII anon service unavailable: %s", exc)
            return None

    def _get_alert_prompt_service(self, db):
        from ion.services.alert_prompt_service import AlertPromptService
        return AlertPromptService(db)

    # ------------------------------------------------------------------ #
    # Alert pull
    # ------------------------------------------------------------------ #

    async def _fetch_alert(self, alert_id: str) -> Optional[dict]:
        """Fetch a single alert by ES ``_id`` and return the ``_source`` dict.

        Falls back to ``get_alerts_by_ids`` (which returns parsed
        ElasticsearchAlert objects) when a dedicated ``get_alert`` helper
        isn't exposed.
        """
        es = self._get_es()
        # Direct ES _search for richer raw shape.
        try:
            body = {
                "size": 1,
                "query": {"ids": {"values": [alert_id]}},
            }
            result = await es._request(
                "POST",
                f"/{es.alert_index}/_search",
                json=body,
            )
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                hit = hits[0]
                source = dict(hit.get("_source") or {})
                source["_id"] = hit.get("_id") or alert_id
                source["_index"] = hit.get("_index")
                return source
        except Exception as exc:
            logger.debug("ES direct lookup failed for %s: %s", alert_id, exc)

        # Fallback: parsed helper.
        try:
            alerts = await es.get_alerts_by_ids([alert_id])
        except Exception as exc:
            logger.warning("Failed to fetch alert %s from ES: %s", alert_id, exc)
            return None
        if not alerts:
            return None
        parsed = alerts[0]
        raw = dict(parsed.raw_data or {})
        raw["_id"] = parsed.id
        # Flatten a few parsed fields into the top-level so the rest of the
        # pipeline finds them via _get().
        raw.setdefault("rule.name", parsed.rule_name)
        raw.setdefault("host.name", parsed.host)
        raw.setdefault("user.name", parsed.user)
        raw.setdefault("source.ip", parsed.source_ip)
        raw.setdefault("destination.ip", parsed.destination_ip)
        return raw

    async def _fetch_open_alerts(self, max_alerts: int) -> List[dict]:
        """Pull up to ``max_alerts`` open alerts, newest first."""
        es = self._get_es()
        try:
            alerts = await es.get_alerts(
                status="open",
                limit=max_alerts,
                hours=168,  # 1 week window — broad enough for backlogs
                include_closed=False,
            )
        except Exception as exc:
            logger.warning("Sweep: failed to pull open alerts: %s", exc)
            return []

        out: List[dict] = []
        for a in alerts:
            raw = dict(a.raw_data or {})
            raw["_id"] = a.id
            raw.setdefault("rule.name", a.rule_name)
            raw.setdefault("host.name", a.host)
            raw.setdefault("user.name", a.user)
            raw.setdefault("source.ip", a.source_ip)
            raw.setdefault("destination.ip", a.destination_ip)
            out.append(raw)
        return out

    # ------------------------------------------------------------------ #
    # Writeback
    # ------------------------------------------------------------------ #

    async def _writeback_alert(
        self,
        alert_id: str,
        inv_id: int,
        verdict: str,
        severity: str,
        mitre_tags: List[str],
        summary: str,
    ) -> None:
        """Best-effort alert writeback. Never raises.

        Delegates to ``ElasticsearchService.update_alert`` which handles the
        painless ``_update_by_query`` and gracefully returns False for
        Kibana-managed ``.alerts-*`` indices that block direct writes.
        """
        es = self._get_es()
        payload = {
            "ion.investigation_id": inv_id,
            "ion.verdict": verdict,
            "ion.severity_assessment": severity,
            "ion.mitre_tags": mitre_tags,
            "ion.investigated_at": _utcnow().isoformat(),
            "ion.summary": (summary or "")[:2000],
        }
        try:
            ok = await es.update_alert(alert_id, payload)
            if not ok:
                logger.debug(
                    "Alert writeback not applied for %s (managed index or no matching doc)",
                    alert_id,
                )
        except Exception as exc:
            logger.warning("Alert writeback raised for %s: %s", alert_id, exc)

    async def _post_to_case(
        self,
        alert_id: str,
        inv_id: int,
        verdict: Optional[str],
        severity: Optional[str],
        summary: Optional[str],
        actions: Optional[List[str]] = None,
        mitre_tags: Optional[List[str]] = None,
        iocs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Best-effort: attach investigation result to the alert's case.

        Writes an ION ``Note`` row on the case and, if a ``kibana_case_id``
        is linked, posts the same text as a Kibana Cases comment. Never
        raises out of this method.
        """
        try:
            from ion.models.alert_triage import (
                AlertCase,
                AlertCaseStatus,
                AlertTriage,
                AlertTriageStatus,
                Note,
                NoteEntityType,
            )
            from ion.storage.database import get_session_factory

            factory = get_session_factory()
            case = None
            db = factory()
            kibana_case_id: Optional[str] = None
            kibana_case_version: Optional[str] = None
            case_moved_to_ack = False
            triage_moved_to_ack = False
            try:
                triage = db.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
                if triage is None or triage.case_id is None:
                    logger.debug("No case linked for alert %s — skipping case note", alert_id)
                    return
                case = db.get(AlertCase, triage.case_id)
                if case is None:
                    return

                # Leading HTML-comment marker so the Kibana→ION comment sync
                # can recognise round-tripped ION-originated content and skip
                # creating a duplicate Note for it.
                body_lines = [
                    f"<!-- ion-origin: investigation:{inv_id} -->",
                    f"### Investigation #{inv_id} — {verdict or 'inconclusive'}",
                    "",
                    f"**Severity:** {severity or 'unknown'}",
                ]
                if mitre_tags:
                    body_lines.append(f"**MITRE:** {', '.join(mitre_tags)}")
                body_lines.append("")
                body_lines.append((summary or "").strip() or "_(no summary)_")
                if actions:
                    body_lines.append("")
                    body_lines.append("**Recommended actions:**")
                    for a in actions:
                        body_lines.append(f"- {a}")
                body_lines.append("")
                body_lines.append(f"_Alert: `{alert_id}` · Generated by ION autonomous investigation._")
                note_content = "\n".join(body_lines)

                note = Note(
                    entity_type=NoteEntityType.CASE,
                    entity_id=str(case.id),
                    user_id=self._get_system_user_id(db),
                    content=note_content,
                )
                db.add(note)

                # Merge investigation IOCs into case.observables (dedup by
                # type+value). Shape matches extract_observables_from_raw.
                if iocs:
                    existing = list(case.observables or [])
                    seen = {(o.get("type"), o.get("value")) for o in existing if isinstance(o, dict)}
                    type_map = {
                        "ips": "ip", "ip": "ip",
                        "domains": "domain", "domain": "domain",
                        "urls": "url", "url": "url",
                        "sha256": "sha256", "sha1": "sha1", "md5": "md5",
                        "emails": "email", "email": "email",
                    }
                    added_count = 0
                    for k, vals in iocs.items():
                        obs_type = type_map.get(k)
                        if not obs_type or not vals:
                            continue
                        for v in (vals if isinstance(vals, list) else [vals]):
                            if not isinstance(v, str) or not v:
                                continue
                            key = (obs_type, v)
                            if key in seen:
                                continue
                            seen.add(key)
                            existing.append({
                                "type": obs_type,
                                "value": v,
                                "source": "investigation",
                            })
                            added_count += 1
                    if added_count:
                        case.observables = existing
                        logger.debug(
                            "Merged %d new observables into case %s from inv #%d",
                            added_count, case.case_number, inv_id,
                        )

                # Move alert triage to ACKNOWLEDGED so analysts know the AI
                # has done its pass and it's their turn.
                if triage.status == AlertTriageStatus.OPEN:
                    triage.status = AlertTriageStatus.ACKNOWLEDGED
                    triage_moved_to_ack = True

                # Move case to ACKNOWLEDGED iff currently OPEN (never
                # downgrade from CLOSED — analyst has the final say).
                if case.status == AlertCaseStatus.OPEN:
                    case.status = AlertCaseStatus.ACKNOWLEDGED
                    case_moved_to_ack = True

                db.commit()
                kibana_case_id = case.kibana_case_id
                kibana_case_version = case.kibana_case_version
            except Exception as exc:
                db.rollback()
                logger.warning("Failed to write case note for %s: %s", alert_id, exc)
                return
            finally:
                db.close()

            # Push ES alert status transition (acknowledged) — helps Kibana
            # Security UI reflect that this alert is no longer untouched.
            if triage_moved_to_ack:
                try:
                    es = self._get_es()
                    await es.update_alert_workflow_status([alert_id], ion_status="acknowledged")
                except Exception as exc:
                    logger.debug("ES workflow-status update failed for %s: %s", alert_id, exc)

            if not kibana_case_id:
                return

            # Post Kibana comment + optional status move
            try:
                from ion.services.kibana_cases_service import get_kibana_cases_service
                svc = get_kibana_cases_service()
                if svc and getattr(svc, "enabled", False):
                    svc.add_comment(kibana_case_id, note_content, comment_type="user")
                    if case_moved_to_ack and kibana_case_version:
                        try:
                            svc.update_case(
                                case_id=kibana_case_id,
                                version=kibana_case_version,
                                status="in-progress",
                            )
                        except Exception as exc:
                            logger.debug("Kibana case status move failed for %s: %s",
                                         kibana_case_id, exc)
            except Exception as exc:
                logger.debug("Kibana case-comment post failed for %s: %s", alert_id, exc)
        except Exception as exc:
            logger.warning("_post_to_case raised for %s: %s", alert_id, exc)

    def _get_system_user_id(self, db) -> int:
        """Return the id of the system/admin user for auto-authored Notes."""
        try:
            from ion.models.user import User
            admin = db.query(User).filter_by(username="admin").first()
            if admin:
                return admin.id
        except Exception:
            pass
        return 1

    # ------------------------------------------------------------------ #
    # Existing-investigation check
    # ------------------------------------------------------------------ #

    def _find_recent_investigation(self, alert_id: str) -> Optional[Investigation]:
        """Return the most recent pending/running/completed investigation for this alert, or None.

        Uses a direct SQL query keyed on ``alert_id_ref`` — avoids the
        full-table scan ``list_investigations`` with an empty filter
        would perform.
        """
        from sqlalchemy import desc, select

        factory = get_session_factory(get_engine())
        db = factory()
        try:
            stmt = (
                select(Investigation)
                .where(
                    Investigation.alert_id_ref == alert_id,
                    Investigation.status.in_(("pending", "running", "completed")),
                )
                .order_by(desc(Investigation.created_at))
                .limit(1)
            )
            inv = db.execute(stmt).scalar_one_or_none()
            if inv is not None:
                db.expunge(inv)
            return inv
        finally:
            db.close()

    # ------------------------------------------------------------------ #
    # TI enrichment
    # ------------------------------------------------------------------ #

    async def _enrich_iocs(
        self,
        iocs: Dict[str, List[str]],
        inv_id: int,
    ) -> Dict[str, Dict[str, Any]]:
        """Run all configured TI enrichers in parallel; return nested dict.

        Shape::

            {
              "ip":     {"1.2.3.4": {...}},
              "domain": {"evil.example": {...}},
              "url":    {"http://...": {...}},
              "hash":   {"<sha>": {...}},
            }

        Every IOC touched (even those with no TI hits) gets an
        ``upsert_ioc_sighting`` call so the memory table grows with every
        investigation.
        """
        enrichment: Dict[str, Dict[str, Any]] = {
            "ip": {},
            "domain": {},
            "url": {},
            "hash": {},
        }

        vt = self._get_vt()
        shodan = self._get_shodan()
        opencti = self._get_opencti()
        abuse = self._get_abuseipdb()

        async def _safe_call(coro, label: str) -> Optional[Dict[str, Any]]:
            try:
                return await asyncio.wait_for(coro, timeout=30)
            except asyncio.TimeoutError:
                logger.debug("%s timed out", label)
                return None
            except Exception as exc:
                logger.debug("%s failed: %s", label, exc)
                return None

        factory = get_session_factory(get_engine())

        def _record(ioc_type: str, ioc_value: str, snapshot: Dict[str, Any]) -> None:
            db = factory()
            try:
                inv_repo.upsert_ioc_sighting(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    db=db,
                    reputation=snapshot,
                    inv_id=inv_id,
                )
                db.commit()
            except Exception as exc:
                logger.debug("upsert_ioc_sighting failed (%s %s): %s", ioc_type, ioc_value, exc)
                db.rollback()
            finally:
                db.close()

        # --- IPs
        for ip in iocs.get("ips", []):
            tasks = {}
            if vt is not None and getattr(vt, "is_configured", False):
                tasks["virustotal"] = _safe_call(vt.lookup_ip(ip), f"VT ip {ip}")
            if shodan is not None and getattr(shodan, "is_configured", False):
                tasks["shodan"] = _safe_call(shodan.lookup_ip(ip), f"Shodan {ip}")
            if abuse is not None:
                _svc, abuse_fn = abuse
                tasks["abuseipdb"] = _safe_call(abuse_fn(ip), f"AbuseIPDB {ip}")

            if not tasks:
                _record("ip", ip, {})
                continue

            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            snap: Dict[str, Any] = {}
            for label, res in zip(tasks.keys(), results):
                if isinstance(res, Exception):
                    snap[label] = {"error": str(res)[:200]}
                elif res is not None:
                    snap[label] = res
            enrichment["ip"][ip] = snap
            _record("ip", ip, snap)

        # --- Domains
        for domain in iocs.get("domains", []):
            tasks = {}
            if vt is not None and getattr(vt, "is_configured", False):
                tasks["virustotal"] = _safe_call(vt.lookup_domain(domain), f"VT domain {domain}")
            if opencti is not None and getattr(opencti, "is_configured", False):
                tasks["opencti"] = _safe_call(
                    opencti.enrich_observable("domain-name", domain),
                    f"OpenCTI domain {domain}",
                )
            if not tasks:
                _record("domain", domain, {})
                continue
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            snap = {}
            for label, res in zip(tasks.keys(), results):
                if isinstance(res, Exception):
                    snap[label] = {"error": str(res)[:200]}
                elif res is not None:
                    snap[label] = res
            enrichment["domain"][domain] = snap
            _record("domain", domain, snap)

        # --- URLs
        for url in iocs.get("urls", []):
            if vt is not None and getattr(vt, "is_configured", False):
                res = await _safe_call(vt.lookup_url(url), f"VT url {url}")
                snap = {"virustotal": res} if res is not None else {}
            else:
                snap = {}
            enrichment["url"][url] = snap
            _record("url", url, snap)

        # --- Hashes (SHA256 / SHA1 / MD5)
        hash_specs = [
            ("sha256", iocs.get("sha256", []), "file-sha256"),
            ("sha1",   iocs.get("sha1",   []), "file-sha1"),
            ("md5",    iocs.get("md5",    []), "file-md5"),
        ]
        for ioc_type, values, opencti_type in hash_specs:
            for h in values:
                tasks = {}
                if vt is not None and getattr(vt, "is_configured", False):
                    tasks["virustotal"] = _safe_call(
                        vt.lookup_file_hash(h), f"VT {ioc_type} {h}",
                    )
                if opencti is not None and getattr(opencti, "is_configured", False):
                    tasks["opencti"] = _safe_call(
                        opencti.enrich_observable(opencti_type, h),
                        f"OpenCTI {ioc_type} {h}",
                    )
                if not tasks:
                    _record(ioc_type, h, {})
                    continue
                results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                snap = {}
                for label, res in zip(tasks.keys(), results):
                    if isinstance(res, Exception):
                        snap[label] = {"error": str(res)[:200]}
                    elif res is not None:
                        snap[label] = res
                enrichment["hash"][h] = snap
                _record(ioc_type, h, snap)

        return enrichment

    # ------------------------------------------------------------------ #
    # Prompt / LLM
    # ------------------------------------------------------------------ #

    def _build_alert_summary(self, alert: dict) -> Dict[str, Any]:
        """Build the structured alert payload the LLM sees.

        Only emits fields that are actually present — avoids null noise
        that inflates prompt tokens and trains the model to hallucinate
        values for missing keys. Every field here should be something an
        analyst would visually inspect on Kibana's alert detail page.
        """
        # (key, dot-path aliases) — first non-empty wins
        field_map: List[Tuple[str, Tuple[str, ...]]] = [
            # Envelope
            ("alert_id", ("_id",)),
            ("timestamp", ("@timestamp", "timestamp")),
            ("severity_original", (
                "kibana.alert.severity", "event.severity",
                "signal.rule.severity", "severity",
            )),
            # Rule context — what was the detection looking for?
            ("rule_name", ("rule.name", "kibana.alert.rule.name", "signal.rule.name")),
            ("rule_id", ("rule.id", "kibana.alert.rule.rule_id", "signal.rule.rule_id")),
            ("rule_query", (
                "kibana.alert.rule.parameters.query",
                "signal.rule.query", "rule.query",
            )),
            ("alert_reason", ("kibana.alert.reason",)),
            # Host / user
            ("host", ("host.name", "host_name", "host")),
            ("host_os", ("host.os.name", "host.os.family")),
            ("user_name", ("user.name", "user_name")),
            ("user_domain", ("user.domain",)),
            ("user_email", ("user.email",)),
            ("target_user", ("user.target.name", "user.target.full_name")),
            # Network
            ("source_ip", ("source.ip", "source_ip")),
            ("source_port", ("source.port",)),
            ("destination_ip", ("destination.ip", "destination_ip")),
            ("destination_port", ("destination.port",)),
            ("network_transport", ("network.transport",)),
            ("network_protocol", ("network.protocol",)),
            ("network_bytes", ("network.bytes",)),
            ("network_community_id", ("network.community_id",)),
            # Process / file — the single most load-bearing set for EDR alerts
            ("process_name", ("process.name",)),
            ("process_command_line", ("process.command_line",)),
            ("process_executable", ("process.executable",)),
            ("process_pid", ("process.pid",)),
            ("process_hash_sha256", ("process.hash.sha256",)),
            ("parent_process_name", ("process.parent.name",)),
            ("parent_process_command_line", ("process.parent.command_line",)),
            ("parent_process_pid", ("process.parent.pid",)),
            ("file_path", ("file.path",)),
            ("file_name", ("file.name",)),
            ("file_hash_sha256", ("file.hash.sha256",)),
            ("file_hash_md5", ("file.hash.md5",)),
            # URL / DNS / HTTP
            ("url_full", ("url.full", "url.original")),
            ("url_domain", ("url.domain",)),
            ("dns_question_name", ("dns.question.name",)),
            ("dns_question_type", ("dns.question.type",)),
            ("http_request_method", ("http.request.method",)),
            ("http_response_status", ("http.response.status_code",)),
            ("user_agent", ("user_agent.original",)),
            # Event classification
            ("event_action", ("event.action",)),
            ("event_category", ("event.category",)),
            ("event_code", ("event.code",)),
            ("event_outcome", ("event.outcome",)),
            ("event_module", ("event.module",)),
            ("event_dataset", ("event.dataset",)),
        ]
        out: Dict[str, Any] = {}
        for out_key, aliases in field_map:
            val = _get(alert, *aliases)
            # Drop empty strings, None, empty lists — keep 0, False, "false"
            if val is None:
                continue
            if isinstance(val, str) and not val.strip():
                continue
            if isinstance(val, (list, dict)) and not val:
                continue
            out[out_key] = val
        return out

    def _build_user_prompt_body(
        self,
        alert_summary: Dict[str, Any],
        enrichment: Dict[str, Dict[str, Any]],
        mitre_tags: List[str],
        memory_ctx_md: str,
        extracted_iocs: Dict[str, List[str]],
    ) -> str:
        """Assemble the user-message payload for the LLM.

        Deliberately emits a JSON block (pretty-printed for readability
        in logs) followed by a short instruction tail that specifies the
        JSON output contract.
        """
        body = {
            "alert_summary": alert_summary,
            "enrichment": enrichment,
            "mitre_tags": mitre_tags,
            "memory_context": memory_ctx_md,
            "extracted_iocs": extracted_iocs,
        }
        try:
            dumped = json.dumps(body, default=str, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            dumped = str(body)

        tail = (
            "\n\nRespond with ONE JSON object conforming to the Output Contract "
            "in the system message. No markdown fences, no prose outside JSON."
        )
        return dumped + tail

    async def _single_llm_call(
        self,
        system_prompt: str,
        user_body: str,
        anon_map: Any,
        seed: int,
    ) -> Tuple[Dict[str, Any], str, Optional[int], int, str]:
        """One pass through Ollama — parsed + raw + telemetry.

        The seed value controls which sampling path Ollama takes. Pair with
        the other determinism knobs (temperature=0, top_p=0.1, top_k=1) so
        that two different seeds actually *explore* different verdicts
        instead of converging on the same argmax token stream.
        """
        ollama = self._get_ollama()
        if ollama is None:
            raise InvestigationError("Ollama service is not available")

        kwargs: Dict[str, Any] = {
            "messages": [{"role": "user", "content": user_body}],
            "system_prompt": system_prompt,
            "context_type": "security",
            "user_id": 0,
            # v0.10.11: deterministic-ish sampling. Same alert+seed in =
            # roughly the same verdict out (small variance). Earlier this
            # was temperature=0.0 + top_p=0.1 + top_k=1 + response_format=
            # "json" — that combo over-constrained the decoder, causing
            # the model to emit just `{}` as the simplest valid JSON
            # completion when the prompt was at all ambiguous (v0.17.3
            # bug report). Relaxed to 0.2 / 0.9 / 40, with `seed` still
            # supplied per call below for cross-run reproducibility.
            "temperature": 0.2,
            # v0.19.3: 2048 -> 4096. With memory context now actually
            # populated (v0.18.1 fixed the silent NameError that had been
            # zeroing it out), the prompt is bigger and 7-8B models were
            # running out of generation budget mid-JSON, leaving the parser
            # to fall back to `{}`. 4096 gives the envelope room to close.
            "max_tokens": 4096,
        }
        try:
            import inspect
            sig = inspect.signature(ollama.chat)
            if "anon_map" in sig.parameters:
                kwargs["anon_map"] = anon_map
            if "bypass_queue" in sig.parameters:
                # Background investigations run in per-thread event loops;
                # the shared queue's asyncio primitives bind to one loop and
                # fail cross-loop. Skipping the queue here is safe because
                # Ollama itself limits concurrent inference.
                kwargs["bypass_queue"] = True
            if "response_format" in sig.parameters:
                kwargs["response_format"] = "json"
            if "seed" in sig.parameters:
                kwargs["seed"] = seed
            if "top_p" in sig.parameters:
                kwargs["top_p"] = 0.9
            if "top_k" in sig.parameters:
                kwargs["top_k"] = 40
        except (TypeError, ValueError):
            pass

        # Resolution order: ION_INVESTIGATION_LLM_TIMEOUT_S env (operator
        # tuning knob, no rebuild needed) → config attr → module default.
        timeout_s = _DEFAULT_LLM_TIMEOUT_S
        import os as _os
        try:
            env_v = _os.environ.get("ION_INVESTIGATION_LLM_TIMEOUT_S")
            if env_v and env_v.strip():
                timeout_s = int(env_v.strip())
        except Exception:
            pass
        try:
            from ion.core.config import get_config
            cfg = get_config()
            cfg_v = getattr(cfg, "investigation_llm_timeout_s", None)
            if cfg_v:
                timeout_s = int(cfg_v)
        except Exception:
            pass

        started = time.monotonic()
        try:
            resp = await asyncio.wait_for(ollama.chat(**kwargs), timeout=timeout_s)
        except asyncio.TimeoutError:
            raise InvestigationError(f"LLM call timed out after {timeout_s}s")
        duration_ms = int((time.monotonic() - started) * 1000)

        content = (resp or {}).get("content") or ""
        model = (resp or {}).get("model") or ""
        eval_count = (resp or {}).get("eval_count")
        parsed = _parse_llm_json(content)
        return parsed, model, eval_count, duration_ms, content

    async def _call_llm(
        self,
        system_prompt: str,
        user_body: str,
        anon_map: Any,
    ) -> Tuple[Dict[str, Any], str, Optional[int], int, str]:
        """Run the LLM call; return (parsed, model_name, eval_count, duration_ms, raw_content).

        v0.10.12: self-consistency sampling gated on ION_INVESTIGATION_SAMPLES.
        Default is 1 (single-seed run, cheapest). Setting 2 runs two passes
        with different seeds; on agreement the first result is returned with
        confidence boosted one level. On disagreement the verdict downgrades
        to ``inconclusive`` — two deterministic runs producing different
        verdicts means the prompt is genuinely ambiguous, and forcing a
        confident wrong answer is worse than admitting we don't know.
        """
        import os

        try:
            samples = int(os.environ.get("ION_INVESTIGATION_SAMPLES", "1"))
        except (TypeError, ValueError):
            samples = 1
        samples = max(1, min(3, samples))

        # Single-sample fast path — indistinguishable from v0.10.11 behaviour.
        if samples == 1:
            return await self._single_llm_call(
                system_prompt, user_body, anon_map, seed=42,
            )

        # Multi-sample path. Seeds chosen to be deterministic across runs
        # (so two investigations of the same alert hit the same sample
        # stream) but far apart in hash space to encourage verdict diversity
        # when the prompt is ambiguous.
        seed_pool = [42, 1337, 2024]
        seeds = seed_pool[:samples]
        results: List[Tuple[Dict[str, Any], str, Optional[int], int, str]] = []
        for s in seeds:
            results.append(
                await self._single_llm_call(
                    system_prompt, user_body, anon_map, seed=s,
                )
            )

        verdicts = [r[0].get("verdict", "inconclusive") for r in results]
        verdict_set = set(verdicts)
        total_ms = sum(r[3] for r in results)
        # Merged raw content preserves every sample so the training loop
        # can see exactly what each seed produced. Separator chosen to not
        # collide with JSON syntax or typical prose.
        merged_content = "\n\n===SAMPLE-BOUNDARY===\n\n".join(r[4] for r in results)

        if len(verdict_set) == 1:
            # Consensus — every sample agreed. Return first, bump confidence.
            parsed, model, eval_count, _first_ms, _first_content = results[0]
            level = parsed.get("confidence_level", "low")
            bumped = {"low": "medium", "medium": "high", "high": "high"}.get(level, level)
            parsed["confidence_level"] = bumped
            parsed["sampling"] = {
                "samples": samples,
                "verdicts": verdicts,
                "consensus": True,
            }
            logger.info(
                "Self-consistency OK — %d samples agreed on verdict=%s",
                samples, verdicts[0],
            )
            return parsed, model, eval_count, total_ms, merged_content

        # Disagreement — two deterministic runs produced different verdicts.
        # Don't paper over it with a coin flip; mark inconclusive and let an
        # analyst decide. The AIFeedback ledger will eventually surface
        # which templates trigger disagreement often — those are the prompts
        # that need tuning.
        parsed, model, eval_count, _first_ms, _first_content = results[0]
        parsed["verdict"] = "inconclusive"
        parsed["confidence_level"] = "low"
        parsed["confidence"] = 20
        parsed["suggested_closure_reason"] = "insufficient_data"
        split_note = f"[Self-consistency disagreement — samples: {', '.join(verdicts)}] "
        parsed["summary"] = split_note + (parsed.get("summary") or "")
        parsed["sampling"] = {
            "samples": samples,
            "verdicts": verdicts,
            "consensus": False,
        }
        logger.info(
            "Self-consistency FAILED — %d samples produced %s; verdict forced to inconclusive",
            samples, verdicts,
        )
        return parsed, model, eval_count, total_ms, merged_content

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #

    async def investigate_alert(
        self,
        alert_id: str,
        force: bool = False,
        triggered_by: str = "auto",
    ) -> Investigation:
        """Run the full pipeline for a single alert and return the DB row."""
        # 1) Pull alert
        alert = await self._fetch_alert(alert_id)
        if alert is None:
            raise InvestigationError("alert not found")

        # 2) FP short-circuit
        memory = None
        try:
            from ion.services.investigation_memory_service import (
                get_investigation_memory_service,
            )
            memory = get_investigation_memory_service()
            is_fp, fp_row = memory.is_likely_fp(alert)
        except Exception as exc:
            logger.debug("is_likely_fp probe failed: %s", exc)
            is_fp, fp_row = False, None

        # 3) Dedup check
        if not force:
            existing = self._find_recent_investigation(alert_id)
            if existing is not None:
                logger.info(
                    "investigate_alert: existing %s investigation (id=%s) for %s; returning",
                    existing.status, existing.id, alert_id,
                )
                return existing

        # 4) record_investigation_start
        factory = get_session_factory(get_engine())
        db = factory()
        try:
            inv = inv_repo.record_investigation_start(alert, db)
            inv.status = "running"
            db.commit()
            inv_id = inv.id
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        overall_start = time.monotonic()

        # FP fast-path: no LLM, just record and return.
        if is_fp and fp_row is not None:
            fp_reason = getattr(fp_row, "reason", "") or "matched FP signature"
            summary = f"Matched FP signature: {fp_reason}"
            db = factory()
            try:
                inv_repo.record_investigation_end(
                    inv_id=inv_id,
                    verdict="false_positive",
                    severity="low",
                    summary=summary,
                    actions=[],
                    iocs={},
                    llm_model=None,
                    tokens=None,
                    duration_ms=int((time.monotonic() - overall_start) * 1000),
                    db=db,
                )
                db.commit()
                inv_row = db.get(Investigation, inv_id)
                if inv_row is not None:
                    db.refresh(inv_row)
                    db.expunge(inv_row)
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
            # Best-effort alert writeback
            try:
                await self._writeback_alert(
                    alert_id, inv_id, "false_positive", "low", [], summary,
                )
            except Exception as exc:
                logger.debug("FP alert writeback skipped: %s", exc)
            # Best-effort case note
            await self._post_to_case(
                alert_id, inv_id,
                verdict="false_positive", severity="low",
                summary=summary, actions=[], mitre_tags=[],
            )
            return inv_row  # type: ignore[return-value]

        try:
            # 5) IOC extraction
            try:
                from ion.services.ioc_text_extractor import extract_iocs
                raw_iocs = extract_iocs(_alert_to_text_blob(alert))
            except Exception as exc:
                logger.warning("IOC extraction failed for %s: %s", alert_id, exc)
                raw_iocs = {}
            extracted_iocs = _normalise_extracted_iocs(raw_iocs)

            # 6) TI enrichment
            try:
                enrichment = await self._enrich_iocs(extracted_iocs, inv_id)
            except Exception as exc:
                logger.warning("Enrichment failed for %s: %s", alert_id, exc)
                enrichment = {"ip": {}, "domain": {}, "url": {}, "hash": {}}

            # 7) MITRE tagging
            mitre_tags = _extract_mitre_tags(alert)

            # 8) Memory context
            memory_ctx_md = _build_memory_ctx(memory, alert)

            # 9) Prompt selection + system prompt render
            template = None
            system_prompt = ""
            prompt_template_id: Optional[int] = None
            db = factory()
            try:
                svc = self._get_alert_prompt_service(db)
                try:
                    template = svc.resolve_template_for_alert(alert)
                except Exception as exc:
                    logger.debug("resolve_template_for_alert failed: %s", exc)
                    template = None
                system_prompt = svc.render_system_prompt(template, alert)
                if template is not None:
                    prompt_template_id = template.id
            finally:
                db.close()

            if not system_prompt:
                # Safety net — the AlertPromptService render_system_prompt
                # with template=None returns the base prompt, but if the
                # service itself blew up we fall back directly.
                try:
                    from ion.services.ollama_service import SYSTEM_PROMPTS
                    system_prompt = SYSTEM_PROMPTS.get("security", "")
                except Exception:
                    system_prompt = ""

            # 10) Build prompt body
            alert_summary = self._build_alert_summary(alert)

            prompt_alert = alert
            anon_map: Any = None
            try:
                pii = self._get_pii_anon()
                if pii is not None and pii.is_enabled():
                    redacted, mapping = pii.tokenize_event(alert)
                    prompt_alert = redacted
                    anon_map = mapping
                    # Rebuild summary from the redacted copy so the LLM
                    # only ever sees tokenised values.
                    alert_summary = self._build_alert_summary(redacted)
            except Exception as exc:
                logger.debug("PII anonymisation failed — sending raw alert: %s", exc)
                prompt_alert = alert
                anon_map = None

            user_body = self._build_user_prompt_body(
                alert_summary=alert_summary,
                enrichment=enrichment,
                mitre_tags=mitre_tags,
                memory_ctx_md=memory_ctx_md,
                extracted_iocs=extracted_iocs,
            )

            # 11) LLM call
            raw_response_content: str = ""
            try:
                parsed, model_used, eval_count, llm_ms, raw_response_content = await self._call_llm(
                    system_prompt=system_prompt,
                    user_body=user_body,
                    anon_map=anon_map,
                )
            except InvestigationError:
                raise
            except Exception as exc:
                logger.warning("LLM call failed for %s: %s", alert_id, exc)
                parsed = _parse_llm_json("")
                parsed["summary"] = f"LLM call failed: {exc}"
                model_used = ""
                eval_count = None
                llm_ms = 0

            # Detokenise summary + actions before persistence so the stored
            # record carries real values.
            if anon_map is not None:
                try:
                    pii = self._get_pii_anon()
                    if pii is not None:
                        parsed["summary"] = pii.detokenize_text(parsed["summary"], anon_map)
                        parsed["recommended_actions"] = [
                            pii.detokenize_text(a, anon_map)
                            for a in parsed.get("recommended_actions", [])
                        ]
                except Exception as exc:
                    logger.debug("detokenise failed: %s", exc)

            # 12) Writeback to Investigation
            duration_ms = int((time.monotonic() - overall_start) * 1000)
            ioc_snapshot = {
                "extracted": extracted_iocs,
                "enrichment": enrichment,
            }

            db = factory()
            try:
                inv = db.get(Investigation, inv_id)
                if inv is not None and prompt_template_id is not None:
                    inv.prompt_template_id = prompt_template_id
                    db.flush()
                inv_repo.record_investigation_end(
                    inv_id=inv_id,
                    verdict=parsed["verdict"],
                    severity=parsed["severity"],
                    summary=parsed["summary"],
                    actions=parsed["recommended_actions"],
                    iocs=ioc_snapshot,
                    llm_model=model_used or None,
                    tokens=eval_count,
                    duration_ms=duration_ms,
                    db=db,
                    prompt_snapshot=user_body,
                    raw_response=raw_response_content,
                    key_observations=parsed.get("key_observations") or [],
                )
                # 12b) Bob-authored writebacks — alert Note, triage hint,
                # high-confidence IOC observables. Never fatal.
                try:
                    _write_bob_outputs(
                        db=db,
                        alert_id=alert_id,
                        investigation_id=inv_id,
                        parsed=parsed,
                    )
                except Exception as exc:
                    logger.warning(
                        "Bob-authored writebacks failed for %s: %s",
                        alert_id, exc,
                    )
                db.commit()
                inv = db.get(Investigation, inv_id)
                if inv is not None:
                    db.refresh(inv)
                    db.expunge(inv)
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

            # 13) Writeback to ES alert (best-effort, never fails the run)
            try:
                await self._writeback_alert(
                    alert_id=alert_id,
                    inv_id=inv_id,
                    verdict=parsed["verdict"],
                    severity=parsed["severity"],
                    mitre_tags=mitre_tags,
                    summary=parsed["summary"],
                )
            except Exception as exc:
                logger.debug("alert writeback skipped: %s", exc)

            # 14) Attach result as a case note (+ Kibana comment if linked)
            await self._post_to_case(
                alert_id=alert_id,
                inv_id=inv_id,
                verdict=parsed["verdict"],
                severity=parsed["severity"],
                summary=parsed["summary"],
                actions=parsed.get("recommended_actions") or [],
                mitre_tags=mitre_tags,
                iocs=extracted_iocs,
            )

            if inv is None:
                # Shouldn't happen, but never return None from this method.
                db = factory()
                try:
                    inv = db.get(Investigation, inv_id)
                    if inv is not None:
                        db.refresh(inv)
                        db.expunge(inv)
                finally:
                    db.close()
            return inv  # type: ignore[return-value]

        except Exception as exc:
            # Mark failed, then re-raise so the sweep caller counts it as an error.
            logger.exception("Investigation %s failed: %s", inv_id, exc)
            try:
                db = factory()
                inv_repo.mark_investigation_failed(inv_id, f"{type(exc).__name__}: {exc}"[:4000], db)
                db.commit()
            except Exception:
                pass
            finally:
                try:
                    db.close()
                except Exception:
                    pass
            raise

    # ------------------------------------------------------------------ #
    # Cluster-level investigation (one LLM call per case, not per alert)
    # ------------------------------------------------------------------ #

    async def investigate_case(
        self,
        case_id: int,
        force: bool = False,
        triggered_by: str = "auto",
    ) -> Optional[Investigation]:
        """Run one cluster-level investigation covering every alert on the case.

        - Loads ``AlertCase`` + its ``source_alert_ids``
        - Fetches each alert from ES (best-effort; missing ones skipped)
        - Aggregates IOCs across all alerts
        - Enriches via VT / Shodan / OpenCTI / AbuseIPDB
        - Selects a prompt template from the first matching alert
        - Makes ONE LLM call with full cluster context
        - Writes ONE Investigation row (alert_id_ref=``case:<id>``)
        - Calls ``_post_to_case`` to write the note + observables + status

        Idempotent unless ``force=True``: skips if a recent
        investigation already exists for this case.
        """
        from ion.models.alert_triage import AlertCase
        from ion.storage.database import get_session_factory

        factory = get_session_factory()
        db = factory()
        alert_ids: List[str] = []
        case_number = ""
        case_title = ""
        case_host = None
        case_user = None
        try:
            case = db.get(AlertCase, case_id)
            if case is None:
                raise InvestigationError(f"case #{case_id} not found")
            alert_ids = list(case.source_alert_ids or [])
            case_number = case.case_number or f"CASE-{case_id}"
            case_title = case.title or ""
            hosts = case.affected_hosts or []
            users = case.affected_users or []
            case_host = hosts[0] if hosts else None
            case_user = users[0] if users else None
        finally:
            db.close()

        if not alert_ids:
            logger.info("investigate_case: %s has no alerts — skipping", case_number)
            return None

        synthetic_alert_ref = f"case:{case_id}"

        # Idempotency: skip if a recent case-level investigation exists.
        if not force:
            existing = self._find_recent_investigation(synthetic_alert_ref)
            if existing is not None:
                logger.debug("investigate_case: reusing existing inv #%d for %s",
                             existing.id, case_number)
                return existing

        # Record the investigation start using a synthetic alert dict so the
        # repo helpers don't need a real ES fetch.
        seed_alert = {
            "_id": synthetic_alert_ref,
            "alert_signature": case_title,
            "rule_name": case_title,
            "host": case_host,
            "user_name": case_user,
        }
        db = factory()
        try:
            inv = inv_repo.record_investigation_start(seed_alert, db)
            inv_id = inv.id
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        overall_start = time.monotonic()
        es = self._get_es()

        # Fetch every alert on the case (best-effort, single batched call).
        alerts: List[Dict[str, Any]] = []
        try:
            es_alerts = await es.get_alerts_by_ids(alert_ids)
            for a in (es_alerts or []):
                alerts.append(a.to_dict(include_raw=True) if hasattr(a, "to_dict") else a)
        except Exception as exc:
            logger.debug("investigate_case: bulk fetch failed: %s", exc)

        # Aggregate IOCs across every alert, dedup by (type, value).
        from ion.services.ioc_text_extractor import extract_iocs
        combined_raw: Dict[str, set] = {}
        for a in alerts:
            try:
                raw = extract_iocs(_alert_to_text_blob(a))
            except Exception:
                raw = {}
            for k, vs in (raw or {}).items():
                if not isinstance(vs, (list, tuple, set)):
                    continue  # skip scalar metadata like _total
                combined_raw.setdefault(k, set()).update(vs)
        extracted_iocs = _normalise_extracted_iocs({k: list(v) for k, v in combined_raw.items()})

        # Enrichment across all IOCs (dedup happens inside helper).
        try:
            enrichment = await self._enrich_iocs(extracted_iocs, inv_id=inv_id)
        except Exception as exc:
            logger.warning("investigate_case: enrichment failed: %s", exc)
            enrichment = {"ip": {}, "domain": {}, "url": {}, "hash": {}}

        # MITRE tagging (union of all alerts)
        from ion.services.mitre_navigator_service import tag_alert
        mitre_union: set = set()
        for a in alerts:
            for t in tag_alert(a):
                mitre_union.add(t)
        mitre_tags = sorted(mitre_union)

        # Memory context — use the first alert as representative
        rep_alert = alerts[0] if alerts else seed_alert
        try:
            from ion.services.investigation_memory_service import (
                get_investigation_memory_service,
            )
            memory = get_investigation_memory_service()
        except Exception as exc:
            logger.debug("memory service init failed: %s", exc)
            memory = None
        memory_ctx_md = _build_memory_ctx(memory, rep_alert)

        # Prompt template match (first alert)
        prompt_template_id: Optional[int] = None
        try:
            from ion.services.ollama_service import SYSTEM_PROMPTS
            system_prompt = SYSTEM_PROMPTS.get("security") or SYSTEM_PROMPTS.get("default") or ""
        except Exception:
            system_prompt = ""
        try:
            from ion.services.alert_prompt_service import AlertPromptService
            db = factory()
            try:
                svc = AlertPromptService(db)
                tpl = svc.resolve_template_for_alert(rep_alert)
                if tpl is not None:
                    prompt_template_id = tpl.id
                    system_prompt = svc.render_system_prompt(tpl, rep_alert)
            finally:
                db.close()
        except Exception as exc:
            logger.debug("prompt template resolution failed: %s", exc)

        # Build cluster prompt
        brief_lines = [
            f"Investigate this cluster of {len(alerts)} alert(s) on {case_number}.",
            f"Signature: {case_title}",
            f"Host: {case_host or 'unknown'} · User: {case_user or 'unknown'}",
            "",
            "Alerts in this cluster:",
        ]
        for i, a in enumerate(alerts[:20], 1):
            rule_name = _get(a, "rule.name") or _get(a, "kibana.alert.rule.name") or "n/a"
            ts = _get(a, "@timestamp") or _get(a, "timestamp") or ""
            aid = a.get("_id") or a.get("id") or ""
            brief_lines.append(f"  {i}. [{ts}] {rule_name} id={aid[:20]}")
        if len(alerts) > 20:
            brief_lines.append(f"  … and {len(alerts) - 20} more")
        brief_lines += [
            "",
            f"Extracted IOCs across cluster: {json.dumps(extracted_iocs)}",
            f"Enrichment summary: {json.dumps({k: len(v) for k, v in enrichment.items()})}",
            f"MITRE tags (union): {', '.join(mitre_tags) or 'none'}",
            "",
            "Memory context:",
            memory_ctx_md or "(no prior investigations for this signature)",
            "",
            "Analyse the CLUSTER as a whole. Respond with ONE JSON object "
            "conforming to the Output Contract in the system message. Scope "
            "every field (verdict, IOCs, affected assets, blast radius, "
            "recommended actions, tuning) to the cluster, not any single "
            "alert. No markdown fences, no prose outside JSON.",
        ]
        user_prompt = "\n".join(brief_lines)

        # LLM call
        try:
            parsed, model_used, eval_count, llm_ms = await self._call_llm(
                system_prompt=system_prompt,
                user_body=user_prompt,
                anon_map=None,
            )
        except InvestigationError as exc:
            logger.warning("investigate_case LLM failed for %s: %s", case_number, exc)
            parsed = {
                "verdict": "inconclusive",
                "severity": "low",
                "summary": f"LLM call failed: {exc}",
                "recommended_actions": [],
                "confidence": 0,
            }
            model_used, eval_count, llm_ms = None, None, 0

        duration_ms = int((time.monotonic() - overall_start) * 1000)
        ioc_snapshot = {
            "extracted": extracted_iocs,
            "enrichment": enrichment,
            "cluster_size": len(alerts),
            "case_id": case_id,
            "case_number": case_number,
        }

        # Writeback Investigation row
        db = factory()
        try:
            inv = db.get(Investigation, inv_id)
            if inv is not None and prompt_template_id is not None:
                inv.prompt_template_id = prompt_template_id
                db.flush()
            inv_repo.record_investigation_end(
                inv_id=inv_id,
                verdict=parsed["verdict"],
                severity=parsed["severity"],
                summary=parsed["summary"],
                actions=parsed["recommended_actions"],
                iocs=ioc_snapshot,
                llm_model=model_used,
                tokens=eval_count,
                duration_ms=duration_ms,
                db=db,
            )
            db.commit()
            inv = db.get(Investigation, inv_id)
            if inv is not None:
                db.refresh(inv)
                db.expunge(inv)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

        # Attach to the case (note + observables + status). Pass the first real
        # alert id so _post_to_case's AlertTriage lookup finds the case.
        first_real_id = alert_ids[0]
        try:
            await self._post_to_case(
                alert_id=first_real_id,
                inv_id=inv_id,
                verdict=parsed["verdict"],
                severity=parsed["severity"],
                summary=parsed["summary"],
                actions=parsed.get("recommended_actions") or [],
                mitre_tags=mitre_tags,
                iocs=extracted_iocs,
            )
        except Exception as exc:
            logger.debug("_post_to_case from investigate_case failed: %s", exc)

        logger.info(
            "Cluster investigation complete: %s | verdict=%s | alerts=%d | tokens=%s | %.1fs",
            case_number, parsed["verdict"], len(alerts), eval_count, duration_ms / 1000.0,
        )
        return inv

    # ------------------------------------------------------------------ #
    # Sweep
    # ------------------------------------------------------------------ #

    async def investigate_open_alerts_sweep(
        self,
        max_alerts: int = _DEFAULT_MAX_PER_SWEEP,
        force: bool = False,
    ) -> Dict[str, int]:
        """Investigate up to ``max_alerts`` OPEN alerts missing an investigation_id.

        ``force=True`` re-investigates every matching alert, ignoring both the
        ES-side ``ion.investigation_id`` flag and the ION-side
        already-investigated check. Use for full-sweep re-runs after a bug fix.

        Returns a summary dict with counts keyed by outcome.
        """
        summary = {
            "scanned": 0,
            "investigated": 0,
            "skipped_fp": 0,
            "skipped_existing": 0,
            "errors": 0,
        }

        alerts = await self._fetch_open_alerts(max_alerts=max_alerts)
        summary["scanned"] = len(alerts)
        if not alerts:
            return summary

        for alert in alerts:
            alert_id = alert.get("_id")
            if not alert_id:
                summary["errors"] += 1
                continue

            if not force:
                # Skip alerts that already carry an investigation_id (in ES).
                existing_flag = _get(alert, "ion.investigation_id")
                if existing_flag:
                    summary["skipped_existing"] += 1
                    continue

                # Client-side dedup on the ION side too.
                existing = self._find_recent_investigation(alert_id)
                if existing is not None:
                    summary["skipped_existing"] += 1
                    continue

            try:
                inv = await self.investigate_alert(alert_id, force=force, triggered_by="sweep")
                if inv is not None and inv.verdict == "false_positive" and inv.summary_text and \
                        inv.summary_text.startswith("Matched FP signature:"):
                    summary["skipped_fp"] += 1
                else:
                    summary["investigated"] += 1
            except InvestigationError as exc:
                logger.info("sweep: %s for %s", exc, alert_id)
                summary["errors"] += 1
            except Exception as exc:
                logger.warning("sweep: unhandled error for %s: %s", alert_id, exc)
                summary["errors"] += 1

        return summary

    # ------------------------------------------------------------------ #
    # Background loop (threading-based, asyncio.run per iteration)
    # ------------------------------------------------------------------ #

    def run_investigation_sweep_loop(
        self,
        interval_s: int = _DEFAULT_SWEEP_INTERVAL_S,
    ) -> None:
        """Spawn the background sweep thread (idempotent)."""
        if self._loop_thread is not None and self._loop_thread.is_alive():
            logger.info("Investigation sweep loop already running — skipping")
            return

        def _loop() -> None:
            logger.info(
                "Investigation sweep loop started (interval=%ds)", interval_s
            )
            while not self._stop_event.is_set():
                try:
                    max_per = _DEFAULT_MAX_PER_SWEEP
                    try:
                        from ion.core.config import get_config
                        cfg = get_config()
                        max_per = int(
                            getattr(cfg, "investigation_max_per_sweep", _DEFAULT_MAX_PER_SWEEP)
                        )
                    except Exception:
                        pass
                    result = asyncio.run(
                        self.investigate_open_alerts_sweep(max_alerts=max_per)
                    )
                    logger.info(
                        "Investigation sweep complete: %s",
                        json.dumps(result, default=str),
                    )
                except Exception as exc:
                    logger.warning("Investigation sweep iteration error: %s", exc)
                self._stop_event.wait(interval_s)
            logger.info("Investigation sweep loop stopped")

        self._loop_thread = threading.Thread(
            target=_loop, daemon=True, name="ion-investigation-sweep"
        )
        self._loop_thread.start()

    def stop_investigation_sweep_loop(self) -> None:
        """Signal the background thread to exit on its next poll boundary."""
        self._stop_event.set()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_investigation_service: Optional[InvestigationService] = None


def get_investigation_service() -> InvestigationService:
    """Return the process-wide :class:`InvestigationService` singleton."""
    global _investigation_service
    if _investigation_service is None:
        _investigation_service = InvestigationService()
    return _investigation_service


def reset_investigation_service() -> None:
    """Reset the singleton — used in tests / config reloads."""
    global _investigation_service
    if _investigation_service is not None:
        _investigation_service.stop_investigation_sweep_loop()
    _investigation_service = None


# ---------------------------------------------------------------------------
# Startup hook (leader-elected via pg advisory lock 1016)
# ---------------------------------------------------------------------------


def start_investigation_loop_if_enabled(engine=None) -> bool:
    """Leader-elected wrapper that starts the sweep loop under a pg lock.

    Honours the ``ION_INVESTIGATION_LOOP_ENABLED`` env var + config
    attribute (default True). Uses ``LOCK_INVESTIGATION_BG = 1016`` —
    the new constant documented in the Integration Checklist. Falls back
    to ``LOCK_KIBANA_BG_SYNC`` as a dev-mode sentinel **only if** the
    real lock constant hasn't been added to ``storage/database.py`` yet;
    in that degenerate case we refuse to start to avoid colliding with
    an existing loop, and log a warning so the operator fixes it.

    Returns True if this worker actually started the loop, False
    otherwise (disabled, another worker holds the lock, or the lock
    constant is missing).
    """
    import os

    # Resolve enabled flag — env wins, then Config, then default True.
    env_flag = os.environ.get("ION_INVESTIGATION_LOOP_ENABLED", "").strip().lower()
    if env_flag in ("false", "0", "no", "off"):
        logger.info("Investigation loop disabled via ION_INVESTIGATION_LOOP_ENABLED")
        return False

    try:
        from ion.core.config import get_config
        cfg = get_config()
        if env_flag == "" and not getattr(cfg, "investigation_loop_enabled", True):
            logger.info("Investigation loop disabled via config.investigation_loop_enabled")
            return False
        interval_s = int(
            getattr(cfg, "investigation_sweep_interval_s", _DEFAULT_SWEEP_INTERVAL_S)
        )
    except Exception:
        interval_s = _DEFAULT_SWEEP_INTERVAL_S
    env_interval = os.environ.get("ION_INVESTIGATION_SWEEP_INTERVAL_S")
    if env_interval:
        try:
            interval_s = int(env_interval)
        except ValueError:
            pass

    # Pick the lock id — prefer the canonical constant, require it for
    # production so we never race another loop.
    try:
        from ion.storage.database import LOCK_INVESTIGATION_BG  # type: ignore
        lock_id = LOCK_INVESTIGATION_BG
    except ImportError:
        logger.warning(
            "LOCK_INVESTIGATION_BG not found in storage.database — refusing to "
            "start sweep loop. Add `LOCK_INVESTIGATION_BG = 1016` to "
            "src/ion/storage/database.py (see Integration Checklist)."
        )
        return False

    if engine is None:
        engine = get_engine()

    service = get_investigation_service()

    def _start() -> None:
        service.run_investigation_sweep_loop(interval_s=interval_s)

    return run_locked(
        engine,
        lock_id,
        "investigation_bg_loop",
        _start,
        hold_until_close=True,
    )


