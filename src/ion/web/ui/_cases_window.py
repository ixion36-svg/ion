"""The opened case's two layouts, Triage and Read, from data ION already holds.

Everything here is a view over what the case panel reads anyway, plus one
small read (`read_case_extras`) of rows that already exist: Bob's per-alert
investigations, the triage suggestions and the stored enrichments of the
case's observables. Nothing here reads Elasticsearch; the key context strip
and the alert table's times come from the raw documents the alert-detail
component already fetches, so they are derived in the page.

Three outcomes stay three: a read that failed is `None` ("unknown"), an
empty result is an empty list, and data is data.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal, Optional, TypedDict

from ion.models.alert_triage import ALERT_CLOSURE_REASONS

logger = logging.getLogger(__name__)


#: arkime_retention_service files a triage row `retention:<case id>` beside
#: its PCAP warning note, so it warns once per case. The row is a marker,
#: not an alert: it has no Elasticsearch document, and listed as one it was
#: an exhibit whose every tab failed, and an "alert not closed".
RETENTION_MARKER = "retention:"


def case_alerts(alerts: Any) -> Any:
    """The case's alerts without the retention markers; not-a-list passes through."""
    if not isinstance(alerts, list):
        return alerts
    return [a for a in alerts if not (isinstance(a, dict)
            and str(a.get("es_alert_id") or "").startswith(RETENTION_MARKER))]


def letter(index: int) -> str:
    """A, B, ... Z, AA, AB: the exhibit name of the alert at this rail position."""
    out = ""
    n = index + 1
    while n:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


# ── Bob's prose ─────────────────────────────────────────────────────────
#: The headline every Bob note starts with (investigation_service's
#: _render_bob_case_note and _render_bob_alert_note).
BOB_MARKER = re.compile(
    r"\A\s*\*\*\U0001F916 Bob \(AI analyst\) — `(?P<verdict>[^`]*)`\*\*(?P<rest>[^\n]*)")
_FENCED = re.compile(r"```[A-Za-z]*[ \t]*\n?(?P<body>.*?)```", re.S)
# A reply cut off mid-block leaves a fence that never closes.
_OPEN_FENCE = re.compile(r"```[A-Za-z]*[ \t]*\n?(?P<body>.*)\Z", re.S)


_SUMMARY_FIELD = re.compile(r'"summary"\s*:\s*("(?:[^"\\]|\\.)*")')


def _json_summary(text: str) -> Optional[str]:
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        # A reply cut off by the token limit is not JSON, but its summary
        # usually comes first and is complete (CASE-0118's is).
        found = _SUMMARY_FIELD.search(text)
        try:
            salvaged = json.loads(found.group(1)) if found else None
        except ValueError:
            salvaged = None
        return salvaged.strip() if isinstance(salvaged, str) and salvaged.strip() else None
    if isinstance(parsed, dict):
        summary = parsed.get("summary")
        if isinstance(summary, str) and summary.strip():
            return summary.strip()
    return None


def bob_text(raw: Any) -> Optional[str]:
    """Bob's prose, with JSON he failed to unwrap replaced by what it says.

    When the model's reply did not parse, the envelope was stored as a
    fenced ```json block. Such a block becomes its `summary` when it parses
    and has one, else its own text without the fence, so a broken reply
    still reads and never renders as a code dump.
    """
    if not isinstance(raw, str):
        return None

    def unfence(match: re.Match) -> str:
        body = match.group("body").strip()
        return _json_summary(body) or body

    text = _FENCED.sub(unfence, raw)
    text = _OPEN_FENCE.sub(unfence, text).strip()
    return _json_summary(text) or text or None


class BobNote(TypedDict):
    verdict: str
    headline: str
    text: Optional[str]
    when: Any


def bob_case_note(notes: Any) -> Optional[BobNote]:
    """The latest case note Bob wrote, or None when there is none."""
    if not isinstance(notes, list):
        return None
    found: Optional[tuple[str, BobNote]] = None
    for index, entry in enumerate(notes):
        if not isinstance(entry, dict) or not isinstance(entry.get("content"), str):
            continue
        match = BOB_MARKER.match(entry["content"])
        if not match:
            continue
        stamp = entry.get("created_at")
        order = (stamp if isinstance(stamp, str) else "") + "|%08d" % index
        note: BobNote = {
            "verdict": match.group("verdict").strip() or "unstated",
            "headline": match.group("rest").strip(" ·"),
            "text": bob_text(entry["content"][match.end():]),
            "when": stamp,
        }
        if found is None or order > found[0]:
            found = (order, note)
    return found[1] if found else None


# ── Bob per alert ───────────────────────────────────────────────────────
class AlertBob(TypedDict):
    state: Literal["investigated", "none", "unknown", "withheld"]
    summary: Optional[str]
    verdict: Optional[str]
    confidence: Optional[int]
    status: Optional[str]
    actions: list[str]
    suggested_verdict: Optional[str]
    suggested_confidence: Optional[str]
    badge: Optional[str]


def _actions(raw: Any) -> list[str]:
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    out = []
    for entry in parsed if isinstance(parsed, list) else []:
        text = entry if isinstance(entry, str) else (
            entry.get("action") if isinstance(entry, dict) else None)
        if isinstance(text, str) and text.strip():
            out.append(text.strip())
    return out


def alert_bob(alert_id: str, extras: Optional[dict]) -> AlertBob:
    """What Bob has said about one alert, from rows that already exist."""
    view: AlertBob = {
        "state": "unknown", "summary": None, "verdict": None, "confidence": None,
        "status": None, "actions": [], "suggested_verdict": None,
        "suggested_confidence": None, "badge": None,
    }
    if not isinstance(extras, dict):
        return view
    triage = (extras.get("triage") or {}).get(alert_id) or {}
    view["suggested_verdict"] = triage.get("suggested_verdict")
    view["suggested_confidence"] = triage.get("suggested_confidence")
    view["badge"] = triage.get("badge")
    if "investigations" in (extras.get("withheld") or ()):
        view["state"] = "withheld"
        return view
    investigations = extras.get("investigations")
    if not isinstance(investigations, dict):
        return view
    row = investigations.get(alert_id)
    if not row:
        view["state"] = "none"
        return view
    view.update({
        "state": "investigated",
        "summary": bob_text(row.get("summary_text")),
        "verdict": row.get("verdict"),
        "confidence": row.get("confidence_int"),
        "status": row.get("status"),
        "actions": _actions(row.get("recommended_actions_json")),
    })
    return view


# ── The Read mode summary ───────────────────────────────────────────────
class SummaryView(TypedDict):
    source: Literal["bob_note", "evidence_summary", "description", "none"]
    label: str
    text: Optional[str]
    verdict: Optional[str]
    when: Any


_GROUPER_DESCRIPTION = "**Auto-grouped case**"


def summary_view(note: Optional[BobNote], evidence_summary: Any,
                 description: Any) -> SummaryView:
    """The case's summary and where it came from, best source first."""
    if note and note.get("text"):
        return {"source": "bob_note", "label": "Bob's latest case note",
                "text": note["text"], "verdict": note["verdict"],
                "when": note["when"]}
    if isinstance(evidence_summary, str) and evidence_summary.strip():
        return {"source": "evidence_summary", "label": "The case's evidence summary",
                "text": evidence_summary.strip(), "verdict": None, "when": None}
    if isinstance(description, str) and description.strip():
        templated = description.lstrip().startswith(_GROUPER_DESCRIPTION)
        return {"source": "description",
                "label": ("The case grouper's templated description" if templated
                          else "The case description"),
                "text": description.strip(), "verdict": None, "when": None}
    return {"source": "none", "label": "No summary", "text": None,
            "verdict": None, "when": None}


# ── Alert verdicts ──────────────────────────────────────────────────────
class Verdict(TypedDict):
    reason: str
    closure_type: str
    label: str
    key: str


_VERDICT_FACE = {"escalated": ("True positive", "t"), "benign": ("Benign", "b"),
                 "false_positive": ("False positive", "f")}

#: The three verdicts the case window triages with, in button order. Each
#: is sent to POST /elasticsearch/alerts/{id}/close as its closure type and
#: is named by the case closure reason it maps to.
VERDICTS: tuple[Verdict, ...] = tuple(
    {"reason": ALERT_CLOSURE_REASONS[t], "closure_type": t, "label": label, "key": key}
    for t, (label, key) in _VERDICT_FACE.items())

REASONS = frozenset(v["reason"] for v in VERDICTS)

# close_alert's note: "**Alert closed as {closure type, title-cased}**",
# then "Alert: `{id}`" on the next line.
_CLOSED_AS = re.compile(r"\A\*\*Alert closed as (?P<label>[^*\n]+)\*\*[ \t]*\r?\nAlert: `(?P<id>[^`\n]+)`")


def alert_verdicts(notes: Any) -> Optional[dict[str, str]]:
    """Each alert's latest recorded verdict, as a case closure reason.

    The case note close_alert writes is the only place ION keeps the
    verdict an alert was closed with. None when the notes are unreadable.
    """
    if not isinstance(notes, list):
        return None
    latest: dict[str, tuple[str, str]] = {}
    for index, entry in enumerate(notes):
        content = entry.get("content") if isinstance(entry, dict) else None
        match = _CLOSED_AS.match(content) if isinstance(content, str) else None
        reason = match and ALERT_CLOSURE_REASONS.get(
            match.group("label").strip().lower().replace(" ", "_"))
        if not reason:
            continue
        stamp = entry.get("created_at")
        order = (stamp if isinstance(stamp, str) else "") + "|%08d" % index
        alert_id = match.group("id")
        if alert_id not in latest or order > latest[alert_id][0]:
            latest[alert_id] = (order, reason)
    return {alert_id: reason for alert_id, (_, reason) in latest.items()}


def untriaged(alerts: Any, verdicts: Optional[dict[str, str]]) -> Optional[list[str]]:
    """The alerts nobody has decided: not closed, and no verdict recorded."""
    if not isinstance(alerts, list):
        return None
    decided = verdicts or {}
    return [str(a.get("es_alert_id")) for a in alerts if isinstance(a, dict)
            and str(a.get("status") or "open").lower() != "closed"
            and str(a.get("es_alert_id")) not in decided]


def untriaged_title(n: int) -> str:
    return "%d linked alert%s not triaged" % (n, "" if n == 1 else "s")


# ── What stops closure (derived) ────────────────────────────────────────
class Blocker(TypedDict):
    key: str
    title: str
    detail: str
    href: Optional[str]


UNTRIAGED_DETAIL = "Not closed, and no verdict recorded on this case."


def blockers(alerts: Any, assigned_to_id: Any, iris_case_id: Any,
             iris_url: Any, verdicts: Optional[dict[str, str]] = None) -> list[Blocker]:
    """Why this case is not ready to close, from what the panel already read.

    ION has no readiness rules, so this is derived and labelled so; it never
    gates the close action. case-window.js recounts the alerts entry after a
    triage write, by the same rule as untriaged().
    """
    out: list[Blocker] = []
    open_ids = untriaged(alerts, verdicts)
    if open_ids is None:
        out.append({"key": "alerts-unknown", "title": "Linked alerts could not be read",
                    "detail": "Whether any are still open is unknown.", "href": None})
    elif open_ids:
        out.append({"key": "alerts", "title": untriaged_title(len(open_ids)),
                    "detail": UNTRIAGED_DETAIL, "href": None})
    if assigned_to_id is None:
        out.append({"key": "assignee", "title": "No one is assigned",
                    "detail": "The case has no owner.", "href": None})
    if iris_case_id is not None:
        out.append({"key": "iris", "title": "Escalated to DFIR-IRIS #%s" % iris_case_id,
                    "detail": "Check it in IRIS. Closing here does not close it there.",
                    "href": iris_url if isinstance(iris_url, str) and iris_url else None})
    return out


# ── Observables, with what is known about each ──────────────────────────
#: Triage observable type -> the ioc_type POST /api/enrichment/lookup takes.
LOOKUP_TYPES: dict[str, str] = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "source_ip": "ip",
    "destination_ip": "ip", "host_ip": "ip", "domain": "domain",
    "url": "url", "sha256": "sha256", "file_hash_sha256": "sha256",
}

#: Sources ION can enrich from but stores nothing for on a case observable.
UNSTORED_SOURCES = "VirusTotal, AbuseIPDB, Shodan or GeoIP"


class SourceCard(TypedDict):
    name: str
    when: Any
    rows: list[tuple[str, str]]


def _join(values: Any) -> str:
    items = [str(v) for v in values if v not in (None, "")] if isinstance(values, list) else []
    return ", ".join(items) if items else "none"


def inline_opencti(entry: dict) -> Optional[SourceCard]:
    """The OpenCTI result triage stored on the observable, if it found one."""
    if entry.get("enriched") is not True:
        return None
    score = entry.get("score")
    count = entry.get("indicator_count")
    return {"name": "OpenCTI", "when": None, "rows": [
        ("Score", "%s / 100" % score if score is not None else "not given"),
        ("Indicators", str(count) if count is not None else "not given"),
        ("Labels", _join(entry.get("threat_labels"))),
        ("Threat actors", _join(entry.get("threat_actors"))),
    ]}


def stored_source(row: dict) -> SourceCard:
    """One `observable_enrichments` row."""
    malicious = row.get("is_malicious")
    indicators = row.get("indicators")
    when = row.get("enriched_at")
    return {"name": str(row.get("source") or "unnamed source"),
            "when": when.strftime("%Y-%m-%d %H:%M UTC") if hasattr(when, "strftime") else when,
            "rows": [
                ("Verdict", "malicious" if malicious is True
                 else "not malicious" if malicious is False else "not given"),
                ("Score", str(row["score"]) if row.get("score") is not None else "not given"),
                ("Labels", _join(row.get("labels"))),
                ("Threat actors", _join(row.get("threat_actors"))),
                ("Indicators", str(len(indicators)) if isinstance(indicators, list) else "not given"),
            ]}


def observable_cards(observables: Optional[list[dict]], extras: Optional[dict]) -> Optional[list[dict]]:
    """Each observable chip with its enrichment by source.

    Stored enrichments are matched by value, the way `observables` keys
    them (`normalized_value`). When that read failed the stored sources are
    unknown rather than absent.
    """
    if observables is None:
        return None
    stored = extras.get("enrichments") if isinstance(extras, dict) else None
    withheld = isinstance(extras, dict) and "enrichments" in (extras.get("withheld") or ())
    out = []
    for chip in observables:
        sources: list[SourceCard] = []
        inline = chip.get("opencti")
        if inline:
            sources.append(inline)
        rows = (stored or {}).get(str(chip.get("value") or "").lower(), [])
        sources.extend(stored_source(r) for r in rows)
        out.append({**chip, "sources": sources,
                    "stored_withheld": withheld,
                    "stored_unknown": not withheld and not isinstance(stored, dict),
                    "lookup_type": LOOKUP_TYPES.get(chip.get("kind") or "")})
    return out


# ── The one extra read ──────────────────────────────────────────────────
def read_case_extras(session: Any, case_id: int, alert_ids: list[str],
                     values: list[str], *, read_investigations: bool = True,
                     read_enrichments: bool = True) -> dict:
    """Bob's investigations, the triage suggestions and stored enrichments.

    Each part fails on its own into None, so a missing table costs that part
    only. The rollback keeps a failed statement from poisoning the next one
    on Postgres.

    A part the caller may not read is skipped and recorded in `withheld`:
    stored enrichments are `observable:read` data and Bob's investigations
    `alert:read` data everywhere else in ION, and the case panel only
    requires `case:read`.
    """
    from sqlalchemy import select

    from ion.models.alert_triage import AlertTriage
    from ion.models.investigation import Investigation
    from ion.models.observable import Observable, ObservableEnrichment

    extras: dict[str, Any] = {"investigations": None, "triage": None, "enrichments": None,
                              "withheld": set()}

    def attempt(key, read):
        try:
            extras[key] = read()
        except Exception:
            logger.exception("Case %s: the %s read failed", case_id, key)
            try:
                session.rollback()
            except Exception:
                pass

    def investigations():
        latest: dict[str, dict] = {}
        if not alert_ids:
            return latest
        rows = session.execute(
            select(Investigation).where(Investigation.alert_id_ref.in_(alert_ids))
            .order_by(Investigation.created_at.asc())).scalars().all()
        for r in rows:
            latest[r.alert_id_ref] = {
                "status": getattr(r.status, "value", r.status),
                "verdict": getattr(r.verdict, "value", r.verdict),
                "confidence_int": r.confidence_int,
                "summary_text": r.summary_text,
                "recommended_actions_json": r.recommended_actions_json,
            }
        return latest

    def triage():
        rows = session.execute(
            select(AlertTriage.es_alert_id, AlertTriage.suggested_verdict,
                   AlertTriage.suggested_verdict_confidence, AlertTriage.bob_escalation_badge)
            .where(AlertTriage.case_id == case_id)).all()
        return {r[0]: {"suggested_verdict": r[1], "suggested_confidence": r[2], "badge": r[3]}
                for r in rows}

    def enrichments():
        found: dict[str, list[dict]] = {}
        lowered = sorted({v.lower() for v in values if v})
        if not lowered:
            return found
        rows = session.execute(
            select(Observable.normalized_value, ObservableEnrichment)
            .join(ObservableEnrichment, ObservableEnrichment.observable_id == Observable.id)
            .where(Observable.normalized_value.in_(lowered))
            .order_by(ObservableEnrichment.enriched_at.desc())).all()
        for value, e in rows:
            found.setdefault(value, []).append({
                "source": e.source, "enriched_at": e.enriched_at, "is_malicious": e.is_malicious,
                "score": e.score, "labels": e.labels, "threat_actors": e.threat_actors,
                "indicators": e.indicators,
            })
        return found

    if read_investigations:
        attempt("investigations", investigations)
    else:
        extras["withheld"].add("investigations")
    attempt("triage", triage)
    if read_enrichments:
        attempt("enrichments", enrichments)
    else:
        extras["withheld"].add("enrichments")
    return extras
