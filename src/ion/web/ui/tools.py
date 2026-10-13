"""The SOC toolbox's three server reads: two OpenCTI lookups and the
translator's language list.

/tools is mostly not a server page. Defanging text, identifying a hash,
parsing a URL, testing a regex, reading email headers and decoding an
encoding all happen in the browser on text the analyst pasted there, and
there is nothing to ask a server about. Those renders moved into
<template> elements in the page shell, which is the other half of this
conversion; see tests/unit/test_ui_page_tools_client_state.py.

What is left is the part that reads something ION holds:

    POST /api/opencti/enrich          get_current_user, no named permission
    POST /api/opencti/enrich/batch    get_current_user, no named permission
    GET  /api/translator/languages    alert:read

Every fragment here is `alert:read`. For the language list that is the
endpoint's own gate. For the two OpenCTI lookups there is no named
permission to copy, and alert:read is the gate server.py puts on the
/tools page itself, so the fragment is stricter than the JSON route rather
than softer, which is the direction the rule allows. The registry's
bare-auth allow-list is not this conversion's file to grow.

`require_permission`, never `require_page_permission`: the page dependency
redirects to /login on an expired session and htmx would swap a password
box into the lookup panel.

What the JavaScript got wrong, as opposed to merely built badly:

  * The single lookup posted `{value: ioc}` with no `type`. The endpoint's
    request model requires both, so every lookup 422'd before OpenCTI was
    asked, and the catch printed "Lookup failed: Unexpected token" or
    rendered the 422 body as a not-found. The feature has not worked.
  * Even past that, the renderer branched on `!data.data ||
    data.data.length === 0`. `enrich_observable` returns no `data` key at
    all, so a genuine hit rendered "No threat intelligence found for this
    IOC" — a confident negative finding on an indicator OpenCTI knows.
  * `data.score`, `data.created`, `data.modified` and `data.relationships`
    are all absent from the response. The score is nested under
    `observable`, and the rows that exist are `indicators`,
    `threat_actors` and `reports`. Every one of those table rows was
    dead code that never rendered.
  * `data.labels.map(l => …escapeHtml(l))` stringified each label, and a
    label is `{value, color}`, so a real label rendered as
    "[object Object]".
  * The bulk table read `data.score || '-'`, so a measured score of 0,
    which is OpenCTI's "known and assessed as benign", printed as a dash
    and was indistinguishable from no score at all.
  * The bulk loop was unbounded and sequential: a thousand pasted lines
    were a thousand round trips with no cap and no progress past the first
    "Looking up N IOCs..." line.
  * `exportLookupResults` wrote `"${r.data.score || ''}"` straight into
    CSV with no quote escaping, so a label or type containing a double
    quote broke the row.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Any, Optional, TypedDict
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

IOC = "_fragments/tools_ioc.html"
IOC_BULK = "_fragments/tools_ioc_bulk.html"
LANGUAGES = "_fragments/tools_languages.html"

#: server.py gates the /tools page on it. See the module docstring for why
#: the two OpenCTI fragments use the page's permission rather than the
#: endpoint's absence of one.
ALERT_READ = "alert:read"

#: How many pasted lines one bulk request looks up. The page had no cap and
#: issued one request per line from the browser. The number of lines
#: dropped is reported rather than silently truncated: a bulk lookup that
#: quietly stopped at fifty is a page of IOCs nobody checked.
BULK_LIMIT = 50

#: Length-to-type for a bare hex digest, longest first so a 64-character
#: string is not read as four MD5s.
_HASH = (
    (64, "file-sha256", "SHA256"),
    (40, "file-sha1", "SHA1"),
    (32, "file-md5", "MD5"),
)

#: The reader-facing word for each OpenCTI type this page can produce.
#: detectIOCType built this second vocabulary in the browser and the two
#: disagreed: it reported "IPv4" for a value the request never typed at
#: all, because the request carried no type.
_TYPE_LABELS = {
    "file-sha256": "SHA256",
    "file-sha1": "SHA1",
    "file-md5": "MD5",
    "ipv4-addr": "IPv4",
    "ipv6-addr": "IPv6",
    "url": "URL",
    "email-addr": "Email",
    "domain-name": "Domain",
}

#: SUPPORTED_LANGUAGES' code for "work out what this is". It is a legal
#: source and not a legal target.
AUTO_CODE = "auto"

#: The description cap the analyst panel uses, so a long OpenCTI write-up
#: does not push the rest of the result off the panel.
DESCRIPTION_CAP = 200

#: How many related rows of each kind the panel shows.
RELATED_CAP = 10


class ToolsPanel(TypedDict):
    """What every panel of this page carries.

    `failed` is the read's outcome and is never inferred from an empty
    result: a lookup that could not run and an indicator OpenCTI has never
    heard of are different things to tell an analyst, and conflating them
    is how this page came to answer "No threat intelligence found" to a
    request that was rejected before it left ION.
    """
    view: str
    failed: bool


class IocPanel(ToolsPanel):
    value: str
    ioc_type: str
    label: str
    error: Optional[str]
    found: Optional[bool]
    score: Optional[int | float]
    labels: list
    description: Optional[str]
    indicators: list
    threat_actors: list
    reports: list
    observables_url: str


class BulkPanel(ToolsPanel):
    rows: list
    error: Optional[str]
    found_count: Optional[int]
    submitted: int
    dropped: int
    limit: int


class LanguagesPanel(ToolsPanel):
    languages: Optional[list]
    source_default: str
    target_default: str
    #: The code that may be a source and may not be a target. Named in the
    #: model rather than inferred from source_default being "auto": those
    #: are two different facts that happen to share a value today.
    auto_code: str


def _render(request: Request, view: ToolsPanel) -> HTMLResponse:
    """One panel, as markup or as the model itself.

    render_view answers JSON to a caller that asks for it, so each panel is
    a contract rather than a detail of one template. The whole context is
    the one object, including the value looked up and the type it was
    typed as, which the route knows and the fragment must show: a model the
    caller has to complete is not a contract.
    """
    return render_view(request, _FRAGMENT_OF[view["view"]], view)


def _number(value: object) -> Optional[int | float]:
    """A measured figure, or None when there is not one.

    `bool` is a subclass of `int`, so a check that only rejects non-numbers
    turns True into 1. A whole float comes back as an int so a score of 0.0
    renders as 0 rather than 0.0.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else value
    return None


def _text(value: object) -> Optional[str]:
    """A display string, or None when there is nothing to show."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    return text or None


def ioc_type(value: str) -> str:
    """The OpenCTI type for a value an analyst pasted.

    Every name returned is a key of `OpenCTIService.TYPE_MAP`, which is
    what POST /api/opencti/enrich validates against. The page sent no type
    at all, so this function is the fix for its oldest defect rather than a
    tidier version of something that worked.

    `javascript:alert(1)` is not a URL: only an http(s) scheme is. IPv6
    goes through `ipaddress` rather than a dotted-quad regex, which is what
    detectIOCType used, so an IPv6 address was typed as a domain.

    ion/web/ui/analyst.py holds a private copy of this decision for the
    command centre's own lookup, and _shared.py's docstring is explicit
    that a second page needing a function is what earns it a place there.
    It is not moved in this commit because analyst.py is not a file this
    conversion owns and several page conversions are in flight in the same
    package; unifying the two is a follow-up, named in the report rather
    than left for someone to find.
    """
    text = value.strip()
    for length, name, _label in _HASH:
        if re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", text):
            return name
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if isinstance(address, ipaddress.IPv4Address):
        return "ipv4-addr"
    if isinstance(address, ipaddress.IPv6Address):
        return "ipv6-addr"
    if re.match(r"https?://", text, re.IGNORECASE):
        return "url"
    if "@" in text:
        return "email-addr"
    return "domain-name"


def type_label(name: str) -> str:
    """The word a reader sees for an OpenCTI type.

    Falls back to the type itself rather than to a guess. The browser's
    detectIOCType was a separate vocabulary that could disagree with the
    type the request carried, and on this page it always did, because the
    request carried none.
    """
    return _TYPE_LABELS.get(name, name)


def _as_dict(result: object) -> Optional[dict]:
    """A JSON object out of a dict or a JSONResponse.

    `enrich_observable` and `enrich_batch` both return a JSONResponse 503
    when OpenCTI is disabled or unconfigured, and a dict when they ran.
    htmx will not swap a non-2xx response, so the fragment is always 200
    and the body is what the JSON route would have said. A body that is
    not an object is not a result.
    """
    if isinstance(result, JSONResponse):
        try:
            data = json.loads(result.body)
        except (TypeError, ValueError):
            return None
        return data if isinstance(data, dict) else None
    if isinstance(result, dict):
        return result
    dump = getattr(result, "model_dump", None) or getattr(result, "dict", None)
    if dump is None:
        return None
    data = dump()
    return data if isinstance(data, dict) else None


def _score(payload: dict) -> Optional[int | float]:
    """`observable.score` when that key is present, otherwise the top level.

    The service nests the score under `observable`. The page read a flat
    `data.score`, which does not exist, so it showed nothing for a real
    hit. A present key whose value is 0 is a measured score and must not
    fall through to another field: OpenCTI's zero means known and assessed
    as benign, which is a finding.
    """
    observable = payload.get("observable")
    if isinstance(observable, dict) and "score" in observable:
        return _number(observable.get("score"))
    if "score" in payload:
        return _number(payload.get("score"))
    return None


def _labels(raw: object) -> list:
    """Label values. A label is `{value, color}`, not a string.

    `escapeHtml(l)` on one of those renders "[object Object]". The colour
    is dropped on purpose: a view model carrying a colour makes every
    reader of it inherit OpenCTI's palette, and the stylesheet paints a
    label chip.
    """
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw:
        text = _text(item.get("value")) if isinstance(item, dict) else _text(item)
        if text is not None:
            out.append(text)
    return out


def _description(payload: dict) -> Optional[str]:
    text = _text(payload.get("description"))
    if text is None:
        observable = payload.get("observable")
        if isinstance(observable, dict):
            text = _text(observable.get("description"))
    if text is None:
        return None
    if len(text) > DESCRIPTION_CAP:
        return text[:DESCRIPTION_CAP] + "..."
    return text


def _named_rows(raw: object, *keys: str) -> list:
    """Related entities as `{name, detail}`, capped.

    These three lists are what the response actually carries. The page
    rendered `data.relationships`, which the service never returns, so the
    Related Entities table was dead code and every real indicator, threat
    actor and report went unshown.
    """
    if not isinstance(raw, list):
        return []
    out = []
    for item in raw[:RELATED_CAP]:
        if not isinstance(item, dict):
            continue
        name = None
        for key in keys:
            name = _text(item.get(key))
            if name is not None:
                break
        if name is None:
            continue
        out.append({
            "name": name,
            "score": _number(item.get("score")),
        })
    return out


def _found(payload: dict) -> Optional[bool]:
    """True, False, or None when the response did not say.

    Identity, not truthiness: `found: "no"` is neither boolean and must not
    be read as a hit, and a response with no `found` key at all has not
    told us either way.
    """
    value = payload.get("found")
    return value if value is True or value is False else None


def _ioc_view(payload: dict, value: str, name: str) -> IocPanel:
    view: IocPanel = {
        "view": "ioc", "failed": False,
        "value": value,
        "ioc_type": name,
        "label": type_label(name),
        "error": _text(payload.get("error")),
        "found": _found(payload),
        "score": _score(payload),
        "labels": _labels(payload.get("labels")),
        "description": _description(payload),
        "indicators": _named_rows(payload.get("indicators"), "name", "pattern"),
        "threat_actors": _named_rows(payload.get("threat_actors"), "name"),
        "reports": _named_rows(payload.get("reports"), "name"),
        # One value, then the template's safe_url filter. Mixing a literal
        # "&" with an escaped variable is how a query was double-escaped.
        "observables_url": "/observables?search=" + quote(value, safe=""),
    }
    return view


def _ioc_failed(value: str, name: str) -> IocPanel:
    panel: IocPanel = {
        "view": "ioc", "failed": True, "value": value, "ioc_type": name,
        "label": type_label(name), "error": None, "found": None, "score": None,
        "labels": [], "description": None, "indicators": [],
        "threat_actors": [], "reports": [],
        "observables_url": "/observables?search=" + quote(value, safe=""),
    }
    return panel


@router.post(
    "/tools/ioc",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
async def tools_ioc(
    request: Request,
    value: str = Form(""),
    current_user: User = Depends(require_permission(ALERT_READ)),
) -> HTMLResponse:
    """One indicator, typed and then handed to POST /api/opencti/enrich.

    An empty value is a bad request rather than a failed lookup: the
    failure sentence is reserved for a check that did not run, and htmx
    leaves the panel alone on a 422 so the reader keeps the previous
    result instead of being told it failed.
    """
    from ion.web.api import OpenCTIEnrichRequest, enrich_observable

    text = value.strip()
    if not text:
        raise HTTPException(status_code=422, detail="An IOC is required")
    name = ioc_type(text)
    try:
        result = await enrich_observable(
            OpenCTIEnrichRequest(type=name, value=text),
            current_user=current_user,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("tools IOC fragment could not be rendered")
        return _render(request, _ioc_failed(text, name))
    payload = _as_dict(result)
    if payload is None:
        return _render(request, _ioc_failed(text, name))
    return _render(request, _ioc_view(payload, text, name))


def _bulk_values(raw: str) -> tuple[list, int, int]:
    """The pasted lines, de-duplicated, capped, and what was dropped.

    De-duplication is new and deliberate: the page looked up the same value
    once per line it appeared on, which on a pasted log extract is most of
    the request budget. `submitted` is how many distinct values were asked
    for and `dropped` how many were not, so a truncated run says so rather
    than ending quietly at fifty.
    """
    seen: list = []
    for line in raw.splitlines():
        text = line.strip()
        if text and text not in seen:
            seen.append(text)
    return seen[:BULK_LIMIT], len(seen[:BULK_LIMIT]), max(0, len(seen) - BULK_LIMIT)


def _bulk_row(raw: object, asked: Optional[dict] = None) -> Optional[dict]:
    if not isinstance(raw, dict):
        return None
    value = _text(raw.get("value")) or (asked or {}).get("value")
    if value is None:
        return None
    name = _text(raw.get("type")) or (asked or {}).get("type") or ""
    return {
        "value": value,
        "ioc_type": name,
        "label": type_label(name),
        "score": _score(raw),
        "found": _found(raw),
        "error": _text(raw.get("error")),
    }


@router.post(
    "/tools/ioc-bulk",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
async def tools_ioc_bulk(
    request: Request,
    values: str = Form(""),
    current_user: User = Depends(require_permission(ALERT_READ)),
) -> HTMLResponse:
    """Many indicators through POST /api/opencti/enrich/batch.

    One request instead of one per line. The page issued a sequential fetch
    per pasted line from the browser, unbounded, so a thousand lines were a
    thousand round trips and the reader watched a single "Looking up 1000
    IOCs..." line until the last one came back.
    """
    from ion.web.api import OpenCTIEnrichBatchRequest, enrich_batch

    pasted, submitted, dropped = _bulk_values(values)
    if not pasted:
        raise HTTPException(status_code=422, detail="At least one IOC is required")
    observables = [{"type": ioc_type(v), "value": v} for v in pasted]
    try:
        result = await enrich_batch(
            OpenCTIEnrichBatchRequest(observables=observables),
            current_user=current_user,
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("tools bulk IOC fragment could not be rendered")
        return _render(request, _bulk_failed(submitted, dropped))
    payload = _as_dict(result)
    if payload is None:
        return _render(request, _bulk_failed(submitted, dropped))
    results = payload.get("results")
    if not isinstance(results, list):
        return _render(request, _bulk_failed(submitted, dropped))

    rows = []
    for index, raw in enumerate(results):
        asked = observables[index] if index < len(observables) else None
        row = _bulk_row(raw, asked)
        if row is not None:
            rows.append(row)
    view: BulkPanel = {
        "view": "bulk", "failed": False, "rows": rows,
        "error": _text(payload.get("error")),
        # The endpoint's own tally, not a count of the rows that rendered.
        # `data.found !== false && data.data.length > 0` never matched, so
        # the page reported every value as not found.
        "found_count": _number(payload.get("found")),
        "submitted": submitted, "dropped": dropped, "limit": BULK_LIMIT,
    }
    return _render(request, view)


def _bulk_failed(submitted: int, dropped: int) -> BulkPanel:
    panel: BulkPanel = {
        "view": "bulk", "failed": True, "rows": [], "error": None,
        "found_count": None, "submitted": submitted, "dropped": dropped,
        "limit": BULK_LIMIT,
    }
    return panel


@router.get(
    "/tools/translator-languages",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(ALERT_READ))],
)
def tools_translator_languages(
    request: Request,
    current_user: User = Depends(require_permission(ALERT_READ)),
) -> HTMLResponse:
    """Both language pickers, from GET /api/translator/languages.

    The page built these with createElement in a loop, which the status
    tool does not count as a DOM write and which is nonetheless a second
    definition of a list the server already has. Rendering them here means
    the "target cannot be auto" rule lives in one place; in the browser it
    was an early `return` inside the loop that a reader had to spot.
    """
    from ion.web.translator_api import get_languages

    try:
        payload = get_languages(_user=current_user)
    except Exception:
        logger.exception("tools translator languages fragment failed")
        return _render(request, _languages_failed())
    found = payload.get("languages") if isinstance(payload, dict) else None
    if not isinstance(found, list):
        return _render(request, _languages_failed())
    languages = []
    for item in found:
        if not isinstance(item, dict):
            continue
        code = _text(item.get("code"))
        label = _text(item.get("label"))
        if code is None or label is None:
            continue
        languages.append({"code": code, "label": label})
    if not languages:
        return _render(request, _languages_failed())
    view: LanguagesPanel = {
        "view": "languages", "failed": False, "languages": languages,
        "source_default": AUTO_CODE, "target_default": "en",
        "auto_code": AUTO_CODE,
    }
    return _render(request, view)


def _languages_failed() -> LanguagesPanel:
    """No pickers rather than empty ones.

    An empty <select> next to a Translate button is a control that looks
    usable and submits nothing. The page's `if (!r.ok) return` left exactly
    that: two empty dropdowns and no explanation.
    """
    panel: LanguagesPanel = {
        "view": "languages", "failed": True, "languages": None,
        "source_default": AUTO_CODE, "target_default": "en",
        "auto_code": AUTO_CODE,
    }
    return panel


#: Which template renders which panel, so the discriminator and the file it
#: reaches are one mapping rather than a `name=` repeated per call site.
_FRAGMENT_OF = {
    "ioc": IOC,
    "bulk": IOC_BULK,
    "languages": LANGUAGES,
}
