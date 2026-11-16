"""The render page: the variables form, the section cards and the output pane.

template_render.html built all three in the browser, across eight innerHTML
sites and 560 lines of inline JavaScript: the variables form and its
"no variables" state, the section cards and their "could not load" state,
the live re-render of one section while it is edited, and three forms of the
output pane. With them went a field-type guesser of nine regexes, three
hard-coded option lists, a 36-word list deciding which variables get a
textarea, a label formatter and a markdown section splitter.

Four things here are not a straight port.

`loadSections()` caught a failed preview and wrote "Could not load sections.
Click Preview to try again." into the card area, which is honest, but
`renderTemplate()`'s own catch wrote the error into the output pane and then
called `buildSectionCards(splitMarkdownSections(undefined))`, which threw
inside the catch and left the cards as they were, showing the previous
render's sections next to an error about this one.

A variable the template declares nothing about and a variable it declares as
optional both rendered with no marker, so "nobody said whether this is
required" and "this is not required" were the same pixel. They are kept
apart here, and the form says how many of its fields had their input type
guessed from the variable's name because nothing was declared.

The page's `detectFieldType` ran on every variable twice, once to build the
field and once more per variable inside `autoFillDefaults`, and the two
could disagree about nothing because they were the same function. It runs
once per variable here and the answer travels with the field, which is also
what lets Auto-fill Defaults restore a default the server computed.

And the markdown-to-HTML step is the one thing that did not move to the
server. ION has no HTML sanitiser in its dependencies, `markdown.markdown`
passes raw HTML and `javascript:` hrefs straight through, and this content
is a template filled in with values a user typed, so rendering it here and
marking it safe would be a cross-site scripting hole on a document
renderer. The markdown is sent as text, inside a textarea, and the page's
existing `safeMarkdown` (marked plus DOMPurify) paints it. The surrounding
`.rendered-content` rules in frontend/ion-daisy-theme.css already style
those generated elements by descendant selector, so the restyling argument
for moving markup to the server does not apply to this one case.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.core.exceptions import RenderError, TemplateNotFoundError
from ion.web.api import Services, get_services, template_payload, template_variables_payload
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

VARIABLES_FRAGMENT = "_fragments/template_render_variables.html"
SECTIONS_FRAGMENT = "_fragments/template_render_sections.html"
OUTPUT_FRAGMENT = "_fragments/template_render_output.html"

#: Matches GET /api/templates/{id}, GET /api/templates/{id}/variables and
#: POST /api/templates/{id}/preview, which are the three reads this page
#: makes. All three gate on template:read.
#:
#: POST /api/templates/{id}/render gates on document:create instead, because
#: it writes a document. That endpoint is still what Save as Document calls,
#: and it still refuses on its own; the button is withheld below from a
#: viewer who does not hold the permission, so the only way to learn the
#: server would refuse is no longer to click and read the error.
_PERM = "template:read"

#: What Save as Document needs. The page itself is gated on template:read,
#: so a viewer can reach this page and not be allowed to save from it.
_SAVE_PERM = "document:create"

#: The page's detectFieldType, in order, because the order decides: a
#: variable named `assessment_date` matches the date rule before the
#: textarea word list would catch "assessment".
#:
#: `search`, not `fullmatch`, because the patterns carry their own anchors
#: and some are deliberately unanchored at one end. Lifted verbatim from the
#: page so a name that got a date picker still gets one.
_FIELD_RULES: list[tuple[str, str, str, bool, Optional[str]]] = [
    (
        r"(^date$|_date$|^effective|^last_updated|_datetime$|^created|^updated"
        r"|^completion|^assessment_date|^detection)",
        "date", "date", True, "Auto-filled with today's date",
    ),
    (r"(^version$|_version$)", "version", "text", True,
     "Auto-filled with 1.0"),
    (r"(^author$|^prepared_by$|^completed_by$|^assessor$|^reported_by$"
     r"|^approved_by$)",
     "author", "text", True, "Auto-filled from preferences"),
    (r"(^classification$|^security_classification$)", "classification",
     "select", True, "Auto-filled from preferences"),
    (r"(^severity$|^priority$|^risk_level$)", "severity", "select", False, None),
    (r"(_count$|_number$|^count_|^num_)", "number", "number", False, None),
    (r"(^review_cycle$)", "review_cycle", "select", True,
     "Common review periods"),
]

#: Substring match on the lower-cased variable name, as the page's
#: shouldUseTextarea did. A name containing any of these gets a textarea.
_TEXTAREA_WORDS = (
    "description", "content", "body", "text", "notes", "details",
    "summary", "overview", "purpose", "scope", "procedure", "steps",
    "instructions", "responsibilities", "requirements", "narrative",
    "background", "situation", "mission", "execution", "assessment",
    "findings", "analysis", "recommendations", "checklist", "matrix",
    "impact", "remediation", "lessons", "appendices", "references",
    "definitions", "timeline", "iocs", "resources", "considerations",
)

#: The three option lists the page spelled out as concatenated HTML.
_SELECT_OPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "classification": (
        "-- Select Classification --",
        ("UNCLASSIFIED", "FOR OFFICIAL USE ONLY", "CONFIDENTIAL", "SECRET",
         "TOP SECRET"),
    ),
    "severity": (
        "-- Select Severity --",
        ("Critical", "High", "Medium", "Low", "Informational"),
    ),
    "review_cycle": (
        "-- Select Review Cycle --",
        ("Monthly", "Quarterly", "Semi-Annual", "Annual", "As Needed"),
    ),
}

#: What Auto-fill Defaults puts in a field of each kind, where the value is
#: the same for everyone. `author` and `classification` are absent on
#: purpose: those two come from the viewer's own stored preferences, which
#: only the browser holds, so the page fills them and the server does not
#: pretend to know them.
_STATIC_DEFAULTS = {"version": "1.0", "review_cycle": "Annual"}

#: A `## 3. Findings` heading starts a new section. The rest is the document
#: header, which is why the first part is titled rather than dropped.
_SECTION_HEADING = re.compile(r"^## (\d+)\.\s+(.+)")


def field_kind(name: str) -> dict[str, Any]:
    """The input a variable gets, from its name alone.

    A port of detectFieldType. It is a guess and the form says so: nothing
    about the variable declares its type, so the name is all there is.
    """
    lowered = (name or "").lower()
    for pattern, kind, input_type, auto_fill, hint in _FIELD_RULES:
        if re.search(pattern, lowered):
            return {
                "kind": kind,
                "input": input_type,
                "auto_fill": auto_fill,
                "hint": hint,
            }
    if any(word in lowered for word in _TEXTAREA_WORDS):
        return {"kind": "textarea", "input": "textarea", "auto_fill": False,
                "hint": None}
    return {"kind": "text", "input": "text", "auto_fill": False, "hint": None}


def format_label(name: str) -> str:
    """`prepared_by` to `Prepared By`, as the page's formatLabel did."""
    spaced = (name or "").replace("_", " ")
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", spaced)
    # JavaScript's \b\w on a string of words: upper-case the first letter of
    # each run. re.sub with a word-boundary lookbehind matches the same set.
    return re.sub(r"\b\w", lambda m: m.group(0).upper(), spaced)


def _default_value(kind: str, today: str) -> Optional[str]:
    """What the server can honestly pre-fill for a field of this kind.

    `today` is the caller's, computed once per request so every date field
    on one form agrees. It is UTC, which is what the page's
    `new Date().toISOString().split('T')[0]` produced: toISOString is UTC,
    so this is the same date the page filled in and not the server's local
    one. A date rendered from the server's own local clock would be a day
    out for half the world, which is the same mistake as formatting a
    timestamp server-side.
    """
    if kind == "date":
        return today
    return _STATIC_DEFAULTS.get(kind)


def variable_view(name: str, meta: Optional[dict], today: str) -> dict[str, Any]:
    """One row of the variables form.

    `described` carries whether the template says anything at all about this
    variable. The page did `varMeta[varName] || {}` and then tested
    `meta.required`, which made an undeclared variable and a variable
    declared as not required render identically.
    """
    kind = field_kind(name)
    options: list[str] = []
    placeholder = ""
    required: Optional[bool] = None
    default_value: Optional[str] = None
    input_type = kind["input"]

    if meta is not None:
        # required is nullable=False on the column, so a row always has a
        # real boolean. None here means there is no row at all.
        required = bool(meta.get("required"))
        declared = meta.get("default_value")
        if declared is not None and declared != "":
            default_value = str(declared)
        declared_options = meta.get("options")
        if isinstance(declared_options, list) and declared_options:
            # A declared option list wins over the guess: the template says
            # what the values are, so the name no longer has to be read.
            options = [str(o) for o in declared_options]
            input_type = "options"

    if input_type in ("text", "textarea", "number"):
        placeholder = default_value or (
            "Enter " + format_label(name).lower() + "..."
        )

    prompt = ""
    if input_type == "select":
        prompt, choices = _SELECT_OPTIONS.get(kind["kind"], ("", ()))
        options = list(choices)
    elif input_type == "options":
        prompt = "-- Select " + format_label(name) + " --"

    return {
        "name": name,
        "label": format_label(name),
        "kind": kind["kind"],
        "input": input_type,
        "auto_fill": kind["auto_fill"],
        "hint": kind["hint"],
        "described": meta is not None,
        "required": required,
        "options": options,
        "prompt": prompt,
        "placeholder": placeholder,
        # The value the field is rendered with and the value Auto-fill
        # Defaults restores. Both come from here so the button cannot put
        # something different in from what the first render showed.
        "default": default_value if default_value is not None
        else _default_value(kind["kind"], today),
    }


def variables_view(payload: dict) -> dict[str, Any]:
    """The whole form, from the payload the JSON endpoint returns."""
    meta_by_name = {
        str(entry.get("name")): entry for entry in payload.get("defined") or ()
    }
    today = datetime.now(timezone.utc).date().isoformat()
    fields = [
        variable_view(str(name), meta_by_name.get(str(name)), today)
        for name in payload.get("extracted") or ()
    ]
    return {
        "fields": fields,
        # A count, not a flag. `is not None` guards it in the template,
        # because zero undescribed variables is the good news and a
        # truthiness test renders it the same as not having counted.
        "undescribed": sum(1 for f in fields if not f["described"]),
        "total": len(fields),
    }


def split_sections(rendered: Optional[str]) -> list[dict[str, Any]]:
    """The rendered document split on its numbered headings.

    A port of splitMarkdownSections. Each part keeps its own markdown; the
    conversion to HTML happens in the browser, for the reason in the module
    docstring.
    """
    if rendered is None:
        return []
    parts: list[dict[str, Any]] = []
    current: dict[str, Any] = {"title": "Document Header", "num": "", "lines": []}
    for line in rendered.split("\n"):
        match = _SECTION_HEADING.match(line)
        if match:
            parts.append(current)
            current = {
                "title": match.group(2).strip(),
                "num": match.group(1),
                "lines": [line],
            }
        else:
            current["lines"].append(line)
    parts.append(current)

    out = []
    for part in parts:
        markdown = "\n".join(part["lines"]).strip()
        if not markdown:
            continue
        out.append(
            {
                "title": part["title"],
                "num": part["num"],
                "markdown": markdown,
                # The header part carries no number and opens by default,
                # which is what the page's `isHeader` did.
                "is_header": not part["num"],
                "label": ("S" + part["num"]) if part["num"] else "HDR",
            }
        )
    # The index is assigned after the empty parts are dropped, so it matches
    # the position in the list the page renders and the order the save
    # reassembles. Numbering before the filter would leave gaps and the
    # assembled document would be missing a section.
    for idx, section in enumerate(out):
        section["idx"] = idx
    return out


def _parse_data(data_json: Optional[str]) -> dict:
    """The variable values out of the form field carrying them.

    The page's JSON tab let a variable hold a number, a list or an object,
    which the form tab cannot express, so the textarea is the one source and
    both tabs are kept in sync by the page. An empty field is an empty
    object, which is what the textarea is initialised to.
    """
    parsed = json.loads(data_json or "{}")
    if not isinstance(parsed, dict):
        raise ValueError(f"render data is not an object: {type(parsed).__name__}")
    return parsed


def _preview(services: Services, template_id: int, data: dict) -> str:
    """The rendered document, via the function the JSON endpoint calls."""
    return services.render.preview(template_id, data=data)


@router.get("/template-render/variables", response_class=HTMLResponse)
def template_render_variables_fragment(
    request: Request,
    template_id: int = Query(...),
    user=Depends(require_permission(_PERM)),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The variables form, replacing two innerHTML sites.

    It calls `template_variables_payload` and `template_payload`, which are
    what GET /api/templates/{id}/variables and GET /api/templates/{id} call,
    so the extracted/declared pair and the template's name and format have
    one definition each.

    The template's name is swapped into the page heading out of band, which
    is how the heading stops saying "Loading..." without a second request
    for one word. On a failed read it says so there too, rather than
    leaving the word "Loading..." on screen for ever.

    Save as Document is rendered only for a viewer holding document:create,
    which is what POST /api/templates/{id}/render requires. The page offered
    it to everyone and let the server refuse.
    """
    context: dict[str, Any] = {
        "template_id": template_id,
        "name": None,
        "format": None,
        "variables": None,
        "failed": False,
        "not_found": False,
        "can_save": user.has_permission(_SAVE_PERM),
    }

    try:
        info = template_payload(services, template_id)
        payload = template_variables_payload(services, template_id)
    except TemplateNotFoundError:
        context["not_found"] = True
        return templates.TemplateResponse(
            request=request, name=VARIABLES_FRAGMENT, context=context
        )
    except Exception:
        logger.exception(
            "Template %s could not be read for its render form", template_id
        )
        context["failed"] = True
        return templates.TemplateResponse(
            request=request, name=VARIABLES_FRAGMENT, context=context
        )

    context.update(
        {
            "name": info.get("name"),
            "format": info.get("format"),
            "variables": variables_view(payload),
        }
    )
    return templates.TemplateResponse(
        request=request, name=VARIABLES_FRAGMENT, context=context
    )


def _sections_context(
    services: Services, template_id: int, data_json: Optional[str]
) -> dict[str, Any]:
    """The section cards for one preview, or the reason there are none.

    Three failure states, not one. The data would not parse; the template
    would not render with it, which is the one the user can act on and whose
    message names the offending expression; or the read itself failed.
    """
    context: dict[str, Any] = {
        "sections": None,
        "failed": False,
        "not_found": False,
        "data_invalid": False,
        "render_error": None,
    }
    try:
        data = _parse_data(data_json)
    except Exception:
        logger.exception("Render data could not be parsed")
        context["data_invalid"] = True
        return context

    try:
        context["sections"] = split_sections(_preview(services, template_id, data))
    except TemplateNotFoundError:
        context["not_found"] = True
    except RenderError as exc:
        # The template's own error, worth showing: it names the variable or
        # the expression that stopped the render.
        logger.exception("Template %s could not be previewed", template_id)
        context["render_error"] = str(exc)
    except Exception:
        logger.exception(
            "Template %s sections could not be read", template_id
        )
        context["failed"] = True
    return context


@router.post("/template-render/sections", response_class=HTMLResponse)
def template_render_sections_fragment(
    request: Request,
    template_id: int = Form(...),
    data_json: Optional[str] = Form(None),
    user=Depends(require_permission(_PERM)),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The document's sections for the current variable values.

    POST because the variable values travel in the body: a document's prose
    has no length limit and a query string does.

    This is the page's `loadSections()`. It is not a save: nothing is
    written until Save as Document, which is still
    POST /api/templates/{id}/render.
    """
    return templates.TemplateResponse(
        request=request,
        name=SECTIONS_FRAGMENT,
        context=_sections_context(services, template_id, data_json),
    )


@router.post("/template-render/output", response_class=HTMLResponse)
def template_render_output_fragment(
    request: Request,
    template_id: int = Form(...),
    data_json: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    user=Depends(require_permission(_PERM)),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The output pane, and the section cards with it.

    Two callers and two modes. Preview sends the variable values and this
    runs the same `services.render.preview` the JSON endpoint runs. Save as
    Document has already written the document through
    POST /api/templates/{id}/render and sends back the content that was
    stored, because that is what the user should be looking at: a fresh
    preview would re-render from the template and silently drop the section
    edits the save just kept.

    One response paints both panes, the output by swap and the cards out of
    band, which is what the page's renderTemplate() did from one fetch. Two
    requests could land in either order and leave an output pane and a set
    of cards describing different renders.

    `format` decides how the output is presented, read from the template
    rather than from a variable the page happened to still hold: its
    `templateInfo` was null until the first load finished and null again if
    that load failed, and `templateInfo && format === 'markdown'` then chose
    the preformatted branch for a markdown template.
    """
    context: dict[str, Any] = {
        "template_id": template_id,
        "rendered": None,
        "format": None,
        "failed": False,
        "not_found": False,
        "data_invalid": False,
        "render_error": None,
        "sections": None,
    }

    try:
        context["format"] = template_payload(services, template_id).get("format")
    except TemplateNotFoundError:
        context["not_found"] = True
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )
    except Exception:
        logger.exception(
            "Template %s could not be read to present its output", template_id
        )
        context["failed"] = True
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )

    if content is not None:
        # Display mode: the document that was just saved.
        context["rendered"] = content
        context["sections"] = split_sections(content)
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )

    try:
        data = _parse_data(data_json)
    except Exception:
        logger.exception("Render data could not be parsed")
        context["data_invalid"] = True
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )

    try:
        rendered = _preview(services, template_id, data)
    except RenderError as exc:
        logger.exception("Template %s could not be previewed", template_id)
        context["render_error"] = str(exc)
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )
    except Exception:
        logger.exception("Template %s could not be previewed", template_id)
        context["failed"] = True
        return templates.TemplateResponse(
            request=request, name=OUTPUT_FRAGMENT, context=context
        )

    context["rendered"] = rendered
    context["sections"] = split_sections(rendered)
    return templates.TemplateResponse(
        request=request, name=OUTPUT_FRAGMENT, context=context
    )
