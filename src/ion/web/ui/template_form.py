"""The template editor: the form, the section library and the section cards.

template_form.html built its whole section editor in the browser. Four
innerHTML sites across 660 lines of inline JavaScript: the library tile, a
card's header, a card's body (nine field builders, six of them list
builders), and the inline Add Section button between cards. Alongside them
sat a second definition of every default a section type carries, a second
definition of each card's title, a variable-name suggester, and a
`sectionToPreview()` that assembled Jinja2 a second time.

Three things here are not a straight port.

The form was filled in by script from GET /api/templates/{id}, and a failed
read only raised a toast: the fields stayed empty and the Save button stayed
live. Saving then sent `content: ''` because the sections array was empty,
which overwrites the stored template body with nothing. A read that failed
now renders no form at all, so there is nothing to submit.

The section editor's structural edits (add, remove, move, add or remove a
list item, convert a legacy template) are applied here rather than in the
browser, so `SECTION_TYPES` is read in one place and a section's default
config has one definition. The edits are not saves: nothing reaches the
database until the form is submitted, which is still a JSON POST or PUT to
/api/templates exactly as before.

And Preview now shows what the server will actually store, by calling
`assemble_jinja2`, the function create_template and update_template call.
The page's own `sectionToPreview()` was a reimplementation of it, so the
preview could and did disagree with the saved content.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.core.exceptions import TemplateNotFoundError
from ion.web.api import Services, get_services, template_payload
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/template_form.html"
LIBRARY_FRAGMENT = "_fragments/template_form_library.html"
SECTIONS_FRAGMENT = "_fragments/template_form_sections.html"

#: Matches GET /api/templates/{id}, GET /api/templates/section-types and
#: GET /api/document-types, the three reads this page made. All three gate on
#: template:read, so every fragment here does too.
#:
#: Not template:create or template:update. Those gate the save, which is
#: still POST/PUT /api/templates and still refuses on its own. Gating the
#: editor's re-render on a write permission would make a fragment stricter
#: than the API it mirrors, which is the other half of the rule.
_PERM = "template:read"

#: The title shown on a collapsed card, per section type. The page spelled
#: this out as a switch; it is a table here because every arm had the same
#: shape, a format string over the section's own config.
_TITLE_VARIABLE = {
    "severity_badge": ("Severity: {{{{ {} }}}}", "variable_name", "severity"),
    "ioc_table": ("IOC Table: {{{{ {} }}}}", "variable_name", "ioc_list"),
    "timeline": ("Timeline: {{{{ {} }}}}", "variable_name", "timeline_entries"),
    "mitre_table": ("MITRE: {{{{ {} }}}}", "variable_name", "mitre_techniques"),
}

#: How many characters of a text section's content become its card title.
_TITLE_CHARS = 50

#: How long a suggested variable name may be, and how much of a text
#: section's content is considered when suggesting one.
_VAR_NAME_CHARS = 30


def _section_types() -> dict[str, dict]:
    """The section-type table, read from the module the JSON endpoint reads.

    GET /api/templates/section-types returns SECTION_TYPES unchanged, so
    importing it is reusing that endpoint's whole body. A second copy of
    this table is how a field added to a section type stops appearing in
    the editor while still being assembled into the content.
    """
    from ion.services.section_types import SECTION_TYPES

    return SECTION_TYPES


def _slug(text: str) -> str:
    """Lower-case, non-alphanumerics collapsed to one underscore, trimmed."""
    slugged = re.sub(r"[^a-z0-9]+", "_", text.lower())
    return slugged.strip("_")


def suggest_variable_name(section: dict, type_def: dict) -> str:
    """The variable name the editor offers for a section that has none.

    A port of the page's suggestVarName. The two substring limits are the
    page's own and are kept: the first bounds how much prose is considered,
    the second bounds the name.
    """
    config = section.get("config") or {}
    stype = section.get("type") or ""
    if stype == "text":
        base = str(config.get("content") or "")[:_VAR_NAME_CHARS]
    elif stype == "heading":
        base = str(config.get("text") or "")
    else:
        base = str(type_def.get("label") or stype)
    return _slug(base)[:_VAR_NAME_CHARS] or stype


def section_title(section: dict, type_def: dict) -> str:
    """The one-line title on a card header.

    `len(...)` over a list that may be absent, never truthiness: a table
    with zero columns reads "Table (0 cols)", which is the state worth
    seeing because it assembles to nothing at all.
    """
    config = section.get("config") or {}
    stype = section.get("type") or ""

    if stype in _TITLE_VARIABLE:
        pattern, key, default = _TITLE_VARIABLE[stype]
        return pattern.format(config.get(key) or default)

    if stype == "heading":
        return str(config.get("text") or "Heading")
    if stype == "text":
        if config.get("variable"):
            return "{{ " + str(config.get("variable_name") or "...") + " }}"
        return str(config.get("content") or "Text")[:_TITLE_CHARS]
    if stype == "table":
        return f"Table ({len(config.get('columns') or [])} cols)"
    if stype == "list":
        return ("Ordered" if config.get("ordered") else "Unordered") + " List"
    if stype == "key_value":
        return f"Key-Value ({len(config.get('pairs') or [])} pairs)"
    if stype == "divider":
        return "Horizontal Rule"
    if stype == "metadata_block":
        return f"Metadata ({len(config.get('fields') or [])} fields)"
    if stype == "signature_block":
        return f"Signatures ({len(config.get('roles') or [])} roles)"
    if stype == "image_placeholder":
        return str(config.get("caption") or "Image")
    if stype == "checklist":
        return f"Checklist ({len(config.get('items') or [])} items)"
    if stype == "evidence_block":
        return "Evidence: " + str(config.get("source") or "...")
    return str(type_def.get("label") or stype)


def default_config(type_def: dict) -> dict[str, Any]:
    """The config a freshly added section of this type starts with.

    A port of the page's buildDefaultConfig, with one difference that
    matters. The page wrote `f.default !== undefined`, which is the right
    test, and then `f.default || false` and `f.default || options[0].value`
    in two later arms, which is not: a field declaring a default of 0 or
    false would have had it dropped. Those arms are only reached when the
    field declares no default at all, so the behaviour is the same today
    and stays right if a section type ever declares `"default": 0`.
    """
    config: dict[str, Any] = {}
    for field in type_def.get("fields") or ():
        name = field.get("name")
        if name is None:
            continue
        if "default" in field:
            config[name] = field["default"]
            continue
        ftype = field.get("type")
        if ftype in ("text", "textarea"):
            config[name] = ""
        elif ftype == "select":
            options = field.get("options") or ()
            if options:
                config[name] = options[0].get("value")
        elif ftype == "checkbox":
            config[name] = False
        elif ftype in ("items", "checklist_items", "pairs"):
            config[name] = []
        elif ftype == "columns":
            config[name] = [{"name": "Column 1"}]
        elif ftype == "metadata_fields":
            config[name] = [{"label": "Date", "variable_name": "date"}]
        elif ftype == "signature_roles":
            config[name] = [
                {"role_name": "Prepared By", "variable_name": "prepared_by"}
            ]
    return config


#: What a new row in each kind of list field looks like. The page spelled
#: this out as an if-chain inside addListItem; the list kind is already a
#: value travelling from the template to the request, so it keys a table.
_NEW_LIST_ITEM: dict[str, Any] = {
    "pairs": {"label": "", "value": ""},
    "columns": {"name": ""},
    "metadata": {"label": "", "variable_name": ""},
    "signatures": {"role_name": "", "variable_name": ""},
    "checklist": {"text": "", "checked": False},
}

#: Which list shape each field type renders as. The page carried this twice,
#: once as `data-list-type` written into the markup and once as the if-chain
#: in addListItem that read it back.
_LIST_KIND = {
    "items": "items",
    "checklist_items": "checklist",
    "pairs": "pairs",
    "columns": "columns",
    "metadata_fields": "metadata",
    "signature_roles": "signatures",
}


def _list_rows(kind: str, raw: object) -> list[dict[str, Any]]:
    """One list field's rows, normalised for the template.

    Each shape accepts the legacy bare string the page accepted, because
    stored sections predate the object form: `typeof item === 'string' ?
    item : (item.text || '')` appears in four of the page's six builders.
    """
    rows: list[dict[str, Any]] = []
    for item in raw or ():
        if kind == "pairs":
            rows.append(
                {"label": _text(item, "label"), "value": _text(item, "value")}
            )
        elif kind == "columns":
            rows.append({"name": _text(item, "name")})
        elif kind == "metadata":
            rows.append(
                {
                    "label": _text(item, "label"),
                    "variable_name": _text(item, "variable_name"),
                }
            )
        elif kind == "signatures":
            rows.append(
                {
                    "role_name": _text(item, "role_name"),
                    "variable_name": _text(item, "variable_name"),
                }
            )
        elif kind == "checklist":
            rows.append(
                {
                    "text": _text(item, "text"),
                    "checked": bool(
                        item.get("checked") if isinstance(item, dict) else False
                    ),
                }
            )
        else:
            rows.append({"text": _text(item, "text")})
    return rows


def _text(item: object, key: str) -> str:
    """A row's field, accepting the legacy bare-string row shape."""
    if isinstance(item, dict):
        value = item.get(key)
        return "" if value is None else str(value)
    return str(item) if item is not None else ""


def _field_view(field: dict, config: dict, idx: int) -> dict[str, Any]:
    """One editor control, as the template needs it.

    `value` resolves the stored value, then the field's declared default,
    then the empty string, with `is not None` at each step. The page wrote
    `config[f.name] !== undefined ? config[f.name] : (f.default || '')`,
    which renders a stored JSON null as the literal text "null" in the
    input, and drops a declared default of 0 or false.
    """
    ftype = field.get("type")
    name = field.get("name")
    stored = config.get(name)
    if stored is None:
        stored = field.get("default")
    view: dict[str, Any] = {
        "name": name,
        "label": field.get("label") or name,
        "type": ftype,
        "idx": idx,
        "value": "" if stored is None else str(stored),
        "checked": bool(stored),
        "options": [],
        "rows": [],
        "list_kind": _LIST_KIND.get(ftype or ""),
    }
    if ftype == "select":
        for option in field.get("options") or ():
            view["options"].append(
                {
                    "value": option.get("value"),
                    "label": option.get("label"),
                    # String comparison, as the page's
                    # `String(val) === String(o.value)` did, so a level
                    # stored as the number 2 still selects the "2" option.
                    "selected": view["value"] == str(option.get("value")),
                }
            )
    if view["list_kind"]:
        view["rows"] = _list_rows(view["list_kind"], config.get(name))
    return view


def _section_view(section: dict, idx: int, types: dict[str, dict]) -> dict[str, Any]:
    """One section card.

    `known` is carried rather than papered over. The page substituted
    `{label: section.type, icon: '?', fields: []}` for a type it did not
    recognise, which renders a card with no controls at all: the section is
    still in the template and still assembled into the content, but the
    editor shows nothing to edit and says nothing about why.
    """
    stype = section.get("type") or ""
    type_def = types.get(stype)
    known = type_def is not None
    if type_def is None:
        type_def = {"label": stype, "icon": "?", "fields": []}
    config = section.get("config") or {}

    stored_name = config.get("variable_name")
    return {
        "idx": idx,
        "type": stype,
        "known": known,
        "icon": type_def.get("icon"),
        "type_label": type_def.get("label"),
        "title": section_title(section, type_def),
        "fields": [
            _field_view(f, config, idx) for f in (type_def.get("fields") or ())
        ],
        "supports_variable": bool(type_def.get("supports_variable")),
        # Three states collapse to two here on purpose: the checkbox has no
        # third state to render. `config.variable` missing and false both
        # mean the box is clear, and the page's `c.variable || false` said
        # the same.
        "is_variable": bool(config.get("variable")),
        "variable_name": (
            str(stored_name)
            if stored_name
            else suggest_variable_name(section, type_def)
        ),
    }


def sections_view(sections: list[dict]) -> list[dict[str, Any]]:
    types = _section_types()
    return [_section_view(s, idx, types) for idx, s in enumerate(sections)]


def parse_state(raw: Optional[str]) -> list[dict]:
    """The editor state out of the form field carrying it.

    An absent field and an empty list are different: absent means this
    request carries no state, an empty list means the user deleted every
    section. The caller distinguishes them before calling, so anything that
    arrives here and is not a JSON list is a malformed state, which raises
    rather than quietly becoming an empty editor.
    """
    parsed = json.loads(raw or "[]")
    if not isinstance(parsed, list):
        raise ValueError(f"editor state is not a list: {type(parsed).__name__}")
    return [s for s in parsed if isinstance(s, dict)]


def apply_edit(
    sections: list[dict],
    op: Optional[str],
    *,
    index: Optional[int] = None,
    section_type: Optional[str] = None,
    insert_at: Optional[int] = None,
    direction: Optional[int] = None,
    field: Optional[str] = None,
    list_kind: Optional[str] = None,
    item_index: Optional[int] = None,
    legacy_content: Optional[str] = None,
) -> list[dict]:
    """The editor state after one structural edit.

    Pure, and total: an out-of-range index or an unknown section type
    returns the state unchanged rather than raising, which is what the
    page's own guards did (`if (!st) return;`, `if (newIdx < 0 ...) return;`).
    A stale index arrives whenever a click lands on markup the next render
    has already replaced, so refusing it has to be ordinary, not an error.
    """
    sections = [dict(s) for s in sections]

    if op is None:
        return sections

    if op == "add":
        types = _section_types()
        type_def = types.get(section_type or "")
        if type_def is None:
            return sections
        section = {
            "type": section_type,
            "config": default_config(type_def),
        }
        # The page's insertAtIndex contract: -1, or any index outside the
        # list, appends; otherwise the new section lands after that card.
        if insert_at is not None and 0 <= insert_at < len(sections):
            sections.insert(insert_at + 1, section)
        else:
            sections.append(section)
        return sections

    if op == "convert_legacy":
        # One text section holding the raw template body, which is what the
        # page's convertToSections built after re-fetching the template.
        return [
            {
                "type": "text",
                "config": {
                    "content": legacy_content or "",
                    "variable": False,
                    "variable_name": "",
                },
            }
        ]

    if index is None or not 0 <= index < len(sections):
        return sections

    if op == "remove":
        del sections[index]
        return sections

    if op == "move":
        target = index + (direction or 0)
        if not 0 <= target < len(sections):
            return sections
        sections[index], sections[target] = sections[target], sections[index]
        return sections

    if op in ("add_item", "remove_item") and field:
        config = dict(sections[index].get("config") or {})
        items = list(config.get(field) or ())
        if op == "add_item":
            new = _NEW_LIST_ITEM.get(list_kind or "", "")
            items.append(dict(new) if isinstance(new, dict) else new)
        elif item_index is not None and 0 <= item_index < len(items):
            del items[item_index]
        config[field] = items
        sections[index] = {**sections[index], "config": config}
        return sections

    return sections


def _sections_response(
    request: Request,
    sections: list[dict],
    *,
    legacy: bool = False,
    edit_failed: bool = False,
    state_failed: bool = False,
) -> HTMLResponse:
    """Render the section cards plus the input that carries their state."""
    return templates.TemplateResponse(
        request=request,
        name=SECTIONS_FRAGMENT,
        context={
            "sections": sections_view(sections),
            # The state the next request will send back. Re-emitted on every
            # branch including the failed ones, because a render that
            # dropped it would delete the user's unsaved sections.
            "sections_json": json.dumps(sections),
            # Whether this template still holds a raw body no section
            # describes. The page hid its legacy notice with a style
            # assignment once the conversion ran; it is derived here from
            # the two facts that make it true, so it is right again if the
            # user deletes the section the conversion produced.
            "legacy": legacy,
            "edit_failed": edit_failed,
            "state_failed": state_failed,
        },
    )


@router.get("/template-form", response_class=HTMLResponse)
def template_form_fragment(
    request: Request,
    template_id: Optional[int] = Query(None),
    user=Depends(require_permission(_PERM)),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The form fields and the section editor, filled in on the server.

    Replaces the page's DOMContentLoaded block: two fetches, a loop building
    `<option>` elements, five assignments of `.value`, and the legacy-notice
    reveal. `template_payload` is what GET /api/templates/{id} calls and
    `DOCUMENT_TYPES` is what GET /api/document-types returns, so neither the
    row shape nor the type list exists twice.

    Four outcomes, where the page had two. A new template; a template read
    successfully; a template id that does not exist; and a read that failed.
    The page showed the last two identically, as one toast over an empty
    form, and left Save live. Saving then sent the empty section list, which
    the API turns into `content: ''` and writes over the stored body.
    """
    from ion.services.soc_template_service import DOCUMENT_TYPES

    context: dict[str, Any] = {
        "template_id": template_id,
        "template": None,
        "sections": [],
        "sections_json": "[]",
        "document_types": DOCUMENT_TYPES,
        "failed": False,
        "not_found": False,
        "legacy": False,
    }

    if template_id is None:
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context
        )

    try:
        payload = template_payload(services, template_id)
    except TemplateNotFoundError:
        context["not_found"] = True
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context
        )
    except Exception:
        logger.exception("Template %s could not be read for the editor", template_id)
        context["failed"] = True
        return templates.TemplateResponse(
            request=request, name=FRAGMENT, context=context
        )

    sections = payload.get("sections") if payload.get("has_sections") else None
    sections = sections if isinstance(sections, list) else []
    context.update(
        {
            "template": payload,
            "sections": sections_view(sections),
            "sections_json": json.dumps(sections),
            # The notice offering to convert a raw template, shown on the
            # page's own condition: stored content and no stored sections.
            "legacy": not payload.get("has_sections") and bool(payload.get("content")),
        }
    )
    return templates.TemplateResponse(request=request, name=FRAGMENT, context=context)


@router.get("/template-form/library", response_class=HTMLResponse)
def template_form_library_fragment(
    request: Request,
    user=Depends(require_permission(_PERM)),
) -> HTMLResponse:
    """The section library's two grids, replacing the library innerHTML site.

    The panel's header and its Close button stay in the page shell. A render
    that said the library could not be read would otherwise take away the
    only way out of a full-height overlay.
    """
    generic: list[dict] = []
    soc: list[dict] = []
    failed = False
    try:
        for key, type_def in _section_types().items():
            tile = {
                "key": key,
                "icon": type_def.get("icon"),
                "label": type_def.get("label"),
                "description": type_def.get("description") or "",
            }
            (soc if type_def.get("category") == "soc" else generic).append(tile)
    except Exception:
        logger.exception("Section-type library could not be read")
        failed = True

    return templates.TemplateResponse(
        request=request,
        name=LIBRARY_FRAGMENT,
        context={"generic": generic, "soc": soc, "failed": failed},
    )


@router.post("/template-form/sections", response_class=HTMLResponse)
def template_form_sections_fragment(
    request: Request,
    sections: Optional[str] = Form(None),
    op: Optional[str] = Form(None),
    index: Optional[int] = Form(None),
    section_type: Optional[str] = Form(None),
    insert_at: Optional[int] = Form(None),
    direction: Optional[int] = Form(None),
    field: Optional[str] = Form(None),
    list_kind: Optional[str] = Form(None),
    item_index: Optional[int] = Form(None),
    template_id: Optional[int] = Form(None),
    legacy: bool = Form(False),
    user=Depends(require_permission(_PERM)),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The section cards after one structural edit of the unsaved state.

    POST because the whole editor state travels in the body. A section's
    text content has no length limit, so a GET would put a document's prose
    in a query string and lose it to the first request-line limit.

    This is not a save. Nothing here touches the database except
    `convert_legacy`, which reads the template to find the body it is
    wrapping. The template reaches storage only when the form is submitted,
    which is still POST or PUT /api/templates.

    An edit that fails leaves the state alone and says so, with the cards
    still rendered from it. The alternative, rendering an error in place of
    the editor, would throw away sections the user had not saved yet.
    """
    try:
        state = parse_state(sections)
    except Exception:
        logger.exception("Template editor state could not be parsed")
        # Nothing can be rendered from a state that would not parse, and
        # guessing an empty editor would read as "your sections are gone".
        return _sections_response(request, [], legacy=legacy, state_failed=True)

    legacy_content: Optional[str] = None
    if op == "convert_legacy":
        if template_id is None:
            return _sections_response(
                request, state, legacy=legacy, edit_failed=True
            )
        try:
            legacy_content = template_payload(services, template_id).get("content")
        except Exception:
            logger.exception(
                "Template %s could not be read to convert it to sections",
                template_id,
            )
            return _sections_response(
                request, state, legacy=legacy, edit_failed=True
            )

    try:
        edited = apply_edit(
            state,
            op,
            index=index,
            section_type=section_type,
            insert_at=insert_at,
            direction=direction,
            field=field,
            list_kind=list_kind,
            item_index=item_index,
            legacy_content=legacy_content,
        )
    except Exception:
        logger.exception("Template editor edit %r could not be applied", op)
        return _sections_response(request, state, legacy=legacy, edit_failed=True)

    return _sections_response(request, edited, legacy=legacy)


@router.post("/template-form/preview", response_class=HTMLResponse)
def template_form_preview_fragment(
    request: Request,
    sections: Optional[str] = Form(None),
    user=Depends(require_permission(_PERM)),
) -> HTMLResponse:
    """The assembled Jinja2 the save will store, for the Preview modal.

    `assemble_jinja2` is the function template_service calls on create and
    update, so this shows the content that will actually be written. The
    page assembled its own approximation in `sectionToPreview()`, which is a
    second definition of fifteen section types and already disagrees with
    the first: for a variable table the service emits `{{% for row in x %}}`
    and the page's preview emitted `{% for row in x %}`.
    """
    from ion.services.section_types import assemble_jinja2

    try:
        state = parse_state(sections)
    except Exception:
        logger.exception("Template editor state could not be parsed for preview")
        return templates.TemplateResponse(
            request=request,
            name="_fragments/template_form_preview.html",
            context={"content": None, "failed": True},
        )

    try:
        content = assemble_jinja2(state)
    except Exception:
        logger.exception("Template sections could not be assembled for preview")
        return templates.TemplateResponse(
            request=request,
            name="_fragments/template_form_preview.html",
            context={"content": None, "failed": True},
        )

    return templates.TemplateResponse(
        request=request,
        name="_fragments/template_form_preview.html",
        # "" and None are different answers: a template with no sections
        # assembles to the empty string, and that is a fact about the
        # template, not a failure to assemble it.
        context={"content": content, "failed": False},
    )
