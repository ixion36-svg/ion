"""The template view: header, sections, variables and version history.

template_view.html built six regions out of string concatenation and wrote
them with innerHTML: the tag chips, the variables table, the version table,
the version modal's meta line, the diff (after formatDiff wrapped each line
in a span) and the section cards. escapeHtml() was what kept a tag or a
version message from being markup. Jinja does that now.

The reads are the ones the page already made, through the same functions:

  * template_payload              GET /api/templates/{id}
  * template_variables_payload    GET /api/templates/{id}/variables
  * VersionService.list_versions  GET /api/templates/{id}/versions
  * VersionService.get_version    GET /api/templates/{id}/versions/{n}

Nothing about a template row, an extracted variable or a version is
reimplemented here. The section-card summary is the page's own
renderSectionCards, which had no server equivalent; the icon and the label
come from SECTION_TYPES, which is what GET /api/templates/section-types
returns, rather than the shortened copy the script carried.

This is not a detection-engineering page. fragment_plan reads the live
gates as template:read on those four GETs, and none of them is mounted
behind require_de_module. Adding that gate would answer 404 for a template
on a deployment that is licensed to have templates, while the page and the
JSON API still served them.

Template.format, Template.document_type and Variable.var_type are String
columns, not SQLEnum. plain() still wraps every one of them on the way to
the template: the JSON endpoint serialises an enum member by value and
str() on a member does not, so a column that later becomes an enum would
otherwise render as Format.MARKDOWN and only the text would be wrong.
There is no stored URL on this page. The Render and Edit links are built
from the template id, which is an integer from the path, and a section
caption is text, not an href.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import get_current_user, require_permission
from ion.core.exceptions import TemplateNotFoundError, VersionNotFoundError
from ion.models.user import User
from ion.services.section_types import SECTION_TYPES
from ion.web.api import Services, get_services, template_payload, template_variables_payload
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

FRAGMENT = "_fragments/template_view.html"

#: What the four GETs this page made are gated on. Named once so the page
#: fragment and the version modal cannot drift apart, and so neither can
#: drift from the endpoint it mirrors.
PERMISSION = "template:read"

#: What POST /api/templates/{id}/rollback/{to_version} requires. The button
#: is withheld without it. The endpoint still refuses on its own; the
#: withhold is so a viewer does not have to click to learn that.
ROLLBACK_PERMISSION = "template:update"

_DOC_CLASS = re.compile(r"[A-Za-z0-9_-]+")

# The editor's default when a heading never recorded a level. Only None and
# "" take it. 0 is a level, and `raw or 2` is how it used to become H2.
_HEADING_DEFAULT = "2"

# What the view showed for an evidence block that named no chain variable.
# The section type's own default, not a second spelling of it.
_CHAIN_DEFAULT = "chain_of_custody"


def _ordered_label(value: object) -> str:
    """Ordered or Unordered, mirroring what the document will contain.

    Truthiness on purpose, and the contract's three-state rule does not
    apply, because `ordered` has no third state anywhere downstream. The
    assembler is `ion.services.section_types._section_to_jinja2`, which does
    `config.get("ordered", False)` and then `if ordered:`, so measured
    through `assemble_jinja2`: True, 1, "no" and "false" all render `1. a`,
    while False, 0, None and a missing key all render `- a`.

    This card is a preview of that document, so a third label would describe
    a decision the renderer never makes. An earlier version of this helper
    returned "Order not recorded" for None, a missing key and the string
    "no". For a missing key that manufactured work (the list will be
    unordered, and nothing needs setting), and for "no" it was simply false:
    that list renders ordered.
    """
    return "Ordered" if value else "Unordered"


def _count(value: object) -> Optional[int]:
    """How many entries a section lists.

    None is an empty collection: the section was read and it names nothing,
    which is a count of 0. A value that is not a list was not a count.
    `|length` on the string "no" is 2, and that 2 was never measured.
    """
    if value is None:
        return 0
    if isinstance(value, list):
        return len(value)
    return None


def _joined(value: object, key: str) -> Optional[str]:
    """Comma-joined names, '' when there are none, None when unreadable.

    Same rule as _count. A string is not a list of names, and joining it
    would spell the word out one character at a time.
    """
    if value is None:
        return ""
    if not isinstance(value, list):
        return None
    parts: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = item.get(key)
        if name is None or name == "":
            continue
        parts.append(str(name))
    return ", ".join(parts)


def _heading_level(raw: object) -> str:
    """The heading level as text, defaulting only when none was stored.

    0 stays 0. `raw or 2` is the expression that turned it into H2, which
    reads as the editor's default and hides a level that was recorded.
    """
    if raw is None or raw == "":
        return _HEADING_DEFAULT
    return str(raw)


def _clip(value: object) -> str:
    if value is None or value == "":
        return ""
    return str(value)[:80]


def _or_default(value: object, default: str) -> object:
    """`value or default` turns a stored 0 into the default. This does not."""
    if value is None or value == "":
        return default
    return value


def _blank(value: object) -> object:
    """None renders as nothing. 0 renders as 0, not as the word None."""
    if value is None:
        return ""
    return value


def _badge(name: object) -> dict[str, object]:
    return {"kind": "badge", "text": _blank(name)}


def _code(name: object) -> dict[str, object]:
    return {"kind": "code", "text": _blank(name)}


def _section_card(section: object) -> dict[str, Any]:
    """One section as the read-only card renderSectionCards built.

    A section that is not an object is a card that says so. Dropping it
    would lower the section count and look like a shorter template.
    """
    if not isinstance(section, dict):
        return {
            "icon": "?",
            "label": "Unreadable section",
            "title": None,
            "details": {
                "kind": "text",
                "text": "This section was not an object, so nothing in it was rendered.",
            },
        }

    stype = plain(section.get("type"))
    stype_s = None if stype is None else str(stype)
    meta = SECTION_TYPES.get(stype_s) if stype_s else None
    if isinstance(meta, dict):
        icon = meta.get("icon") or "?"
        label = meta.get("label") or stype_s
    else:
        icon = "?"
        label = stype_s if stype_s else "?"

    config = section.get("config")
    if not isinstance(config, dict):
        config = {}

    title: Any = None
    details: Optional[dict[str, object]] = None
    # Truthiness, for the same reason as _ordered_label: the assembler reads
    # this flag as `config.get("variable", False)` and then `if is_variable
    # and var_name`, so measured through assemble_jinja2 a section carrying
    # `variable: "no"` with a name emits `{{ name }}`. Saying the section is
    # static because the flag holds a string is a false statement about the
    # document, and it is also what the JavaScript this replaced got right
    # with a plain `if (c.variable)`.
    variable_on = bool(config.get("variable"))

    if stype_s == "heading":
        text = config.get("text")
        title = None if text is None or text == "" else text
        level = config.get("level") if "level" in config else None
        details = {"kind": "text", "text": "Level: H" + _heading_level(level)}
    elif stype_s == "text":
        if variable_on:
            details = _badge(config.get("variable_name"))
        else:
            clipped = _clip(config.get("content"))
            title = None if clipped == "" else clipped
    elif stype_s == "table":
        joined = _joined(config.get("columns") if "columns" in config else None, "name")
        if joined is None:
            title = "columns unreadable"
        elif joined != "":
            title = joined
        if variable_on:
            details = _badge(config.get("variable_name"))
    elif stype_s == "list":
        word = _ordered_label(config.get("ordered"))
        count = _count(config.get("items") if "items" in config else None)
        tail = "item count unknown" if count is None else f"{count} items"
        title = f"{word} - {tail}"
        if variable_on:
            details = _badge(config.get("variable_name"))
    elif stype_s == "key_value":
        count = _count(config.get("pairs") if "pairs" in config else None)
        title = "pair count unknown" if count is None else f"{count} pairs"
        if variable_on:
            details = _badge(config.get("variable_name"))
    elif stype_s == "divider":
        title = "Horizontal Rule"
    elif stype_s == "metadata_block":
        joined = _joined(config.get("fields") if "fields" in config else None, "label")
        if joined is None:
            title = "fields unreadable"
        elif joined != "":
            title = joined
    elif stype_s == "signature_block":
        joined = _joined(config.get("roles") if "roles" in config else None, "role_name")
        if joined is None:
            title = "roles unreadable"
        elif joined != "":
            title = joined
    elif stype_s == "image_placeholder":
        caption = config.get("caption")
        title = None if caption is None or caption == "" else caption
        details = _code(config.get("variable_name"))
    elif stype_s in ("severity_badge", "ioc_table", "timeline", "mitre_table"):
        details = _badge(config.get("variable_name"))
    elif stype_s == "checklist":
        count = _count(config.get("items") if "items" in config else None)
        title = "item count unknown" if count is None else f"{count} items"
    elif stype_s == "evidence_block":
        source = config.get("source")
        title = None if source is None or source == "" else source
        chain = config.get("chain_of_custody_var") if "chain_of_custody_var" in config else None
        details = _code(_or_default(chain, _CHAIN_DEFAULT))

    return {"icon": icon, "label": label, "title": title, "details": details}


def _body(payload: dict) -> dict[str, Any]:
    """Which body to show, and the section cards when that is the body.

    has_sections is three states. True with a list is the section view,
    including a list of length 0, which is a template that has no sections
    yet and not a legacy raw template. False is the raw body. Anything else,
    including the string "no", is not a decision and is not rendered as
    either: truthiness would treat "no" as having sections.
    """
    has_sections = payload.get("has_sections")
    sections = payload.get("sections")
    content = payload.get("content")
    if has_sections is True and isinstance(sections, list):
        return {
            "mode": "sections",
            "section_count": len(sections),
            "cards": [_section_card(s) for s in sections],
            "content": None,
        }
    if has_sections is True:
        return {
            "mode": "unreadable",
            "section_count": None,
            "cards": [],
            "content": None,
        }
    if has_sections is False:
        return {
            "mode": "raw",
            "section_count": None,
            "cards": [],
            "content": content,
        }
    return {
        "mode": "unreadable",
        "section_count": None,
        "cards": [],
        "content": None,
    }


def _document_type(value: object) -> Optional[dict[str, Optional[str]]]:
    """The type chip, or None when the template has no type.

    The class is appended only for a token the stylesheet can name. A type
    of `"><script>` is still shown, as text, and is not interpolated into
    the class attribute. plain() first, so an enum member contributes its
    value and not its repr.
    """
    value = plain(value)
    if value is None or value == "":
        return None
    text = str(value)
    css = "doc-type-" + text if _DOC_CLASS.fullmatch(text) else None
    return {"label": text, "css": css}


def _tags(value: object) -> Optional[list]:
    """The tag list, or None when it was not a list.

    None is not "no tags". An empty list is no tags. A string would render
    one chip per character, which is a third, wrong claim.
    """
    if isinstance(value, list):
        return value
    return None


def _variable_rows(payload: object) -> Optional[list[dict[str, Any]]]:
    """One row per extracted name, or None when the payload is not that pair.

    `defined` not being a list does not mean every variable is undefined. It
    means the declaration list was unreadable, and each row says so instead
    of "Not defined".
    """
    if not isinstance(payload, dict):
        return None
    extracted = payload.get("extracted")
    defined = payload.get("defined")
    if not isinstance(extracted, list):
        return None
    defined_by: Optional[dict[object, dict]] = None
    if isinstance(defined, list):
        defined_by = {}
        for item in defined:
            if isinstance(item, dict) and item.get("name") is not None:
                defined_by[item["name"]] = item
    rows = []
    for name in extracted:
        meta = defined_by.get(name) if defined_by is not None else None
        if defined_by is None:
            state: Optional[bool] = None
            var_type = None
        elif meta is None:
            state = False
            var_type = None
        else:
            state = True
            var_type = plain(meta.get("var_type"))
        rows.append({"name": name, "defined": state, "var_type": var_type})
    return rows


def _field(obj: object, key: str) -> object:
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def version_row(version: object, current: object, can_rollback: bool) -> dict[str, Any]:
    """One version row, including whether it is the current one.

    current is None when the template read did not say. That is not "this
    row is not current": a rollback offered on that basis can roll the live
    version back to itself. Version number 0 compares equal to a current
    version of 0, which `if version_number` would treat as absent.
    """
    number = _field(version, "version_number")
    if current is None or number is None:
        is_current: Optional[bool] = None
    else:
        is_current = number == current
    return {
        "version_number": number,
        "message": _field(version, "message"),
        "author": _field(version, "author"),
        "is_checkpoint": _field(version, "is_checkpoint"),
        "checkpoint_name": _field(version, "checkpoint_name"),
        "created_at": _field(version, "created_at"),
        "is_current": is_current,
        "offer_rollback": bool(can_rollback) and is_current is False and number is not None,
    }


def diff_lines(diff: object) -> Any:
    """The diff as lines tagged add, del or same.

    None means no diff was stored. A string, including the empty string,
    means a diff was stored: empty is "nothing in it", not "nobody computed
    one". The markers match formatDiff: a line is an add when it starts
    with "+" but not "+++", and a delete when it starts with "-" but not
    "---". The file headers are neither.

    A non-string is unreadable. Returning None for it would say the diff
    was never stored.
    """
    if diff is None:
        return None
    if not isinstance(diff, str):
        return "unreadable"
    # "".split("\n") is [""], one blank line, which would render as a diff
    # that has a line in it. An empty stored diff has no lines.
    if diff == "":
        return []
    lines = []
    for line in diff.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            kind = "add"
        elif line.startswith("-") and not line.startswith("---"):
            kind = "del"
        else:
            kind = "same"
        lines.append({"kind": kind, "text": line})
    return lines


def _page_context(
    template_id: int,
    *,
    template: Optional[dict],
    template_state: str,
    variables: Optional[list],
    variables_state: str,
    versions: Optional[list],
    versions_state: str,
    can_rollback: bool,
) -> dict[str, Any]:
    """Everything the page fragment renders, for every combination of states.

    The failed and missing branches still carry template_id and the other
    panels' own states. An error that rendered only the meta card would
    leave the variables and versions slots on their spinner, which reads as
    a load that has not finished.
    """
    current = None
    name = None
    fmt = None
    document_type = None
    updated_at = None
    tags = None
    description = None
    body = {"mode": "none", "section_count": None, "cards": [], "content": None}
    if template_state == "ok" and isinstance(template, dict):
        current_raw = template.get("current_version")
        current = plain(current_raw) if current_raw is not None else None
        name = template.get("name")
        fmt = plain(template.get("format"))
        document_type = _document_type(template.get("document_type"))
        updated_at = template.get("updated_at")
        tags = _tags(template.get("tags"))
        description = template.get("description")
        body = _body(template)

    version_rows = None
    if versions_state == "ok" and isinstance(versions, list):
        version_rows = [version_row(v, current, can_rollback) for v in versions]

    return {
        "panel": "page",
        "template_id": template_id,
        "template_state": template_state,
        "name": name,
        "format": fmt,
        "document_type": document_type,
        "current_version": current,
        "updated_at": updated_at,
        "tags": tags,
        "description": description,
        "body_mode": body["mode"],
        "section_count": body["section_count"],
        "cards": body["cards"],
        "content": body["content"],
        "variables_state": variables_state,
        "variables": variables,
        "versions_state": versions_state,
        "versions": version_rows,
    }


def _read_template(services: Services, template_id: int) -> tuple[Optional[dict], str]:
    try:
        return template_payload(services, template_id), "ok"
    except TemplateNotFoundError:
        return None, "missing"
    except Exception:
        logger.exception("template %s could not be read", template_id)
        return None, "failed"


def _read_variables(services: Services, template_id: int) -> tuple[Optional[list], str]:
    try:
        payload = template_variables_payload(services, template_id)
    except TemplateNotFoundError:
        return None, "missing"
    except Exception:
        logger.exception("variables for template %s could not be read", template_id)
        return None, "failed"
    rows = _variable_rows(payload)
    if rows is None:
        return None, "unreadable"
    if len(rows) == 0:
        return [], "empty"
    return rows, "ok"


def _read_versions(services: Services, template_id: int) -> tuple[Optional[list], str]:
    try:
        return services.version.list_versions(template_id), "ok"
    except TemplateNotFoundError:
        return None, "missing"
    except Exception:
        logger.exception("version history for template %s could not be read", template_id)
        return None, "failed"


@router.get(
    "/template-view/{template_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def template_view_fragment(
    request: Request,
    template_id: int,
    current_user: User = Depends(get_current_user),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """The template, its variables and its history, as one fragment.

    Three reads, three states each. One of them failing must not turn the
    others into an empty list, and a template that does not exist is not a
    read that failed. Both are what the JSON endpoints already distinguish,
    as 404 against 500.

    The current version travels with the template read. When that read did
    not succeed, the history can still be shown and rollback is withheld,
    because which row is current is then unknown rather than "none of them".

    The read permission is declared on the decorator and the User still comes
    in as a parameter, which is de_metrics' shape rather than a second one.
    The gate belongs on the route; the object is needed because the rollback
    control is withheld on `template:update`, and asking the viewer's own
    permissions is the only way to decide that here. Taking it from
    `get_current_user` rather than from a second `require_permission` call
    means the read permission is still checked exactly once: FastAPI caches
    `get_current_user` per request and the decorator's dependency has already
    resolved it, where a second `require_permission(PERMISSION)` would be a
    distinct closure, miss the cache and re-run the check.
    """
    template, template_state = _read_template(services, template_id)
    variables, variables_state = _read_variables(services, template_id)
    versions, versions_state = _read_versions(services, template_id)
    if versions_state == "ok" and isinstance(versions, list) and len(versions) == 0:
        versions_state = "empty"

    context = _page_context(
        template_id,
        template=template,
        template_state=template_state,
        variables=variables,
        variables_state=variables_state,
        versions=versions,
        versions_state=versions_state,
        can_rollback=bool(
            current_user and current_user.has_permission(ROLLBACK_PERMISSION)
        ),
    )
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context
    )


def _version_context(
    template_id: int,
    version_number: int,
    *,
    state: str,
    version: object,
    current: object,
    can_rollback: bool,
) -> dict[str, Any]:
    number = version_number
    row = None
    content = None
    lines = None
    if state == "ok" and version is not None:
        row = version_row(version, current, can_rollback)
        number = row["version_number"]
        content = _field(version, "content")
        lines = diff_lines(_field(version, "diff"))
    return {
        "panel": "version",
        "state": state,
        "template_id": template_id,
        "version_number": number,
        "version": row,
        "content": content,
        "diff_lines": lines,
    }


@router.get(
    "/template-view/{template_id}/versions/{version_number}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def template_view_version_fragment(
    request: Request,
    template_id: int,
    version_number: int,
    current_user: User = Depends(get_current_user),
    services: Services = Depends(get_services),
) -> HTMLResponse:
    """One version, as the body of the preview modal.

    Mirrors GET /api/templates/{id}/versions/{n} through the same
    VersionService.get_version. The template read exists only to know
    whether this version is the current one, which is what decides the
    rollback button. It failing does not hide the version; it withholds the
    button, because offering rollback without knowing which version is live
    is a guess.

    Close is rendered in every state. The modal is the swap, so an error
    branch without it leaves the panel open with no way out but a reload.
    """
    current: object = None
    try:
        payload = template_payload(services, template_id)
        current = payload.get("current_version")
        if current is not None:
            current = plain(current)
    except TemplateNotFoundError:
        current = None
    except Exception:
        logger.exception(
            "template %s could not be read while opening version %s",
            template_id, version_number,
        )
        current = None

    version = None
    try:
        version = services.version.get_version(template_id, version_number)
        state = "ok"
    except (VersionNotFoundError, TemplateNotFoundError):
        state = "missing"
    except Exception:
        logger.exception(
            "version %s of template %s could not be read",
            version_number, template_id,
        )
        state = "failed"

    context = _version_context(
        template_id,
        version_number,
        state=state,
        version=version,
        current=current,
        can_rollback=bool(
            current_user and current_user.has_permission(ROLLBACK_PERMISSION)
        ),
    )
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context
    )
