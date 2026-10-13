"""Server-rendered panels for the AI chat page.

The chat page is not like the rest of the redesign. Its centre is a token
stream: `contentEl.innerHTML = formatMessage(fullResponse)` runs once per
chunk, and serving that from a fragment would mean a round trip per token.
So this module does not try to take the stream. It takes everything around it
that is built from server data, and chat.html documents the writes that
stay and why.

What it takes, and what was wrong with it.

AN ABSENT GROUNDING BOX MEANT TWO OPPOSITE THINGS

The grounding pass annotates an answer with the specifics its cited
sources do not support. ai_api.py emits the result only when it ran:

    if not grounding.get("skipped"):
        yield f"data: {json.dumps({'grounding': grounding})}\\n\\n"

and the page discarded the rest with `if (!g || g.skipped) return ''`. So
no grounding box meant either "checked, and every specific is in the
sources" or "never checked". The check is off unless
ION_CHAT_GROUNDING_CHECK is set, and skips whenever RAG returned nothing
to check against, so the second is the common case. For an advisory whose
only job is to say whether to trust the specifics in an answer, those two
readings are opposites. This module renders "not checked" for both the
skipped result and the absent event, with the reason when there is one.

chat_grounding_service also collects `notes`, the model's own account of
what it could not support, and caps it at 500 characters. Nothing ever
rendered it.

A GROUNDING WARNING COULD BECOME A REASSURANCE

    const claims = g.unsupported_claims || [];
    if (g.grounded && !claims.length) return 'Every specific here appears
                                              in the cited sources.'

A claims payload that is not a list became an empty one, and an empty
one with `grounded` set printed the reassurance. The service now derives
that verdict only from a list, and stores any other claims value as
None with skipped left false. This module's unreadable state is that
result: a missing list and a list in the wrong shape both refuse the
reassurance.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)

router = APIRouter()

#: The chat page's own permission, from server.py's page table.
PERMISSION = "ai:chat"

ANSWER_META_FRAGMENT = "_fragments/chat_answer_meta.html"

#: The citation kinds the chip styling knows, each with its label and the
#: glyph the page used. A kind outside this set keeps its text but takes
#: no class, since `ai-citation-chip ${c.type}` would have put a server
#: value into the class attribute.
CITATION_KINDS: dict[str, tuple[str, str]] = {
    "knowledge_base": ("KB", "\U0001F4C4"),
    "user_note": ("Note", "\U0001F4DD"),
    "playbook": ("PB", "\U0001F4CB"),
}


class Citation(TypedDict):
    kind: Optional[str]
    label: str
    glyph: str
    title: str


class Grounding(TypedDict):
    state: str
    reason: Optional[str]
    claims: list[str]
    notes: Optional[str]


class AnswerMetaView(TypedDict):
    msg_id: str
    show_citations: bool
    citations: Optional[list[Citation]]
    citations_readable: bool
    grounding: Grounding


def _text(value: Any) -> Optional[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return None


def _payload(raw: Optional[str]) -> tuple[Any, bool]:
    """Parse one JSON form field.

    Returns the value and whether it parsed. A field that is absent and a
    field that arrived malformed are different answers, and the page needs
    to say which.
    """
    if raw is None or not raw.strip():
        return None, True
    try:
        return json.loads(raw), True
    except (ValueError, TypeError):
        return None, False


def citation(raw: Any) -> Optional[Citation]:
    if not isinstance(raw, dict):
        return None
    kind = _text(raw.get("type"))
    label, glyph = CITATION_KINDS.get(kind or "", (kind or "Source", ""))
    return {
        # None when the kind is not one the chip styling knows, so it
        # never reaches a class attribute.
        "kind": kind if kind in CITATION_KINDS else None,
        "label": label,
        "glyph": glyph,
        "title": _text(raw.get("title")) or "untitled source",
    }


def citations_view(raw: Any) -> Optional[list[Citation]]:
    """None when the payload is not a list at all.

    `if (!citations || !citations.length) return ''` drew a payload in the
    wrong shape as "no sources", which for a cited answer is the wrong way
    to be wrong.
    """
    if not isinstance(raw, list):
        return None
    return [c for c in (citation(entry) for entry in raw) if c is not None]


def grounding_view(raw: Any, *, parsed: bool) -> Grounding:
    """The five states an advisory can be in.

    The page had two: a box, or nothing.
    """
    absent: Grounding = {"state": "not_checked", "reason": None,
                         "claims": [], "notes": None}
    if not parsed:
        return {"state": "unreadable", "reason": None, "claims": [],
                "notes": None}
    if raw is None:
        return absent
    if not isinstance(raw, dict):
        return {"state": "unreadable", "reason": None, "claims": [],
                "notes": None}
    notes = _text(raw.get("notes"))
    if raw.get("skipped") is True:
        return {"state": "not_checked",
                "reason": _text(raw.get("reason")),
                "claims": [], "notes": notes}

    claims = raw.get("unsupported_claims")
    if claims is None:
        # The service stores None when the claims value was not a list.
        # The page showed the reassurance for that, after coercing it to [].
        return {"state": "unreadable", "reason": None, "claims": [],
                "notes": notes}
    if not isinstance(claims, list):
        return {"state": "unreadable", "reason": None, "claims": [],
                "notes": notes}
    readable = [t for t in (_text(c) if isinstance(c, str) else _text(str(c))
                            for c in claims) if t]
    if readable:
        return {"state": "claims", "reason": None, "claims": readable,
                "notes": notes}
    if raw.get("grounded") is True:
        return {"state": "grounded", "reason": None, "claims": [],
                "notes": notes}
    # Not grounded, and nothing listed. The page drew the warning box
    # with a header, a footer and nothing between them.
    return {"state": "unlisted", "reason": None, "claims": [],
            "notes": notes}


@router.post(
    "/chat/answer-meta",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def chat_answer_meta_fragment(
    request: Request,
    msg_id: str = Form(""),
    citations: Optional[str] = Form(None),
    grounding: Optional[str] = Form(None),
    show_citations: str = Form("true"),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The panels that follow a completed answer.

    The payloads come back from the page because they arrive as SSE events
    on a stream the page owns. Nothing new is disclosed by echoing them,
    and it puts the state logic and the escaping somewhere testable.
    """
    raw_citations, citations_parsed = _payload(citations)
    raw_grounding, grounding_parsed = _payload(grounding)
    # An absent field, a malformed one and one in the wrong shape are
    # three answers. A stream that carried no citations event is the
    # first, and must not draw the sources bar at all.
    present = citations is not None and bool(citations.strip())
    view: AnswerMetaView = {
        "msg_id": msg_id,
        "show_citations": show_citations != "false",
        "citations": ([] if not present else
                      citations_view(raw_citations) if citations_parsed
                      else None),
        "citations_readable": citations_parsed,
        "grounding": grounding_view(raw_grounding, parsed=grounding_parsed),
    }
    return render_view(request, ANSWER_META_FRAGMENT, view)


# ---------------------------------------------------------------------------
# The file panel, the file viewer and the quick prompts
# ---------------------------------------------------------------------------
#
# formatFileSize reported a size for a file that had none:
#
#     if (bytes < 1024) return bytes + ' B';
#     if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
#     return (bytes / 1048576).toFixed(1) + ' MB';
#
# Both comparisons are false for undefined, so the last line ran and the
# file was listed as "NaN MB". A zero-byte file took the first branch and
# read "0 B", which is right, so only the missing case was wrong, which is
# the harder kind to notice.
#
# `uploadedFiles = data.files || []` drew a payload in the wrong shape as
# "No files attached", and GET /api/ai/files can return None outright:
# it is `for db in get_session(): return {...}`, which falls off the end
# if the generator yields nothing.
#
# The file id went raw into two attributes, one of them a single-quoted
# data-args, and the viewer did the same with file.id three more times.
#
# The viewer's only failure signal was showToast('Failed to load file')
# with no modal, so a transient failure and a file that no longer exists
# looked identical.

FILES_FRAGMENT = "_fragments/chat_files.html"
FILE_VIEWER_FRAGMENT = "_fragments/chat_file_viewer.html"
QUICK_PROMPTS_FRAGMENT = "_fragments/chat_quick_prompts.html"

#: The quick prompts per context. These were AI_QUICK_PROMPTS, a
#: JavaScript object in the template, so the one list a reviewer would
#: want to read sat in a script block.
QUICK_PROMPTS: dict[str, tuple[str, ...]] = {
    "security": (
        "What are common indicators of a phishing attack?",
        "Explain MITRE ATT&CK T1059 \u2014 Command and Scripting Interpreter",
        "How do I triage a suspicious network connection?",
        "What should I look for in Windows event logs for lateral movement?",
        "Help me analyse this IOC for threat intelligence",
    ),
    "engineering": (
        "How do I configure Elastic Agent for log collection?",
        "Help me tune Elasticsearch index performance",
        "What's the best way to set up log pipelines with Filebeat?",
        "Help me design a high-availability SIEM architecture",
        "How do I harden a Linux server baseline?",
    ),
    "coding": (
        "Help me write a Python log parser",
        "Write a YARA rule for detecting packed executables",
        "Help me create a Sigma detection rule",
        "Build a KQL query for failed authentication events",
        "Write a PowerShell script to extract IOCs from emails",
    ),
    "general": (
        "What can you help me with?",
        "How do I document a security incident?",
        "What are security best practices for new SOC analysts?",
        "Help me write a post-incident report",
        "What certifications should I pursue in cyber security?",
    ),
}


class FileRow(TypedDict):
    id: Optional[str]
    name: str
    size: Optional[str]
    lines: Optional[int]


class FilesView(TypedDict):
    state: str
    error: Optional[str]
    files: list[FileRow]


class ViewerView(TypedDict):
    state: str
    error: Optional[str]
    file_id: Optional[str]
    name: str
    content: Optional[str]


def file_size(value: Any) -> Optional[str]:
    """The size label, or None when no size was recorded.

    The thresholds are the page's. What changes is that a file with no
    recorded size says so instead of reading "NaN MB".
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0:
        return None
    if value < 1024:
        return "%d B" % int(value)
    if value < 1048576:
        return "%.1f KB" % (value / 1024)
    return "%.1f MB" % (value / 1048576)


def file_row(raw: Any) -> Optional[FileRow]:
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("id")
    lines = raw.get("lines")
    return {
        "id": (str(identifier) if identifier is not None else None),
        "name": _text(raw.get("name")) or "unnamed file",
        "size": file_size(raw.get("size")),
        "lines": (lines if isinstance(lines, int)
                  and not isinstance(lines, bool) else None),
    }


def files_view(payload: Any) -> FilesView:
    if not isinstance(payload, dict):
        return {"state": "failed", "error": None, "files": []}
    raw = payload.get("files")
    if not isinstance(raw, list):
        return {"state": "unreadable", "error": None, "files": []}
    rows = [r for r in (file_row(entry) for entry in raw) if r is not None]
    return {"state": "data" if rows else "empty", "error": None,
            "files": rows}


def viewer_view(payload: Any) -> ViewerView:
    if not isinstance(payload, dict):
        return {"state": "failed", "error": None, "file_id": None,
                "name": "", "content": None}
    identifier = payload.get("id")
    content = payload.get("content")
    return {
        "state": "data",
        "error": None,
        "file_id": (str(identifier) if identifier is not None else None),
        "name": _text(payload.get("name")) or "unnamed file",
        "content": content if isinstance(content, str) else None,
    }


class PromptsView(TypedDict):
    context: str
    prompts: list[str]


def prompts_view(context: str) -> PromptsView:
    """An unknown context is no prompts rather than an error: the context
    comes from the page's own buttons, and a panel of suggestions is not
    worth failing a request over."""
    return {"context": context,
            "prompts": list(QUICK_PROMPTS.get(context, ()))}


def _refusal(exc: Any) -> Optional[str]:
    """A refusal's own reason, which the page replaced with its own
    sentence."""
    from fastapi import HTTPException

    if isinstance(exc, HTTPException):
        return (str(exc.detail) if exc.detail
                else "This read was refused.")
    return None


@router.get(
    "/chat/files",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def chat_files_fragment(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The attachment panel."""
    from ion.web import ai_api

    try:
        payload = await ai_api.list_uploaded_files(current_user=current_user)
    except Exception as exc:
        reason = _refusal(exc)
        if reason is None:
            logger.exception("Chat file panel could not read the listing")
        view = files_view(None)
        view["error"] = reason
        return render_view(request, FILES_FRAGMENT, view)
    return render_view(request, FILES_FRAGMENT, files_view(payload))


@router.get(
    "/chat/files/{file_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def chat_file_viewer_fragment(
    request: Request,
    file_id: str,
    current_user: User = Depends(get_current_user),
) -> Response:
    """One uploaded file, to read or to edit."""
    from ion.web import ai_api

    try:
        payload = await ai_api.get_file_content(
            file_id=file_id, current_user=current_user)
    except Exception as exc:
        reason = _refusal(exc)
        if reason is None:
            logger.exception("Chat file viewer could not read %s", file_id)
        view = viewer_view(None)
        view["error"] = reason
        view["file_id"] = file_id
        return render_view(request, FILE_VIEWER_FRAGMENT, view)
    return render_view(request, FILE_VIEWER_FRAGMENT, viewer_view(payload))


@router.get(
    "/chat/quick-prompts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def chat_quick_prompts_fragment(
    request: Request,
    context: str = "security",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The suggested prompts for one context."""
    return render_view(request, QUICK_PROMPTS_FRAGMENT,
                       prompts_view(context))
