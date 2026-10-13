"""Server-rendered panels for the AI chat page.

The chat page is not like the rest of the redesign. Its centre is a token
stream: `contentEl.innerHTML = formatMessage(fullResponse)` runs once per
chunk, and a server fragment per token would be a round trip per token. So
this module does not try to take the stream. It takes everything around it
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

A claims payload that is not a list became an empty one. The service does
the same coercion before deriving its verdict:

    claims = obj.get("unsupported_claims")
    if not isinstance(claims, list):
        claims = []
    ...
    if grounded is None:
        grounded = not claims

so a model that returned its claims in an unreadable shape is recorded as
grounded and then reassures the analyst. The service half of that is a
separate change, filed rather than made here, because it is a change to
what ION records and not to how a page draws it. What this module can do
is refuse to print the reassurance when the list it rests on was not
readable, and say so instead.
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
        # The verdict without the list it rests on. The page showed the
        # reassurance for this.
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
