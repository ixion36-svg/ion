"""Case comments, annotations and explicitly requested note translations."""

from __future__ import annotations

import logging
from typing import Literal, TypedDict

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.storage.database import get_db_session
from ion.web import kibana_api, translator_api, workbench_api
from ion.web.ui._shared import instant_label, render_view, rows

logger = logging.getLogger(__name__)
router = APIRouter()
READ = require_permission("case:read")


class Comment(TypedDict):
    author: str
    created: str | None
    body: str


class CommentsView(TypedDict):
    state: Literal["failed", "empty", "data"]
    comments: list[Comment] | None
    count: int | None


class Annotation(TypedDict):
    id: int | None
    author: str
    timestamp: str | None
    body: str


class AnnotationsView(TypedDict):
    state: Literal["failed", "empty", "data"]
    case_id: int
    annotations: list[Annotation] | None
    count: int | None
    can_update: bool


class TranslationView(TypedDict):
    state: Literal["failed", "empty", "data"]
    translation: str | None
    error: str | None


def comments_view(payload: object) -> CommentsView:
    records = rows(payload, "comments")
    if records is not None and not all(isinstance(item, dict) for item in records):
        records = None
    comments = (
        [
            {
                "author": item.get("created_by") if isinstance(item.get("created_by"), str) and item["created_by"] else "kibana",
                "created": instant_label(item.get("created_at")),
                "body": item.get("comment") if isinstance(item.get("comment"), str) else "",
            }
            for item in records
        ]
        if records is not None
        else None
    )
    return {"state": "failed" if comments is None else "data" if comments else "empty", "comments": comments, "count": len(comments) if comments is not None else None}


def annotations_view(payload: object, case_id: int, user) -> AnnotationsView:
    records = rows(payload, "annotations")
    if records is not None and not all(isinstance(item, dict) for item in records):
        records = None
    annotations = (
        [
            {
                "id": item.get("id") if isinstance(item.get("id"), int) and not isinstance(item["id"], bool) else None,
                "author": item.get("created_by_username") if isinstance(item.get("created_by_username"), str) and item["created_by_username"] else "unknown",
                "timestamp": instant_label(item.get("timeline_ts")),
                "body": item.get("body") if isinstance(item.get("body"), str) else "",
            }
            for item in records
        ]
        if records is not None
        else None
    )
    return {
        "state": "failed" if annotations is None else "data" if annotations else "empty",
        "case_id": case_id,
        "annotations": annotations,
        "count": len(annotations) if annotations is not None else None,
        "can_update": user.has_permission("case:update"),
    }


def translation_view(payload: object, error: str | None = None) -> TranslationView:
    translated = payload.get("translation") if isinstance(payload, dict) else None
    if not isinstance(translated, str):
        translated = None
    return {
        "state": "failed" if translated is None else "data" if translated else "empty",
        "translation": translated,
        "error": error or ("Unreadable translation response" if translated is None else None),
    }


@router.get("/cases/kibana/{kibana_id}/comments", response_class=HTMLResponse)
async def comments(request: Request, kibana_id: str, user=Depends(READ)):
    try:
        payload = await kibana_api.get_kibana_case(case_id=kibana_id, current_user=user)
    except Exception:
        logger.exception("Case comments could not be read")
        payload = None
    return render_view(request, "_fragments/cases_detail_comments.html", comments_view(payload))


@router.get("/cases/{case_id}/annotations", response_class=HTMLResponse)
def annotations(request: Request, case_id: int, user=Depends(READ), session: Session = Depends(get_db_session)):
    try:
        payload = workbench_api.list_annotations_endpoint(case_id=case_id, session=session)
    except Exception:
        logger.exception("Case annotations could not be read")
        payload = None
    return render_view(request, "_fragments/cases_detail_annotations.html", annotations_view(payload, case_id, user))


@router.post("/cases/note-translation", response_class=HTMLResponse)
def note_translation(request: Request, text: str = Form(..., min_length=1, max_length=200_000), source: str = Form("auto"), target: str = Form("en"), user=Depends(READ)):
    if not user.has_permission("alert:read"):
        raise HTTPException(status_code=403, detail="Permission denied")
    body = translator_api.TranslateRequest(text=text, source=source, target=target)
    error = None
    try:
        payload = translator_api.translate(body=body, _user=user)
    except HTTPException as exc:
        payload, error = None, str(exc.detail)
    except Exception:
        logger.exception("Case note translation failed")
        payload, error = None, "Translator unavailable"
    return render_view(request, "_fragments/cases_detail_translation.html", translation_view(payload, error))
