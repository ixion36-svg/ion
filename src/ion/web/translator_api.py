"""Translator routes (v0.17.0).

Mounted under ``/api/translator/*`` plus the page route at ``/translator``.

Routes:

- ``GET  /translator``                     — the standalone page
- ``GET  /api/translator/languages``       — supported language list
- ``POST /api/translator/translate``       — JSON {text, source, target}
- ``POST /api/translator/translate-file``  — multipart upload + translate
- ``POST /api/translator/extract``         — multipart upload, extract only
                                              (returns the source text without
                                              calling the LLM — useful for
                                              previewing what'll be translated)

All routes require ``alert:read`` permission to keep the translator
available to any analyst with general SOC access (the same permission
gate as the alerts page).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from ion.auth.dependencies import require_page_permission, require_permission
from ion.models.user import User
from ion.services.translation_service import (
    MAX_FILE_BYTES,
    SUPPORTED_LANGUAGES,
    TranslationError,
    extract_text_from_upload,
    supported_extensions,
    translate_long_text,
)

logger = logging.getLogger(__name__)


router = APIRouter()


_TEMPLATES_DIR = Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


# ── Page route ───────────────────────────────────────────────────────────


@router.get("/translator", response_class=HTMLResponse)
def translator_page(
    request: Request,
    _user: User = Depends(require_page_permission("alert:read")),
):
    """Standalone translator page."""
    return _templates.TemplateResponse(
        request=request,
        name="translator.html",
    )


# ── API: language list ───────────────────────────────────────────────────


@router.get("/api/translator/languages")
def get_languages(
    _user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    return {
        "languages": SUPPORTED_LANGUAGES,
        "supported_extensions": supported_extensions(),
        "max_file_bytes": MAX_FILE_BYTES,
    }


# ── API: text translate ──────────────────────────────────────────────────


class TranslateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=200_000)
    source: str = "auto"
    target: str = "en"


@router.post("/api/translator/translate")
def translate(
    body: TranslateRequest,
    _user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Translate a string. Long inputs are chunked transparently."""
    try:
        out = translate_long_text(body.text, target_lang=body.target, source_lang=body.source)
    except TranslationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "source": body.source,
        "target": body.target,
        "input_chars": len(body.text),
        "output_chars": len(out),
        "translation": out,
    }


# ── API: file upload — extract + translate ──────────────────────────────


@router.post("/api/translator/translate-file")
async def translate_file(
    file: UploadFile = File(...),
    target: str = Form("en"),
    source: str = Form("auto"),
    _user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Upload a document, extract its text, translate, return both."""
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        text, kind = extract_text_from_upload(file.filename or "upload", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning("Extractor failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=400, detail=f"Extract failed: {exc}")
    if not text.strip():
        return {
            "filename": file.filename,
            "kind": kind,
            "source": source,
            "target": target,
            "input_chars": 0,
            "output_chars": 0,
            "extracted": "",
            "translation": "",
            "warning": "No translatable text extracted from the file.",
        }
    try:
        out = translate_long_text(text, target_lang=target, source_lang=source)
    except TranslationError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "filename": file.filename,
        "kind": kind,
        "source": source,
        "target": target,
        "input_chars": len(text),
        "output_chars": len(out),
        "extracted": text,
        "translation": out,
    }


# ── API: extract only (no LLM call) ──────────────────────────────────────


@router.post("/api/translator/extract")
async def extract(
    file: UploadFile = File(...),
    _user: User = Depends(require_permission("alert:read")),
) -> Dict[str, Any]:
    """Extract source text from a file without calling the LLM. Lets the
    UI preview what will be translated before paying the round-trip."""
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        text, kind = extract_text_from_upload(file.filename or "upload", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning("Extractor failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=400, detail=f"Extract failed: {exc}")
    return {
        "filename": file.filename,
        "kind": kind,
        "extracted": text,
        "input_chars": len(text),
    }
