"""Translator routes (v0.17.0).

Mounted under ``/api/translator/*`` plus the retired page route at ``/translator``.

Routes:

- ``GET  /translator``                     — 302 → /tools?tab=translator (v0.75.0)
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
from typing import Any, Dict

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ion.auth.dependencies import require_permission

# v0.19.17: route exception details through safe_error so HTTP responses
# don't carry raw `str(exc)` (file paths, internal libraries, partial
# stack frames). The full trace still goes to the app log.
from ion.core.safe_errors import safe_error
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


# ── Retired page route ───────────────────────────────────────────────────────────


@router.get("/translator")
def translator_redirect():
    """Retired in v0.75.0 (route audit phase 7f).

    A 277-line single-purpose page whose sibling tab strip contained exactly one
    other entry — /tools, the 1076-line toolbox it belonged in. It is now the
    Translator tab there. Same permission on both sides (`alert:read`), so this
    is a pure relocation: no gate widened, narrowed, or removed. The
    /api/translator/* endpoints below are untouched — /alerts and /cases both
    call /api/translator/translate directly and never went through this page.
    """
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/tools?tab=translator", status_code=302)


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
        raise HTTPException(status_code=502, detail=f"Translator unavailable: {safe_error(exc, 'translate')}")
    except ValueError as exc:
        # ValueError is raised for caller-side input issues (oversize input,
        # bad language code) — its message is part of the API contract,
        # so it stays.
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
    # v0.19.18: was `await file.read()` then post-hoc size check inside
    # extract_text_from_upload, which buffered the whole upload into
    # memory first. Stream-read with a running cap so oversize uploads
    # are rejected before allocation. MAX_FILE_BYTES is the same value
    # the extractor enforces internally — sharing keeps the limits
    # consistent.
    from ion.core.uploads import read_upload_capped
    content = await read_upload_capped(file, MAX_FILE_BYTES)
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    try:
        text, kind = extract_text_from_upload(file.filename or "upload", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.warning("Extractor failed for %s: %s", file.filename, exc)
        raise HTTPException(status_code=400, detail=f"Extract failed: {safe_error(exc, 'translator_extract')}")
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
        raise HTTPException(status_code=502, detail=f"Translator unavailable: {safe_error(exc, 'translate')}")
    except ValueError as exc:
        # ValueError is raised for caller-side input issues (oversize input,
        # bad language code) — its message is part of the API contract,
        # so it stays.
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
        raise HTTPException(status_code=400, detail=f"Extract failed: {safe_error(exc, 'translator_extract')}")
    return {
        "filename": file.filename,
        "kind": kind,
        "extracted": text,
        "input_chars": len(text),
    }
