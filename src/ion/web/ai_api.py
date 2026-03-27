"""AI/LLM API endpoints."""

import logging
import os
import re
import uuid
import shutil
from pathlib import Path
from typing import List, Optional, Dict
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from datetime import datetime
import json

from ion.services.ollama_service import (
    get_ollama_service,
    OllamaError,
    RECOMMENDED_MODELS,
    SYSTEM_PROMPTS,
)
from ion.services.ai_chat_service import AIChatService
from ion.services.ai_context_service import AIContextService
from ion.web.api import limiter
from ion.auth.dependencies import get_current_user
from ion.models.user import User
from ion.models.ai_preferences import AIResponseFeedback
from ion.storage.database import get_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["ai"])


# Request/Response models
class ChatMessage(BaseModel):
    role: str = Field(..., pattern="^(user|assistant|system)$")
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model: Optional[str] = None
    context_type: str = Field(default="security", pattern="^(security|engineering|coding|general|analyst|default)$")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=4096)
    stream: bool = False


class ChatResponse(BaseModel):
    content: str
    model: str
    done: bool
    duration_ms: Optional[int] = None
    tokens: Optional[int] = None


class ModelInfo(BaseModel):
    name: str
    size: str
    parameter_size: str
    quantization: str


class QueueStatus(BaseModel):
    max_concurrent: int
    active_requests: int
    queue_length: int
    max_queue_size: int
    available_slots: int


class StatusResponse(BaseModel):
    available: bool
    url: str
    default_model: str
    models_loaded: int
    models: List[str]
    queue: Optional[QueueStatus] = None
    error: Optional[str] = None


class PullRequest(BaseModel):
    model: str


# Chat History Models
class CreateSessionRequest(BaseModel):
    context_type: str = Field(default="security", pattern="^(security|engineering|coding|general|analyst|default)$")
    title: Optional[str] = None


class SessionResponse(BaseModel):
    id: int
    title: Optional[str]
    context_type: str
    message_count: int
    created_at: datetime
    updated_at: datetime


class MessageResponse(BaseModel):
    id: int
    role: str
    content: str
    created_at: datetime


class ChatWithHistoryRequest(BaseModel):
    session_id: Optional[int] = None  # None = create new session
    message: str
    context_type: str = Field(default="security", pattern="^(security|engineering|coding|general|analyst|default)$")
    stream: bool = True


# AI Preferences / Feedback models
_SENTINEL = object()


class AIPreferencesRequest(BaseModel):
    rag_knowledge_base: Optional[bool] = None
    rag_user_notes: Optional[bool] = None
    rag_playbooks: Optional[bool] = None
    show_citations: Optional[bool] = None
    custom_instructions: Optional[str] = None
    max_context_snippets: Optional[int] = None


class FeedbackRequest(BaseModel):
    rating: str = Field(..., pattern="^(up|down)$")
    comment: Optional[str] = None
    session_id: Optional[int] = None
    message_id: Optional[int] = None
    context_type: Optional[str] = None
    rag_sources_used: Optional[str] = None


# Endpoints
@router.get("/status", response_model=StatusResponse)
async def get_ai_status(current_user: User = Depends(get_current_user)):
    """Get AI service status."""
    service = get_ollama_service()
    status = await service.get_status()
    return StatusResponse(**status)


@router.get("/diagnostic")
async def ai_diagnostic(current_user: User = Depends(get_current_user)):
    """Diagnostic endpoint: check all AI chat dependencies without making a real request."""
    checks = {}

    # 1. Ollama service init
    try:
        service = get_ollama_service()
        checks["ollama_init"] = {"ok": True, "url": service.base_url, "model": service.default_model}
    except Exception as e:
        checks["ollama_init"] = {"ok": False, "error": str(e)}
        return {"checks": checks}

    # 2. Ollama connectivity
    try:
        available = await service.is_available()
        checks["ollama_available"] = {"ok": available}
    except Exception as e:
        checks["ollama_available"] = {"ok": False, "error": str(e)}

    # 3. Database / AI preferences
    try:
        for db in get_session():
            ctx_service = AIContextService(db)
            prefs = ctx_service.get_user_preferences(current_user.id)
            checks["db_preferences"] = {
                "ok": True,
                "rag_kb": prefs.rag_knowledge_base,
                "rag_notes": prefs.rag_user_notes,
                "rag_playbooks": prefs.rag_playbooks,
            }
    except Exception as e:
        checks["db_preferences"] = {"ok": False, "error": str(e)}

    # 4. Quick Ollama chat test (non-streaming, tiny prompt)
    try:
        if checks.get("ollama_available", {}).get("ok"):
            result = await service.chat(
                messages=[{"role": "user", "content": "ping"}],
                context_type="default",
                temperature=0.1,
                max_tokens=5,
                user_id=current_user.id,
            )
            checks["ollama_chat"] = {"ok": True, "model": result.get("model")}
    except Exception as e:
        checks["ollama_chat"] = {"ok": False, "error": str(e)}

    all_ok = all(c.get("ok", False) for c in checks.values())
    return {"status": "ok" if all_ok else "error", "checks": checks}


@router.get("/queue")
async def get_queue_status(current_user: User = Depends(get_current_user)):
    """Get AI request queue status."""
    service = get_ollama_service()
    return await service.get_queue_status()


@router.get("/models")
async def list_models(current_user: User = Depends(get_current_user)):
    """List available AI models."""
    service = get_ollama_service()

    try:
        models = await service.list_models()
        return {
            "models": [
                {
                    "name": m.name,
                    "size": m.size,
                    "parameter_size": m.parameter_size,
                    "quantization": m.quantization,
                }
                for m in models
            ],
            "recommended": RECOMMENDED_MODELS,
        }
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/prompts")
async def get_system_prompts(current_user: User = Depends(get_current_user)):
    """Get available system prompt contexts."""
    return {
        "contexts": [
            {"id": "analyst", "name": "Security Analyst", "description": "Help with alerts, threats, and detection rules"},
            {"id": "engineering", "name": "Engineering", "description": "Help with code, queries, and debugging"},
            {"id": "default", "name": "General", "description": "General assistance"},
        ],
        "prompts": {k: v[:100] + "..." for k, v in SYSTEM_PROMPTS.items()},
    }


@router.post("/chat", response_model=ChatResponse)
@limiter.limit("30/minute")
async def chat(
    request: Request,
    payload: ChatRequest,
    current_user: User = Depends(get_current_user),
):
    """Send a chat message to the AI (non-streaming)."""
    service = get_ollama_service()

    # Check if service is available
    if not await service.is_available():
        raise HTTPException(
            status_code=503,
            detail="AI service (Ollama) is not available. Please ensure Ollama is running.",
        )

    try:
        messages = [{"role": m.role, "content": m.content} for m in payload.messages]

        result = await service.chat(
            messages=messages,
            model=payload.model,
            context_type=payload.context_type,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
            user_id=current_user.id,
        )

        return ChatResponse(
            content=result["content"],
            model=result["model"],
            done=result["done"],
            duration_ms=result.get("total_duration", 0) // 1_000_000 if result.get("total_duration") else None,
            tokens=result.get("eval_count"),
        )
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error("AI chat error: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"AI chat error: {e}")


@router.post("/chat/stream")
@limiter.limit("30/minute")
async def chat_stream(
    request: Request,
    payload: ChatRequest,
    current_user: User = Depends(get_current_user),
):
    """Send a chat message to the AI (streaming response)."""
    try:
        service = get_ollama_service()
    except Exception as e:
        logger.error("Failed to initialize Ollama service: %s", e, exc_info=True)
        raise HTTPException(status_code=503, detail=f"AI service initialization failed: {e}")

    # Check if service is available
    try:
        available = await service.is_available()
    except Exception as e:
        logger.error("Failed to check Ollama availability: %s", e, exc_info=True)
        raise HTTPException(status_code=503, detail=f"AI service check failed: {e}")

    if not available:
        raise HTTPException(
            status_code=503,
            detail="AI service (Ollama) is not available. Please ensure Ollama is running.",
        )

    # --- Greeting / small-talk detection ---
    # Small models (3B) tend to ramble on greetings. Detect and short-circuit.
    GREETING_WORDS = {
        "hi", "hey", "hello", "howdy", "yo", "sup", "hiya", "heya",
        "morning", "afternoon", "evening", "goodmorning", "goodafternoon",
        "goodevening", "thanks", "thank", "cheers", "bye", "goodbye",
        "ok", "okay", "yes", "yeah", "yep", "nope", "nah", "sure",
        "cool", "nice", "please", "sorry", "wow", "lol", "haha",
        "hmm", "ah", "oh", "hey there", "hi there", "hello there",
    }
    is_greeting = False
    if payload.messages:
        last_user_msg = ""
        for m in reversed(payload.messages):
            if m.role == "user":
                last_user_msg = m.content
                break
        # Strip punctuation and check if every word is a greeting/filler
        words = re.findall(r"[a-zA-Z]+", last_user_msg.lower())
        if words and all(w in GREETING_WORDS for w in words):
            is_greeting = True

    # --- RAG context injection ---
    enhanced_system_prompt = None
    citations_metadata = []

    if not is_greeting:
        try:
            for db in get_session():
                ctx_service = AIContextService(db)
                prefs = ctx_service.get_user_preferences(current_user.id)

                any_rag_enabled = (
                    prefs.rag_knowledge_base or prefs.rag_user_notes or prefs.rag_playbooks
                )

                if any_rag_enabled and payload.messages:
                    # Find last user message for keyword extraction
                    last_user_msg = ""
                    for m in reversed(payload.messages):
                        if m.role == "user":
                            last_user_msg = m.content
                            break

                    if last_user_msg:
                        rag_context = ctx_service.retrieve_context(
                            last_user_msg, current_user.id, prefs
                        )
                        if rag_context.snippets:
                            citations_metadata = rag_context.to_citations_metadata()

                            # Build layered system prompt
                            base_prompt = SYSTEM_PROMPTS.get(
                                payload.context_type, SYSTEM_PROMPTS.get("default", "")
                            )
                            layers = [base_prompt]

                            if prefs.custom_instructions:
                                layers.append(
                                    f"\nUser's custom instructions: {prefs.custom_instructions}"
                                )

                            layers.append("\n" + rag_context.to_prompt_block())
                            enhanced_system_prompt = "\n".join(layers)

                # Custom instructions even without RAG
                if not enhanced_system_prompt and prefs.custom_instructions:
                    base_prompt = SYSTEM_PROMPTS.get(
                        payload.context_type, SYSTEM_PROMPTS.get("default", "")
                    )
                    enhanced_system_prompt = (
                        base_prompt
                        + f"\nUser's custom instructions: {prefs.custom_instructions}"
                    )
        except Exception as e:
            logger.warning("RAG context retrieval failed, continuing without: %s", e, exc_info=True)

    # --- Build user role context line ---
    role_labels = {
        "analyst": "L1 SOC Analyst",
        "senior_analyst": "L2 Senior SOC Analyst",
        "principal_analyst": "L3 Principal SOC Analyst",
        "lead": "SOC Team Lead",
        "forensic": "Digital Forensics Specialist",
        "engineering": "Security Engineer",
        "admin": "System Administrator",
    }
    focus_role_obj = getattr(current_user, "_focus_role", None)
    if focus_role_obj is not None:
        user_role = focus_role_obj.name
    else:
        roles = [r.name for r in current_user.roles] if hasattr(current_user, "roles") else []
        user_role = roles[0] if roles else "analyst"
    role_label = role_labels.get(user_role, user_role)
    user_context_line = f"\nYou are speaking to: {current_user.display_name or current_user.username} ({role_label}). Tailor your responses to their experience level and responsibilities."

    # Append role context to whichever system prompt we're using
    if enhanced_system_prompt:
        enhanced_system_prompt += user_context_line
    else:
        base = SYSTEM_PROMPTS.get(payload.context_type, SYSTEM_PROMPTS.get("general", ""))
        enhanced_system_prompt = base + user_context_line

    # For greetings, add a hard constraint so small models don't ramble
    if is_greeting:
        enhanced_system_prompt += "\n\nIMPORTANT: The user is just greeting you. Respond with a brief, friendly greeting and ask how you can help. Keep your response to 1-2 sentences maximum. Do NOT discuss any other topics."

    async def generate():
        try:
            messages = [{"role": m.role, "content": m.content} for m in payload.messages]

            # Add file context to the last user message if files are uploaded
            files_context = get_files_context(current_user.id)
            if files_context and messages:
                # Find the last user message and append file context
                for i in range(len(messages) - 1, -1, -1):
                    if messages[i]["role"] == "user":
                        messages[i]["content"] += files_context
                        break

            stream_kwargs = dict(
                messages=messages,
                model=payload.model,
                context_type=payload.context_type,
                temperature=0.3 if is_greeting else payload.temperature,
                max_tokens=100 if is_greeting else payload.max_tokens,
                user_id=current_user.id,
            )
            # Always pass the enhanced prompt (includes role context)
            if enhanced_system_prompt:
                stream_kwargs["system_prompt"] = enhanced_system_prompt

            async for chunk in service.chat_stream(**stream_kwargs):
                yield f"data: {json.dumps(chunk)}\n\n"

            # Emit citations event before DONE if we have any
            if citations_metadata:
                yield f"data: {json.dumps({'citations': citations_metadata})}\n\n"

            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("AI chat stream error: %s", e, exc_info=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.post("/pull")
async def pull_model(
    request: PullRequest,
    current_user: User = Depends(get_current_user),
):
    """Pull/download a model (streaming progress)."""
    # Check if user has admin role
    eng_roles = {"admin", "engineering", "senior_engineer", "platform_engineer"}
    if not eng_roles.intersection(current_user.roles):
        raise HTTPException(status_code=403, detail="Admin or engineering role required")

    service = get_ollama_service()

    async def generate():
        try:
            async for progress in service.pull_model(request.model):
                yield f"data: {json.dumps(progress)}\n\n"
            yield "data: [DONE]\n\n"
        except OllamaError as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@router.post("/analyze/alert")
async def analyze_alert(
    alert_data: dict,
    current_user: User = Depends(get_current_user),
):
    """Analyze an alert using AI."""
    service = get_ollama_service()

    if not await service.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    # Build analysis prompt
    prompt = f"""Analyze this security alert and provide:
1. A brief summary of what happened
2. Potential impact and severity assessment
3. Recommended investigation steps
4. Possible MITRE ATT&CK techniques involved

Alert Data:
```json
{json.dumps(alert_data, indent=2, default=str)}
```"""

    try:
        result = await service.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="analyst",
            temperature=0.3,  # Lower temperature for more focused analysis
            user_id=current_user.id,
        )
        return {
            "analysis": result["content"],
            "model": result["model"],
        }
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/triage/suggest")
async def triage_suggest(
    alert_data: dict,
    current_user: User = Depends(get_current_user),
):
    """AI-assisted triage: suggest observables, MITRE techniques, and priority."""
    service = get_ollama_service()

    if not await service.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    prompt = f"""You are a security analyst assistant. Analyze this alert and provide structured triage suggestions.

Alert Data:
```json
{json.dumps(alert_data, indent=2, default=str)}
```

Respond EXACTLY in this format (no other text):

OBSERVABLES:
type|value
type|value

Valid types: hostname, source_ip, destination_ip, url, domain, user_account

MITRE:
Txxxx|Technique Name|Tactic
Txxxx|Technique Name|Tactic

PRIORITY: critical/high/medium/low

Extract real observables from the alert data. Map to real MITRE ATT&CK techniques. Set priority based on severity and context."""

    try:
        result = await service.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="analyst",
            temperature=0.2,
            user_id=current_user.id,
        )
        return {
            "suggestions": result["content"],
            "model": result["model"],
        }
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/case/generate")
async def case_generate(
    request_data: dict,
    current_user: User = Depends(get_current_user),
):
    """AI-assisted case creation: generate title, description, and evidence summary."""
    service = get_ollama_service()

    if not await service.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    prompt = f"""You are a security analyst writing an investigation case. Based on this alert and triage context, generate case fields.

Alert and Triage Data:
```json
{json.dumps(request_data, indent=2, default=str)}
```

Respond EXACTLY in this format (no other text):

TITLE: A concise, descriptive case title

DESCRIPTION: A detailed description of the incident, what was detected, and why it matters. Include timeline and affected assets.

EVIDENCE: A narrative summary of the evidence collected, including observables, detection rules triggered, and relevant indicators."""

    try:
        result = await service.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="analyst",
            temperature=0.3,
            user_id=current_user.id,
        )
        return {
            "content": result["content"],
            "model": result["model"],
        }
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.post("/generate/query")
async def generate_query(
    request: dict,
    current_user: User = Depends(get_current_user),
):
    """Generate a search query from natural language."""
    service = get_ollama_service()

    if not await service.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    query_type = request.get("type", "elasticsearch")
    description = request.get("description", "")

    prompt = f"""Generate a {query_type} query for the following request.
Return ONLY the query, no explanation.

Request: {description}"""

    try:
        result = await service.chat(
            messages=[{"role": "user", "content": prompt}],
            context_type="engineering",
            temperature=0.2,  # Very low temperature for precise query generation
            user_id=current_user.id,
        )
        return {
            "query": result["content"].strip(),
            "type": query_type,
            "model": result["model"],
        }
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))


# =============================================================================
# Document Generation Endpoints
# =============================================================================

class DocumentGenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    output_format: str = Field(default="markdown", pattern="^(markdown|html|csv|text)$")
    style: str = Field(default="professional", pattern="^(professional|concise|formal|technical)$")
    existing_content: Optional[str] = Field(default=None, max_length=16000)
    document_name: Optional[str] = None


DOCUMENT_SYSTEM_PROMPTS = {
    "markdown": "You are a document writer. Output clean, well-structured Markdown. Use headings (##, ###), bullet points, tables, and code blocks as appropriate. Do NOT wrap output in ```markdown fences — output raw Markdown directly.",
    "html": "You are a document writer. Output clean, semantic HTML using <h2>, <h3>, <p>, <ul>, <ol>, <table>, <code>, <blockquote> tags. Do NOT include <html>, <head>, or <body> wrappers — output only the body content.",
    "csv": "You are a data writer. Output valid CSV with a header row. Use commas as delimiters. Quote fields containing commas. Output raw CSV text only, no explanation or fences.",
    "text": "You are a document writer. Output clean plain text. Use line breaks and indentation for structure. No markup.",
}

STYLE_INSTRUCTIONS = {
    "professional": "Write in a clear, professional business tone. Be thorough but concise.",
    "concise": "Write as briefly as possible. Use short sentences, bullet points, and minimal prose.",
    "formal": "Write in formal, authoritative language suitable for official documentation or compliance reports.",
    "technical": "Write with precise technical terminology. Include specific details, configurations, and technical accuracy.",
}


@router.post("/document/generate")
@limiter.limit("10/minute")
async def generate_document(
    request: Request,
    payload: DocumentGenerateRequest,
    current_user: User = Depends(get_current_user),
):
    """Generate a document using AI (streaming). Returns SSE stream of content chunks."""
    service = get_ollama_service()

    if not await service.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    system = DOCUMENT_SYSTEM_PROMPTS.get(payload.output_format, DOCUMENT_SYSTEM_PROMPTS["markdown"])
    system += f"\n\n{STYLE_INSTRUCTIONS.get(payload.style, STYLE_INSTRUCTIONS['professional'])}"

    if payload.output_format == "csv":
        system += "\nIMPORTANT: Output ONLY the CSV data. No explanations, no markdown fences."

    user_prompt = payload.prompt
    if payload.existing_content:
        user_prompt += f"\n\nHere is the existing document content to improve/extend:\n---\n{payload.existing_content[:8000]}\n---"

    async def generate():
        try:
            full_content = ""
            async for chunk in service.chat_stream(
                messages=[{"role": "user", "content": user_prompt}],
                system_prompt=system,
                context_type="default",
                temperature=0.4,
                max_tokens=4096,
                user_id=current_user.id,
            ):
                if chunk.get("error"):
                    yield f"data: {json.dumps({'error': chunk['error']})}\n\n"
                    return
                if chunk.get("content"):
                    full_content += chunk["content"]
                    yield f"data: {json.dumps({'content': chunk['content']})}\n\n"

            yield f"data: {json.dumps({'done': True, 'full_content': full_content})}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error("Document generation error: %s", e, exc_info=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


class DocumentSaveRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=100000)
    output_format: str = Field(default="markdown", pattern="^(markdown|html|csv|text)$")
    document_name: Optional[str] = None


@router.post("/document/save")
@limiter.limit("30/minute")
async def save_generated_document(
    request: Request,
    payload: DocumentSaveRequest,
    current_user: User = Depends(get_current_user),
):
    """Save AI-generated content as a document (no re-generation)."""
    from ion.storage.database import get_session as get_db_session
    from ion.storage.document_repository import DocumentRepository

    for db in get_db_session():
        doc_repo = DocumentRepository(db)
        doc_name = payload.document_name or f"AI Generated Document"
        document = doc_repo.create(
            name=doc_name,
            rendered_content=payload.content,
            output_format=payload.output_format,
        )
        db.commit()
        return {
            "document_id": document.id,
            "name": document.name,
            "format": payload.output_format,
        }


# =============================================================================
# Chat History Endpoints
# =============================================================================

@router.get("/history/sessions")
async def list_sessions(
    limit: int = 20,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
):
    """List user's chat sessions."""
    for db in get_session():
        service = AIChatService(db)
        sessions = service.get_user_sessions(current_user.id, limit, offset)
        total = service.get_session_count(current_user.id)

        return {
            "sessions": [
                {
                    "id": s.id,
                    "title": s.title or s.preview,
                    "context_type": s.context_type.value if s.context_type else "default",
                    "message_count": s.message_count,
                    "created_at": s.created_at.isoformat(),
                    "updated_at": s.updated_at.isoformat(),
                }
                for s in sessions
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


@router.post("/history/sessions")
async def create_session(
    request: CreateSessionRequest,
    current_user: User = Depends(get_current_user),
):
    """Create a new chat session."""
    for db in get_session():
        service = AIChatService(db)
        session = service.create_session(
            user_id=current_user.id,
            context_type=request.context_type,
            title=request.title
        )

        return {
            "id": session.id,
            "title": session.title,
            "context_type": session.context_type.value if session.context_type else "default",
            "message_count": 0,
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
        }


@router.get("/history/sessions/{session_id}")
async def get_chat_session(
    session_id: int,
    current_user: User = Depends(get_current_user),
):
    """Get a session with its messages."""
    for db in get_session():
        service = AIChatService(db)
        session = service.get_session(session_id, current_user.id)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        messages = service.get_session_messages(session_id, current_user.id)

        return {
            "id": session.id,
            "title": session.title,
            "context_type": session.context_type.value if session.context_type else "default",
            "created_at": session.created_at.isoformat(),
            "updated_at": session.updated_at.isoformat(),
            "messages": [
                {
                    "id": m.id,
                    "role": m.role,
                    "content": m.content,
                    "created_at": m.created_at.isoformat(),
                }
                for m in messages
            ],
        }


@router.delete("/history/sessions/{session_id}")
async def delete_session(
    session_id: int,
    current_user: User = Depends(get_current_user),
):
    """Delete a chat session."""
    for db in get_session():
        service = AIChatService(db)
        if service.delete_session(session_id, current_user.id):
            return {"status": "deleted"}
        raise HTTPException(status_code=404, detail="Session not found")


@router.put("/history/sessions/{session_id}/title")
async def update_session_title(
    session_id: int,
    title: str,
    current_user: User = Depends(get_current_user),
):
    """Update session title."""
    for db in get_session():
        service = AIChatService(db)
        session = service.update_session_title(session_id, current_user.id, title)

        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        return {"id": session.id, "title": session.title}


@router.post("/history/chat")
async def chat_with_history(
    request: ChatWithHistoryRequest,
    current_user: User = Depends(get_current_user),
):
    """Chat with automatic history saving."""
    ollama = get_ollama_service()

    if not await ollama.is_available():
        raise HTTPException(status_code=503, detail="AI service not available")

    for db in get_session():
        service = AIChatService(db)

        # Get or create session
        if request.session_id:
            session = service.get_session(request.session_id, current_user.id)
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
        else:
            session = service.create_session(
                user_id=current_user.id,
                context_type=request.context_type
            )

        # Save user message
        service.add_message(session.id, current_user.id, "user", request.message)

        # Get conversation history
        messages = service.get_session_messages(session.id, current_user.id, limit=20)
        chat_messages = [{"role": m.role, "content": m.content} for m in messages]

    # Generate response
    if request.stream:
        async def generate():
            full_response = ""
            try:
                async for chunk in ollama.chat_stream(
                    messages=chat_messages,
                    context_type=request.context_type,
                    user_id=current_user.id,
                ):
                    if chunk.get("content"):
                        full_response += chunk["content"]
                    yield f"data: {json.dumps(chunk)}\n\n"

                # Save assistant response
                for db in get_session():
                    service = AIChatService(db)
                    service.add_message(session.id, current_user.id, "assistant", full_response)

                yield f"data: {json.dumps({'session_id': session.id})}\n\n"
                yield "data: [DONE]\n\n"
            except OllamaError as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )
    else:
        try:
            result = await ollama.chat(
                messages=chat_messages,
                context_type=request.context_type,
                user_id=current_user.id,
            )

            # Save assistant response
            for db in get_session():
                service = AIChatService(db)
                service.add_message(session.id, current_user.id, "assistant", result["content"])

            return {
                "session_id": session.id,
                "content": result["content"],
                "model": result["model"],
            }
        except OllamaError as e:
            raise HTTPException(status_code=503, detail=str(e))


@router.get("/history/stats")
async def get_history_stats(current_user: User = Depends(get_current_user)):
    """Get user's chat history stats."""
    for db in get_session():
        service = AIChatService(db)
        return service.get_user_stats(current_user.id)


# =============================================================================
# AI Preferences & Feedback Endpoints
# =============================================================================

@router.get("/preferences")
async def get_ai_preferences(current_user: User = Depends(get_current_user)):
    """Get user's AI preferences (creates defaults if missing)."""
    for db in get_session():
        service = AIContextService(db)
        prefs = service.get_user_preferences(current_user.id)
        return {
            "rag_knowledge_base": prefs.rag_knowledge_base,
            "rag_user_notes": prefs.rag_user_notes,
            "rag_playbooks": prefs.rag_playbooks,
            "show_citations": prefs.show_citations,
            "custom_instructions": prefs.custom_instructions or "",
            "max_context_snippets": prefs.max_context_snippets,
        }


@router.put("/preferences")
async def update_ai_preferences(
    request: AIPreferencesRequest,
    current_user: User = Depends(get_current_user),
):
    """Update user's AI preferences (partial update)."""
    updates = {}
    if request.rag_knowledge_base is not None:
        updates["rag_knowledge_base"] = request.rag_knowledge_base
    if request.rag_user_notes is not None:
        updates["rag_user_notes"] = request.rag_user_notes
    if request.rag_playbooks is not None:
        updates["rag_playbooks"] = request.rag_playbooks
    if request.show_citations is not None:
        updates["show_citations"] = request.show_citations
    if request.custom_instructions is not None:
        # Enforce max 500 chars
        updates["custom_instructions"] = request.custom_instructions[:500]
    if request.max_context_snippets is not None:
        updates["max_context_snippets"] = min(max(request.max_context_snippets, 1), 5)

    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    for db in get_session():
        service = AIContextService(db)
        prefs = service.update_preferences(current_user.id, updates)
        return {
            "rag_knowledge_base": prefs.rag_knowledge_base,
            "rag_user_notes": prefs.rag_user_notes,
            "rag_playbooks": prefs.rag_playbooks,
            "show_citations": prefs.show_citations,
            "custom_instructions": prefs.custom_instructions or "",
            "max_context_snippets": prefs.max_context_snippets,
            "message": "Preferences updated",
        }


@router.post("/feedback")
async def submit_feedback(
    request: FeedbackRequest,
    current_user: User = Depends(get_current_user),
):
    """Submit thumbs up/down feedback on an AI response."""
    for db in get_session():
        feedback = AIResponseFeedback(
            user_id=current_user.id,
            session_id=request.session_id,
            message_id=request.message_id,
            rating=request.rating,
            comment=request.comment,
            context_type=request.context_type,
            rag_sources_used=request.rag_sources_used,
        )
        db.add(feedback)
        db.commit()
        return {"status": "saved", "id": feedback.id}


# =============================================================================
# File Upload Endpoints
# =============================================================================

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {
    '.txt', '.log', '.json', '.yaml', '.yml', '.xml', '.csv',
    '.py', '.js', '.ts', '.html', '.css', '.sh', '.bash', '.ps1',
    '.conf', '.cfg', '.ini', '.toml', '.md', '.rst',
    '.sql', '.kql', '.spl',  # Query languages
    '.yar', '.yara',  # YARA rules
    '.sigma',  # Sigma rules
    '.rule', '.rules',  # Generic rules
}

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB max
UPLOAD_DIR = Path("uploads/ai_chat")

# In-memory storage for uploaded file contents (per user session)
# In production, use Redis or similar
_uploaded_files: Dict[str, Dict[str, dict]] = {}


def get_upload_dir() -> Path:
    """Get or create upload directory."""
    upload_path = UPLOAD_DIR
    upload_path.mkdir(parents=True, exist_ok=True)
    return upload_path


def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def get_user_files(user_id: int) -> Dict[str, dict]:
    """Get uploaded files for a user."""
    key = str(user_id)
    if key not in _uploaded_files:
        _uploaded_files[key] = {}
    return _uploaded_files[key]


@router.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """Upload a file for AI analysis."""
    # Validate file extension
    if not is_allowed_file(file.filename):
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise HTTPException(
            status_code=400,
            detail=f"File type not allowed. Allowed types: {allowed}"
        )

    # Read file content
    content = await file.read()

    # Check file size
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Maximum size is {MAX_FILE_SIZE // 1024 // 1024}MB"
        )

    # Try to decode as text
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        try:
            text_content = content.decode('latin-1')
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=400,
                detail="File must be a text file"
            )

    # Generate unique file ID
    file_id = str(uuid.uuid4())[:8]

    # Store file info
    user_files = get_user_files(current_user.id)
    user_files[file_id] = {
        "id": file_id,
        "name": file.filename,
        "size": len(content),
        "lines": len(text_content.splitlines()),
        "content": text_content,
        "uploaded_at": datetime.utcnow().isoformat(),
    }

    # Limit to 10 files per user
    if len(user_files) > 10:
        oldest_key = min(user_files.keys(), key=lambda k: user_files[k]["uploaded_at"])
        del user_files[oldest_key]

    logger.info("User %s uploaded file: %s (%s)", current_user.username, file.filename, file_id)

    return {
        "id": file_id,
        "name": file.filename,
        "size": len(content),
        "lines": len(text_content.splitlines()),
        "message": "File uploaded successfully. You can now reference it in your chat."
    }


@router.get("/files")
async def list_uploaded_files(current_user: User = Depends(get_current_user)):
    """List uploaded files for the current user."""
    user_files = get_user_files(current_user.id)
    return {
        "files": [
            {
                "id": f["id"],
                "name": f["name"],
                "size": f["size"],
                "lines": f["lines"],
                "uploaded_at": f["uploaded_at"],
            }
            for f in user_files.values()
        ]
    }


@router.get("/files/{file_id}")
async def get_file_content(
    file_id: str,
    current_user: User = Depends(get_current_user),
):
    """Get content of an uploaded file."""
    user_files = get_user_files(current_user.id)

    if file_id not in user_files:
        raise HTTPException(status_code=404, detail="File not found")

    file_info = user_files[file_id]
    return {
        "id": file_info["id"],
        "name": file_info["name"],
        "content": file_info["content"],
    }


@router.delete("/files/{file_id}")
async def delete_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete an uploaded file."""
    user_files = get_user_files(current_user.id)

    if file_id not in user_files:
        raise HTTPException(status_code=404, detail="File not found")

    del user_files[file_id]
    return {"status": "deleted"}


@router.post("/files/{file_id}/edit")
async def apply_file_edit(
    file_id: str,
    edit_request: dict,
    current_user: User = Depends(get_current_user),
):
    """Apply an edit to an uploaded file."""
    user_files = get_user_files(current_user.id)

    if file_id not in user_files:
        raise HTTPException(status_code=404, detail="File not found")

    new_content = edit_request.get("content")
    if new_content is None:
        raise HTTPException(status_code=400, detail="Missing 'content' field")

    # Update the file content
    file_info = user_files[file_id]
    old_content = file_info["content"]
    file_info["content"] = new_content
    file_info["size"] = len(new_content.encode('utf-8'))
    file_info["lines"] = len(new_content.splitlines())
    file_info["last_edited"] = datetime.utcnow().isoformat()

    logger.info("User %s edited file: %s (%s)", current_user.username, file_info['name'], file_id)

    return {
        "id": file_id,
        "name": file_info["name"],
        "size": file_info["size"],
        "lines": file_info["lines"],
        "message": "File updated successfully"
    }


@router.post("/files/{file_id}/download")
async def download_edited_file(
    file_id: str,
    current_user: User = Depends(get_current_user),
):
    """Download the edited file content."""
    user_files = get_user_files(current_user.id)

    if file_id not in user_files:
        raise HTTPException(status_code=404, detail="File not found")

    file_info = user_files[file_id]

    from fastapi.responses import Response
    return Response(
        content=file_info["content"],
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_info["name"]}"'
        }
    )


def get_files_context(user_id: int) -> str:
    """Build context string from uploaded files for AI."""
    user_files = get_user_files(user_id)
    if not user_files:
        return ""

    context_parts = ["\n\n--- UPLOADED FILES ---"]
    for file_info in user_files.values():
        context_parts.append(f"\n### File: {file_info['name']} (ID: {file_info['id']})")
        context_parts.append("```")
        # Truncate very long files
        content = file_info["content"]
        if len(content) > 10000:
            content = content[:10000] + "\n... (truncated, file too long)"
        context_parts.append(content)
        context_parts.append("```")

    return "\n".join(context_parts)
