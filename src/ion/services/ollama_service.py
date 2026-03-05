"""Ollama LLM service for AI-assisted chat."""

import asyncio
import logging
import os
import time
from typing import AsyncGenerator, Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import httpx

logger = logging.getLogger(__name__)


# =============================================================================
# Request Queue & Rate Limiting
# =============================================================================

@dataclass
class QueuedRequest:
    """A request waiting in the queue."""
    request_id: str
    user_id: int
    queued_at: float
    event: asyncio.Event = field(default_factory=asyncio.Event)
    position: int = 0


class RateLimitBucket:
    """Token bucket for per-user rate limiting."""

    def __init__(self, max_tokens: int = 10, refill_rate: float = 0.5):
        """
        Initialize rate limit bucket.

        Args:
            max_tokens: Maximum tokens (requests) allowed
            refill_rate: Tokens added per second
        """
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate
        self.tokens = max_tokens
        self.last_refill = time.time()

    def try_consume(self) -> Tuple[bool, float]:
        """
        Try to consume a token.

        Returns:
            Tuple of (success, wait_time_if_failed)
        """
        now = time.time()
        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1:
            self.tokens -= 1
            return True, 0.0
        else:
            # Calculate wait time for next token
            wait_time = (1 - self.tokens) / self.refill_rate
            return False, wait_time


class RequestQueue:
    """Manages concurrent request limits and queuing."""

    def __init__(self, max_concurrent: int = 4, max_queue_size: int = 50):
        self.max_concurrent = max_concurrent
        self.max_queue_size = max_queue_size
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._queue: List[QueuedRequest] = []
        self._active_count = 0
        self._lock = asyncio.Lock()
        self._rate_limiters: Dict[int, RateLimitBucket] = defaultdict(
            lambda: RateLimitBucket(max_tokens=10, refill_rate=0.5)
        )
        self._request_counter = 0

    @property
    def queue_length(self) -> int:
        return len(self._queue)

    @property
    def active_requests(self) -> int:
        return self._active_count

    async def get_status(self) -> Dict[str, Any]:
        """Get queue status."""
        async with self._lock:
            return {
                "max_concurrent": self.max_concurrent,
                "active_requests": self._active_count,
                "queue_length": len(self._queue),
                "max_queue_size": self.max_queue_size,
                "available_slots": self.max_concurrent - self._active_count,
            }

    async def check_rate_limit(self, user_id: int) -> Tuple[bool, float]:
        """Check if user is rate limited."""
        bucket = self._rate_limiters[user_id]
        return bucket.try_consume()

    async def acquire(self, user_id: int) -> Tuple[bool, int, str]:
        """
        Acquire a slot for processing.

        Returns:
            Tuple of (success, queue_position, request_id)
        """
        async with self._lock:
            self._request_counter += 1
            request_id = f"req_{self._request_counter}"

            # Check queue size limit
            if len(self._queue) >= self.max_queue_size:
                return False, -1, request_id

            # Try to acquire immediately
            if self._semaphore.locked() is False or self._active_count < self.max_concurrent:
                pass  # Will try to acquire below
            else:
                # Add to queue
                queued = QueuedRequest(
                    request_id=request_id,
                    user_id=user_id,
                    queued_at=time.time(),
                    position=len(self._queue) + 1,
                )
                self._queue.append(queued)
                position = queued.position

                # Release lock while waiting
                self._lock.release()
                try:
                    # Wait for our turn
                    await self._semaphore.acquire()
                finally:
                    await self._lock.acquire()

                # Remove from queue
                self._queue = [q for q in self._queue if q.request_id != request_id]
                self._update_positions()

        # We have the semaphore
        await self._semaphore.acquire()
        async with self._lock:
            self._active_count += 1
        return True, 0, request_id

    async def acquire_with_wait(self, user_id: int, timeout: float = 300) -> Tuple[bool, int, str]:
        """
        Acquire a slot, waiting up to timeout seconds.

        Returns:
            Tuple of (success, initial_queue_position, request_id)
        """
        self._request_counter += 1
        request_id = f"req_{self._request_counter}"

        # Check queue capacity
        async with self._lock:
            if len(self._queue) >= self.max_queue_size:
                logger.warning(f"Queue full, rejecting request {request_id}")
                return False, -1, request_id

        start_time = time.time()
        initial_position = 0

        # Try to acquire semaphore with timeout
        try:
            # Check if we can get it immediately
            acquired = self._semaphore.locked() is False
            if not acquired:
                # Add to tracking queue for position info
                async with self._lock:
                    initial_position = len(self._queue) + 1
                    queued = QueuedRequest(
                        request_id=request_id,
                        user_id=user_id,
                        queued_at=time.time(),
                        position=initial_position,
                    )
                    self._queue.append(queued)

            # Wait for semaphore
            await asyncio.wait_for(self._semaphore.acquire(), timeout=timeout)

            # Got it - update tracking
            async with self._lock:
                self._active_count += 1
                self._queue = [q for q in self._queue if q.request_id != request_id]
                self._update_positions()

            return True, initial_position, request_id

        except asyncio.TimeoutError:
            # Timed out waiting
            async with self._lock:
                self._queue = [q for q in self._queue if q.request_id != request_id]
                self._update_positions()
            logger.warning(f"Request {request_id} timed out after {timeout}s in queue")
            return False, initial_position, request_id

    def _update_positions(self):
        """Update queue positions after changes."""
        for i, req in enumerate(self._queue):
            req.position = i + 1

    async def release(self, request_id: str):
        """Release a slot after processing completes."""
        async with self._lock:
            self._active_count = max(0, self._active_count - 1)
        self._semaphore.release()

    async def get_position(self, request_id: str) -> int:
        """Get current queue position for a request."""
        async with self._lock:
            for req in self._queue:
                if req.request_id == request_id:
                    return req.position
        return 0  # Not in queue (either processing or done)


# Global request queue
_request_queue: Optional[RequestQueue] = None


def get_request_queue() -> RequestQueue:
    """Get the global request queue."""
    global _request_queue
    if _request_queue is None:
        max_parallel = int(os.environ.get("OLLAMA_NUM_PARALLEL", "4"))
        _request_queue = RequestQueue(max_concurrent=max_parallel, max_queue_size=50)
        logger.info(f"Initialized request queue with max_concurrent={max_parallel}")
    return _request_queue


class OllamaError(Exception):
    """Ollama service error."""
    pass


class ModelSize(str, Enum):
    """Model size categories."""
    TINY = "tiny"       # < 1GB RAM
    SMALL = "small"     # 1-4GB RAM
    MEDIUM = "medium"   # 4-8GB RAM
    LARGE = "large"     # 8-16GB RAM


@dataclass
class ModelInfo:
    """Information about an Ollama model."""
    name: str
    size: str
    parameter_size: str
    quantization: str
    modified_at: str
    digest: str

    @property
    def display_name(self) -> str:
        return self.name.split(":")[0].title()


# Recommended models for different use cases
RECOMMENDED_MODELS = {
    "testing": {
        "name": "qwen2.5:0.5b",
        "description": "Tiny model for testing (~400MB RAM)",
        "size": ModelSize.TINY,
    },
    "coding": {
        "name": "qwen2.5-coder:7b",
        "description": "Best for code generation and review (~5GB RAM)",
        "size": ModelSize.MEDIUM,
    },
    "general": {
        "name": "llama3:8b",
        "description": "Best all-rounder for analysis (~5GB RAM)",
        "size": ModelSize.MEDIUM,
    },
    "lightweight": {
        "name": "phi3:mini",
        "description": "Good balance of quality and speed (~2GB RAM)",
        "size": ModelSize.SMALL,
    },
}

# System prompts for different contexts
SYSTEM_PROMPTS = {
    "analyst": """You are an AI security analyst assistant integrated into ION, a security operations platform.
You help security analysts with:
- Analyzing alerts and security events
- Understanding threat indicators and IOCs
- Writing detection rules (YARA, Sigma, KQL)
- Explaining malware behavior and techniques
- Investigating incidents and suggesting next steps

Be concise, technical, and actionable. Reference MITRE ATT&CK techniques when relevant.
If you don't know something, say so rather than guessing.""",

    "engineering": """You are an AI engineering assistant integrated into ION, a security operations platform.
You help engineers with:
- Writing and reviewing Python, PowerShell, and other code
- Building Elasticsearch/KQL queries
- Creating automation scripts
- Debugging issues
- Explaining code and system behavior
- Reverse engineering concepts

Provide code examples when helpful. Be precise and technical.""",

    "default": """You are an AI assistant integrated into ION, a security operations platform.
You help users with security analysis, coding, and general questions.
Be concise and helpful.""",
}


class OllamaService:
    """Service for interacting with Ollama LLM."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "qwen2.5:0.5b",
        timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._queue = get_request_queue()

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            from ion.core.config import get_ssl_verify
            verify = get_ssl_verify()
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                verify=verify,
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def is_available(self) -> bool:
        """Check if Ollama service is available."""
        try:
            response = await self.client.get("/api/tags")
            return response.status_code == 200
        except Exception as e:
            logger.debug("Ollama not available: %s", e)
            return False

    async def get_status(self) -> Dict[str, Any]:
        """Get Ollama service status."""
        try:
            available = await self.is_available()
            models = await self.list_models() if available else []
            queue_status = await self._queue.get_status()
            return {
                "available": available,
                "url": self.base_url,
                "default_model": self.default_model,
                "models_loaded": len(models),
                "models": [m.name for m in models],
                "queue": queue_status,
            }
        except Exception as e:
            return {
                "available": False,
                "url": self.base_url,
                "default_model": self.default_model,
                "models_loaded": 0,
                "models": [],
                "error": str(e),
            }

    async def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status."""
        return await self._queue.get_status()

    async def check_rate_limit(self, user_id: int) -> Tuple[bool, float]:
        """Check if user is rate limited."""
        return await self._queue.check_rate_limit(user_id)

    async def list_models(self) -> List[ModelInfo]:
        """List available models."""
        try:
            response = await self.client.get("/api/tags")
            response.raise_for_status()
            data = response.json()

            models = []
            for model in data.get("models", []):
                models.append(ModelInfo(
                    name=model.get("name", ""),
                    size=model.get("size", ""),
                    parameter_size=model.get("details", {}).get("parameter_size", ""),
                    quantization=model.get("details", {}).get("quantization_level", ""),
                    modified_at=model.get("modified_at", ""),
                    digest=model.get("digest", ""),
                ))
            return models
        except Exception as e:
            logger.error("Failed to list models: %s", e)
            raise OllamaError(f"Failed to list models: {e}")

    async def pull_model(self, model_name: str) -> AsyncGenerator[Dict[str, Any], None]:
        """Pull/download a model with progress updates."""
        try:
            async with self.client.stream(
                "POST",
                "/api/pull",
                json={"name": model_name},
                timeout=None,  # No timeout for downloads
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        import json
                        yield json.loads(line)
        except Exception as e:
            logger.error("Failed to pull model %s: %s", model_name, e)
            raise OllamaError(f"Failed to pull model: {e}")

    async def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        context_type: str = "default",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        user_id: int = 0,
    ) -> Dict[str, Any]:
        """Send a chat message and get a response (non-streaming)."""
        model = model or self.default_model

        # Check rate limit
        allowed, wait_time = await self._queue.check_rate_limit(user_id)
        if not allowed:
            raise OllamaError(f"Rate limited. Please wait {wait_time:.1f} seconds before trying again.")

        # Acquire queue slot
        acquired, position, request_id = await self._queue.acquire_with_wait(user_id, timeout=300)
        if not acquired:
            if position == -1:
                raise OllamaError("Server busy. Queue is full. Please try again later.")
            raise OllamaError("Request timed out waiting in queue. Please try again.")

        try:
            # Build messages with system prompt
            full_messages = []
            if system_prompt:
                full_messages.append({"role": "system", "content": system_prompt})
            elif context_type in SYSTEM_PROMPTS:
                full_messages.append({"role": "system", "content": SYSTEM_PROMPTS[context_type]})

            full_messages.extend(messages)

            response = await self.client.post(
                "/api/chat",
                json={
                    "model": model,
                    "messages": full_messages,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        **({"num_predict": max_tokens} if max_tokens else {}),
                    },
                },
            )
            response.raise_for_status()
            data = response.json()

            return {
                "content": data.get("message", {}).get("content", ""),
                "model": model,
                "done": True,
                "total_duration": data.get("total_duration"),
                "eval_count": data.get("eval_count"),
            }
        except httpx.TimeoutException:
            raise OllamaError("Request timed out - model may still be loading")
        except OllamaError:
            raise
        except Exception as e:
            logger.error("Chat failed: %s", e)
            raise OllamaError(f"Chat failed: {e}")
        finally:
            await self._queue.release(request_id)

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        context_type: str = "default",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        user_id: int = 0,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Send a chat message and stream the response."""
        model = model or self.default_model

        # Check rate limit
        allowed, wait_time = await self._queue.check_rate_limit(user_id)
        if not allowed:
            yield {"error": f"Rate limited. Please wait {wait_time:.1f} seconds.", "rate_limited": True, "wait_time": wait_time}
            return

        # Acquire queue slot
        acquired, position, request_id = await self._queue.acquire_with_wait(user_id, timeout=300)
        if not acquired:
            if position == -1:
                yield {"error": "Server busy. Queue is full. Please try again later.", "queue_full": True}
            else:
                yield {"error": "Request timed out waiting in queue.", "queue_timeout": True}
            return

        # If we were queued, send position info
        if position > 0:
            yield {"queued": True, "initial_position": position, "model": model}

        try:
            # Build messages with system prompt
            full_messages = []
            if system_prompt:
                full_messages.append({"role": "system", "content": system_prompt})
            elif context_type in SYSTEM_PROMPTS:
                full_messages.append({"role": "system", "content": SYSTEM_PROMPTS[context_type]})

            full_messages.extend(messages)

            async with self.client.stream(
                "POST",
                "/api/chat",
                json={
                    "model": model,
                    "messages": full_messages,
                    "stream": True,
                    "options": {
                        "temperature": temperature,
                        **({"num_predict": max_tokens} if max_tokens else {}),
                    },
                },
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if line:
                        import json
                        data = json.loads(line)
                        yield {
                            "content": data.get("message", {}).get("content", ""),
                            "done": data.get("done", False),
                            "model": model,
                        }
        except httpx.TimeoutException:
            yield {"error": "Request timed out - model may still be loading"}
        except Exception as e:
            logger.error("Chat stream failed: %s", e)
            yield {"error": f"Chat stream failed: {e}"}
        finally:
            await self._queue.release(request_id)

    async def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system: Optional[str] = None,
        temperature: float = 0.7,
    ) -> str:
        """Simple text generation (non-chat format)."""
        model = model or self.default_model

        try:
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "system": system or SYSTEM_PROMPTS["default"],
                    "stream": False,
                    "options": {"temperature": temperature},
                },
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            logger.error("Generate failed: %s", e)
            raise OllamaError(f"Generate failed: {e}")


# Global service instance
_ollama_service: Optional[OllamaService] = None


def get_ollama_service() -> OllamaService:
    """Get the global Ollama service instance."""
    global _ollama_service
    if _ollama_service is None:
        from ion.core.config import get_config
        config = get_config()
        _ollama_service = OllamaService(
            base_url=getattr(config, 'ollama_url', 'http://localhost:11434'),
            default_model=getattr(config, 'ollama_model', 'qwen2.5:0.5b'),
            timeout=float(getattr(config, 'ollama_timeout', 120)),
        )
    return _ollama_service


def reset_ollama_service():
    """Reset the global service (for testing)."""
    global _ollama_service
    if _ollama_service:
        asyncio.create_task(_ollama_service.close())
    _ollama_service = None
