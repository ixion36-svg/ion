"""Ollama LLM service for AI-assisted chat."""

import asyncio
import logging
from typing import AsyncGenerator, Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import httpx

logger = logging.getLogger(__name__)


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
    "analyst": """You are an AI security analyst assistant integrated into IXION, a security operations platform.
You help security analysts with:
- Analyzing alerts and security events
- Understanding threat indicators and IOCs
- Writing detection rules (YARA, Sigma, KQL)
- Explaining malware behavior and techniques
- Investigating incidents and suggesting next steps

Be concise, technical, and actionable. Reference MITRE ATT&CK techniques when relevant.
If you don't know something, say so rather than guessing.""",

    "engineering": """You are an AI engineering assistant integrated into IXION, a security operations platform.
You help engineers with:
- Writing and reviewing Python, PowerShell, and other code
- Building Elasticsearch/KQL queries
- Creating automation scripts
- Debugging issues
- Explaining code and system behavior
- Reverse engineering concepts

Provide code examples when helpful. Be precise and technical.""",

    "default": """You are an AI assistant integrated into IXION, a security operations platform.
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

    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=httpx.Timeout(self.timeout, connect=10.0),
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
            return {
                "available": available,
                "url": self.base_url,
                "default_model": self.default_model,
                "models_loaded": len(models),
                "models": [m.name for m in models],
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
    ) -> Dict[str, Any]:
        """Send a chat message and get a response (non-streaming)."""
        model = model or self.default_model

        # Build messages with system prompt
        full_messages = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        elif context_type in SYSTEM_PROMPTS:
            full_messages.append({"role": "system", "content": SYSTEM_PROMPTS[context_type]})

        full_messages.extend(messages)

        try:
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
        except Exception as e:
            logger.error("Chat failed: %s", e)
            raise OllamaError(f"Chat failed: {e}")

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        context_type: str = "default",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Send a chat message and stream the response."""
        model = model or self.default_model

        # Build messages with system prompt
        full_messages = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        elif context_type in SYSTEM_PROMPTS:
            full_messages.append({"role": "system", "content": SYSTEM_PROMPTS[context_type]})

        full_messages.extend(messages)

        try:
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
            raise OllamaError("Request timed out - model may still be loading")
        except Exception as e:
            logger.error("Chat stream failed: %s", e)
            raise OllamaError(f"Chat stream failed: {e}")

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
        from ixion.core.config import get_config
        config = get_config()
        _ollama_service = OllamaService(
            base_url=getattr(config, 'ollama_url', 'http://localhost:11434'),
            default_model=getattr(config, 'ollama_model', 'qwen2.5:0.5b'),
        )
    return _ollama_service


def reset_ollama_service():
    """Reset the global service (for testing)."""
    global _ollama_service
    if _ollama_service:
        asyncio.create_task(_ollama_service.close())
    _ollama_service = None
