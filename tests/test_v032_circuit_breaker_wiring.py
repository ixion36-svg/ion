"""Circuit breaker wiring tests for v0.32.

Verifies that ElasticsearchService._request() and OllamaService.chat()/
generate() actually drive the global circuit breaker state machines — i.e.
that connectivity failures trip the breakers and successful responses
reset them.

These tests run entirely in-process with mocked httpx; no real ES/Ollama.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import httpx

from ion.core.circuit_breaker import CircuitState, es_breaker, ollama_breaker


def _reset_breaker(breaker):
    """Force a breaker back to closed/clean state between tests."""
    breaker._state = CircuitState.CLOSED
    breaker._failure_count = 0
    breaker._success_count = 0
    breaker._last_failure_time = 0.0
    breaker._last_state_change = 0.0


@pytest.fixture(autouse=True)
def clean_breakers():
    """Reset both breakers before every test in this module."""
    _reset_breaker(es_breaker)
    _reset_breaker(ollama_breaker)
    yield
    _reset_breaker(es_breaker)
    _reset_breaker(ollama_breaker)


# ---------------------------------------------------------------------------
# ElasticsearchService
# ---------------------------------------------------------------------------

class TestEsBreakerWiring:
    """_request() must drive es_breaker on success and connectivity failure."""

    def _make_service(self):
        from ion.services.elasticsearch_service import ElasticsearchService
        svc = ElasticsearchService.__new__(ElasticsearchService)
        svc.url = "http://es.test:9200"
        svc.api_key = "testkey"
        svc.username = ""
        svc.password = ""
        svc.alert_index = ".alerts-*"
        svc.case_index = "ion-cases"
        svc.kfp_index = "ion-kfp"
        svc.verify_ssl = False
        svc.user_index = ""
        svc.user_field = ""
        svc.assignment_field = "kibana.alert.workflow_user"
        return svc

    def test_success_records_success(self):
        svc = self._make_service()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"hits": {"total": {"value": 0}, "hits": []}}

        with patch("ion.services.elasticsearch_service._get_es_client") as mock_client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_factory.return_value = mock_client

            asyncio.run(svc._request("GET", "/_cat/indices"))

        assert es_breaker._failure_count == 0
        assert es_breaker._state == CircuitState.CLOSED

    def test_connect_error_records_failure(self):
        svc = self._make_service()

        with patch("ion.services.elasticsearch_service._get_es_client") as mock_client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_factory.return_value = mock_client

            from ion.services.elasticsearch_service import ElasticsearchError
            with pytest.raises(ElasticsearchError):
                asyncio.run(svc._request("GET", "/_cat/indices"))

        assert es_breaker._failure_count == 1

    def test_timeout_records_failure(self):
        svc = self._make_service()

        with patch("ion.services.elasticsearch_service._get_es_client") as mock_client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
            mock_client_factory.return_value = mock_client

            from ion.services.elasticsearch_service import ElasticsearchError
            with pytest.raises(ElasticsearchError):
                asyncio.run(svc._request("GET", "/_cat/indices"))

        assert es_breaker._failure_count == 1

    def test_threshold_opens_breaker(self):
        """After failure_threshold connect errors the breaker should open."""
        svc = self._make_service()

        with patch("ion.services.elasticsearch_service._get_es_client") as mock_client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client_factory.return_value = mock_client

            from ion.services.elasticsearch_service import ElasticsearchError
            for _ in range(es_breaker.failure_threshold):
                with pytest.raises(ElasticsearchError):
                    asyncio.run(svc._request("GET", "/_cat/indices"))

        assert es_breaker.is_open

    def test_http_4xx_does_not_trip_breaker(self):
        """4xx means ES is alive — the breaker should see a success."""
        svc = self._make_service()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"error": {"reason": "index not found"}}

        with patch("ion.services.elasticsearch_service._get_es_client") as mock_client_factory:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client_factory.return_value = mock_client

            from ion.services.elasticsearch_service import ElasticsearchError
            with pytest.raises(ElasticsearchError):
                asyncio.run(svc._request("GET", "/missing-index/_search"))

        # Breaker saw record_success() before the 4xx was raised
        assert es_breaker._failure_count == 0
        assert es_breaker._state == CircuitState.CLOSED


# ---------------------------------------------------------------------------
# OllamaService
# ---------------------------------------------------------------------------

class TestOllamaBreakerWiring:
    """chat() / generate() must drive ollama_breaker."""

    def _make_service(self):
        from ion.services.ollama_service import OllamaService
        svc = OllamaService.__new__(OllamaService)
        svc.base_url = "http://ollama.test:11434"
        svc.default_model = "llama3.1:8b"
        svc.enabled = True
        svc.verify_ssl = False
        svc.timeout = 30.0
        svc._client = None
        svc._client_loop = None
        svc._queue = MagicMock()
        return svc

    def test_chat_success_records_success(self):
        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_response = MagicMock()
        mock_response.json.return_value = {"message": {"content": "hello"}}
        mock_response.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        svc = self._make_service()
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            asyncio.run(svc.chat([{"role": "user", "content": "hi"}], bypass_queue=True))

        assert ollama_breaker._failure_count == 0
        assert ollama_breaker._state == CircuitState.CLOSED

    def test_chat_connect_error_records_failure(self):
        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        svc = self._make_service()
        from ion.services.ollama_service import OllamaError
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            with pytest.raises(OllamaError, match="Failed to connect"):
                asyncio.run(svc.chat([{"role": "user", "content": "hi"}], bypass_queue=True))

        assert ollama_breaker._failure_count == 1

    def test_chat_timeout_records_failure(self):
        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        svc = self._make_service()
        from ion.services.ollama_service import OllamaError
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            with pytest.raises(OllamaError, match="timed out"):
                asyncio.run(svc.chat([{"role": "user", "content": "hi"}], bypass_queue=True))

        assert ollama_breaker._failure_count == 1

    def test_chat_open_breaker_raises_immediately(self):
        """When breaker is open, chat() must raise without any HTTP call."""
        _reset_breaker(ollama_breaker)
        for _ in range(ollama_breaker.failure_threshold):
            ollama_breaker.record_failure()
        assert ollama_breaker.is_open

        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_client = AsyncMock()
        svc = self._make_service()

        from ion.services.ollama_service import OllamaError
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            with pytest.raises(OllamaError, match="circuit breaker open"):
                asyncio.run(svc.chat([{"role": "user", "content": "hi"}], bypass_queue=True))

        mock_client.post.assert_not_called()

    def test_generate_success_records_success(self):
        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_response = MagicMock()
        mock_response.json.return_value = {"response": "result text"}
        mock_response.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)

        svc = self._make_service()
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            result = asyncio.run(svc.generate("test prompt"))
        assert result == "result text"
        assert ollama_breaker._failure_count == 0

    def test_generate_open_breaker_raises_immediately(self):
        for _ in range(ollama_breaker.failure_threshold):
            ollama_breaker.record_failure()
        assert ollama_breaker.is_open

        from unittest.mock import PropertyMock

        from ion.services.ollama_service import OllamaService
        mock_client = AsyncMock()
        svc = self._make_service()

        from ion.services.ollama_service import OllamaError
        with patch.object(OllamaService, "client", new_callable=PropertyMock, return_value=mock_client):
            with pytest.raises(OllamaError, match="circuit breaker open"):
                asyncio.run(svc.generate("test prompt"))

        mock_client.post.assert_not_called()
