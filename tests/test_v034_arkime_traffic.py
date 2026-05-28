"""Tests for Arkime traffic analytics API (v0.34.3)."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_httpx_json_response(payload: dict, status_code: int = 200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": "application/json"}
    resp.json.return_value = payload
    resp.text = json.dumps(payload)
    return resp


def _make_service(url="http://ark:8005", user="admin", pwd="pass"):
    from ion.services.arkime_service import ArkimeService
    svc = ArkimeService.__new__(ArkimeService)
    svc.url = url
    svc.username = user
    svc.password = pwd
    svc.verify_ssl = False
    return svc


# ---------------------------------------------------------------------------
# ArkimeService.get_traffic_overview
# ---------------------------------------------------------------------------

class TestGetTrafficOverview:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_returns_histograms_and_protocols(self):
        payload = {
            "recordsFiltered": 42,
            "graph": {
                "srcDataHisto": [[1000, 500], [2000, 600]],
                "dstDataHisto": [[1000, 300], [2000, 400]],
                "protocols": {"tcp": 35, "udp": 7},
                "totDataBytes": 1800,
            },
        }
        svc = _make_service()
        mock_resp = _mock_httpx_json_response(payload)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            result = self._run(svc.get_traffic_overview(0, 86400))

        assert result["src_histo"] == [[1000, 500], [2000, 600]]
        assert result["dst_histo"] == [[1000, 300], [2000, 400]]
        assert result["protocols"] == {"tcp": 35, "udp": 7}
        assert result["total_sessions"] == 42
        assert result["total_bytes"] == 1800

    def test_empty_graph_returns_empty_lists(self):
        payload = {"recordsFiltered": 0, "graph": {}}
        svc = _make_service()
        mock_resp = _mock_httpx_json_response(payload)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            result = self._run(svc.get_traffic_overview(0, 86400))

        assert result["src_histo"] == []
        assert result["dst_histo"] == []
        assert result["protocols"] == {}

    def test_raises_when_not_configured(self):
        from ion.services.arkime_service import ArkimeError
        svc = _make_service(url="")
        with pytest.raises(ArkimeError):
            self._run(svc.get_traffic_overview(0, 86400))

    def test_raises_on_http_error(self):
        from ion.services.arkime_service import ArkimeError
        svc = _make_service()
        mock_resp = _mock_httpx_json_response({}, status_code=500)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            with pytest.raises(ArkimeError):
                self._run(svc.get_traffic_overview(0, 86400))


# ---------------------------------------------------------------------------
# ArkimeService.get_top_talkers
# ---------------------------------------------------------------------------

class TestGetTopTalkers:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_aggregates_by_src_and_dst(self):
        payload = {
            "data": [
                {"srcIp": "1.1.1.1", "dstIp": "2.2.2.2", "totBytes": 1000},
                {"srcIp": "1.1.1.1", "dstIp": "3.3.3.3", "totBytes": 500},
                {"srcIp": "4.4.4.4", "dstIp": "2.2.2.2", "totBytes": 200},
            ]
        }
        svc = _make_service()
        mock_resp = _mock_httpx_json_response(payload)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            result = self._run(svc.get_top_talkers(0, 86400, limit=10))

        # 1.1.1.1 sent 1500 bytes total across 2 sessions
        src_map = {r["ip"]: r for r in result["by_src"]}
        assert src_map["1.1.1.1"]["bytes"] == 1500
        assert src_map["1.1.1.1"]["sessions"] == 2
        # 2.2.2.2 received 1200 bytes
        dst_map = {r["ip"]: r for r in result["by_dst"]}
        assert dst_map["2.2.2.2"]["bytes"] == 1200

    def test_sorted_descending_by_bytes(self):
        payload = {
            "data": [
                {"srcIp": "low", "dstIp": "x", "totBytes": 10},
                {"srcIp": "high", "dstIp": "x", "totBytes": 9999},
            ]
        }
        svc = _make_service()
        mock_resp = _mock_httpx_json_response(payload)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            result = self._run(svc.get_top_talkers(0, 86400))

        assert result["by_src"][0]["ip"] == "high"

    def test_empty_data_returns_empty_lists(self):
        payload = {"data": []}
        svc = _make_service()
        mock_resp = _mock_httpx_json_response(payload)
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.object(svc, "_client", return_value=mock_client):
            result = self._run(svc.get_top_talkers(0, 86400))

        assert result["by_src"] == []
        assert result["by_dst"] == []

    def test_raises_when_not_configured(self):
        from ion.services.arkime_service import ArkimeError
        svc = _make_service(url="")
        with pytest.raises(ArkimeError):
            self._run(svc.get_top_talkers(0, 86400))
