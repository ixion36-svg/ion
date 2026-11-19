"""A user's Elastic profile UID comes from Elasticsearch, not Kibana.

Kibana case assignees are profile UIDs. ION used to look them up through
Kibana's /internal/security/user_profile/_suggest, which is 404 on Kibana
9.x, so no UID was ever resolved and no case reached Kibana with an assignee.
"""

import httpx
import pytest

from ion.services import kibana_cases_service as kcs

ELASTIC_PROFILE = {"uid": "u_abc_0", "user": {"username": "r.okonjo", "email": "r@ion.lab"}}


@pytest.fixture
def svc(monkeypatch):
    monkeypatch.setattr(
        kcs, "get_kibana_config",
        lambda: {"enabled": True, "url": "http://kibana:5601", "username": "k", "password": "p"},
    )
    monkeypatch.setattr(
        "ion.services.elasticsearch_service.get_elasticsearch_config",
        lambda: {"url": "http://es:9200", "username": "e", "password": "p"},
    )
    return kcs.KibanaCasesService()


def _answer(monkeypatch, status, body, calls):
    def fake_post(url, **kw):
        calls.append((url, kw))
        return httpx.Response(status, json=body, request=httpx.Request("POST", url))
    monkeypatch.setattr(kcs.httpx, "post", fake_post)


def test_uid_is_resolved_from_the_elasticsearch_profile_api(svc, monkeypatch):
    calls = []
    _answer(monkeypatch, 200, {"profiles": [ELASTIC_PROFILE]}, calls)

    assert svc.resolve_user_uid("r.okonjo") == "u_abc_0"
    assert [url for url, _ in calls] == ["http://es:9200/_security/profile/_suggest"]
    assert calls[0][1]["auth"] == ("e", "p")


def test_a_fuzzy_hit_for_another_user_is_not_taken(svc, monkeypatch):
    _answer(monkeypatch, 200, {"profiles": [ELASTIC_PROFILE]}, [])

    assert svc.resolve_user_uid("r.okonj") is None


def test_an_elasticsearch_refusal_resolves_nothing(svc, monkeypatch):
    _answer(monkeypatch, 403, {"error": "forbidden"}, [])

    assert svc.suggest_user_profiles("r.okonjo") == []
    assert svc.resolve_user_uid("r.okonjo") is None


@pytest.mark.parametrize("raw", [b"<html>proxy error</html>", b"[]", b'{"profiles": "nope"}'])
def test_a_malformed_success_resolves_nothing_instead_of_raising(svc, monkeypatch, raw):
    monkeypatch.setattr(
        kcs.httpx, "post",
        lambda url, **kw: httpx.Response(200, content=raw, request=httpx.Request("POST", url)),
    )

    assert svc.suggest_user_profiles("r.okonjo") == []
