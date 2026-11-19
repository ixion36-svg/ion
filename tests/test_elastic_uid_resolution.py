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


def test_without_elasticsearch_nothing_is_asked(monkeypatch):
    monkeypatch.setattr(kcs, "get_kibana_config", lambda: {"enabled": True, "url": "http://kibana:5601"})
    monkeypatch.setattr("ion.services.elasticsearch_service.get_elasticsearch_config", lambda: {})
    monkeypatch.setattr(kcs.httpx, "post", lambda *a, **k: pytest.fail("ES was called"))

    assert kcs.KibanaCasesService().suggest_user_profiles("r.okonjo") == []


def test_an_unreachable_elasticsearch_resolves_nothing(svc, monkeypatch):
    def refuse(url, **kw):
        raise httpx.ConnectError("refused", request=httpx.Request("POST", url))
    monkeypatch.setattr(kcs.httpx, "post", refuse)

    assert svc.resolve_user_uid("r.okonjo") is None


class _Session:
    commits = 0

    def commit(self):
        self.commits += 1


def _user(**kw):
    from types import SimpleNamespace
    return SimpleNamespace(**{"username": "r.okonjo", "elastic_uid": None, "elastic_username": None, **kw})


def _login(monkeypatch, answers):
    import asyncio

    from ion.web.api import cache_elastic_uid_on_login

    asked = []

    class Svc:
        enabled = True

        def resolve_user_uid(self, name):
            asked.append(name)
            return answers.get(name)

    monkeypatch.setattr(kcs, "get_kibana_cases_service", lambda: Svc())
    return asked, lambda user, session: asyncio.run(cache_elastic_uid_on_login(user, session))


def test_sign_in_keeps_the_uid_and_the_name_it_was_found_under(monkeypatch):
    asked, login = _login(monkeypatch, {"r.okonjo": "u_1"})
    user, session = _user(), _Session()
    login(user, session)
    assert (user.elastic_uid, user.elastic_username, session.commits) == ("u_1", "r.okonjo", 1)
    assert asked == ["r.okonjo"]


def test_sign_in_falls_back_from_the_elastic_name_to_the_ion_name(monkeypatch):
    asked, login = _login(monkeypatch, {"r.okonjo": "u_2"})
    user = _user(elastic_username="rokonjo@corp")
    login(user, _Session())
    assert asked == ["rokonjo@corp", "r.okonjo"]
    assert user.elastic_uid == "u_2" and user.elastic_username == "rokonjo@corp"


def test_a_cached_uid_is_not_looked_up_again(monkeypatch):
    asked, login = _login(monkeypatch, {})
    login(_user(elastic_uid="u_old"), _Session())
    assert asked == []
