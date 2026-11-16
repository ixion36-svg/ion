"""Every branch of POST /config/test/{integration} must return a real body.

`test_connection` is `async def` on some services (GitLab, OpenCTI,
Elasticsearch) and a plain `def` on others (Kibana Cases, TIDE). A branch that
calls an async one without `await` hands FastAPI a coroutine, which it cannot
serialise, and the settings page gets HTTP 500 instead of a verdict:

    ValueError: [TypeError("'coroutine' object is not iterable"), ...]

That is what shipped for OpenCTI and GitLab. The services are mocked here with
the same async-ness as the real ones, so a call site that stops matching its
service fails this test with no live Elasticsearch, OpenCTI or TIDE in sight.
"""
import importlib
import inspect

import pytest
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.core.config import get_config
from ion.models.user import Permission, Role, User
from ion.web.server import app


@pytest.fixture
def admin_client():
    """Authenticated as a user holding system:settings.

    Same style as tests/test_config_sources_api.py: override get_current_user
    with an in-memory user, so no DB or login flow is needed. The client sends
    no session cookie, which is how it is exempt from CSRF.

    raise_server_exceptions=False so an unserialisable body arrives as the 500
    the browser would see, rather than as an exception out of the test client.
    """
    perm = Permission(name="system:settings", resource="system", action="settings")
    role = Role(name="admin")
    role.permissions = [perm]
    user = User(
        id=1, username="admin", email="admin@localhost", password_hash="x",
        display_name="Administrator", is_active=True,
    )
    user.roles = [role]
    app.dependency_overrides[get_current_user] = lambda: user
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()


class _AsyncService:
    """Stands in for a service whose test_connection is `async def`."""

    is_configured = True
    enabled = True

    def __init__(self, result):
        self._result = result

    async def test_connection(self):
        return self._result


class _SyncService:
    """Stands in for a service whose test_connection is a plain `def`."""

    is_configured = True
    enabled = True

    def __init__(self, result):
        self._result = result

    def test_connection(self):
        return self._result


# One entry per service-backed branch of test_integration_connection: the
# integration name, the module the branch imports from, the name the branch
# calls to obtain a service, the real service class, the stub whose async-ness
# mirrors that class, and what test_connection returns.
BRANCHES = [
    ("gitlab", "ion.services.gitlab_service", "get_gitlab_service",
     "GitLabService", _AsyncService, {"connected": True, "project_name": "soc"}),
    ("opencti", "ion.services.opencti_service", "get_opencti_service",
     "OpenCTIService", _AsyncService, {"connected": True, "user_name": "admin"}),
    ("elasticsearch", "ion.services.elasticsearch_service", "ElasticsearchService",
     "ElasticsearchService", _AsyncService, {"connected": True, "version": "9.4.4"}),
    ("kibana", "ion.services.kibana_cases_service", "get_kibana_cases_service",
     "KibanaCasesService", _SyncService, {"success": True, "spaces": 1}),
    ("tide", "ion.services.tide_service", "get_tide_service",
     "TideService", _SyncService, {"ok": True, "count": 3}),
]

_BRANCH_IDS = [b[0] for b in BRANCHES]


@pytest.mark.parametrize(
    "integration,module_path,factory,service_class,stub,result",
    BRANCHES,
    ids=_BRANCH_IDS,
)
def test_branch_returns_a_serialisable_verdict(
    admin_client, monkeypatch, integration, module_path, factory, service_class,
    stub, result,
):
    module = importlib.import_module(module_path)
    monkeypatch.setattr(module, factory, lambda *a, **kw: stub(result))
    if integration == "tide":
        monkeypatch.setattr(module, "reset_tide_service", lambda: None)

    resp = admin_client.post(f"/api/admin/config/test/{integration}")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["success"] is True
    assert body["details"] == result


@pytest.mark.parametrize(
    "integration,module_path,factory,service_class,stub,result",
    BRANCHES,
    ids=_BRANCH_IDS,
)
def test_stub_matches_the_real_service_signature(
    integration, module_path, factory, service_class, stub, result
):
    """The stubs above only prove anything while they mirror the real services.

    If a service switches between `def` and `async def`, this fails and says so,
    instead of the endpoint test passing against a stub of the wrong shape.
    """
    cls = getattr(importlib.import_module(module_path), service_class)
    assert inspect.iscoroutinefunction(cls.test_connection) is inspect.iscoroutinefunction(
        stub.test_connection
    ), f"{service_class}.test_connection changed async-ness; update BRANCHES"


def test_dfir_iris_branch_returns_a_serialisable_verdict(admin_client, monkeypatch):
    """This branch talks to httpx directly rather than through a service."""
    import httpx

    config = get_config()
    monkeypatch.setattr(config, "dfir_iris_enabled", True)
    monkeypatch.setattr(config, "dfir_iris_url", "https://iris.example")
    monkeypatch.setattr(config, "dfir_iris_api_key", "k")

    payload = {"iris_current_version": "2.4.0"}

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return _Response()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    resp = admin_client.post("/api/admin/config/test/dfir_iris")

    assert resp.status_code == 200, resp.text
    assert resp.json() == {"success": True, "details": payload}


def test_unknown_integration_is_rejected(admin_client):
    resp = admin_client.post("/api/admin/config/test/nope")
    assert resp.status_code == 400
