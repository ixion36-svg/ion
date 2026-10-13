import importlib
from types import SimpleNamespace

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    try:
        ui = importlib.import_module('ion.web.ui._integrations_topology')
    except ModuleNotFoundError as error:
        if error.name != 'ion.web.ui._integrations_topology':
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    if hasattr(ui, 'read_service'):
        async def unavailable(service, user):
            if service == 'gitlab':
                return await ui.gitlab_api.get_gitlab_config_endpoint(current_user=user), None
            return None, None
        monkeypatch.setattr(ui, 'read_service', unavailable)
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(has_permission=lambda p: p == 'alert:read')
    return TestClient(app), ui


@pytest.mark.parametrize('configured', [None, {}, {'enabled': False}, {'enabled': True, 'url': 'https://host'}])
def test_topology_configuration_outcomes(client, monkeypatch, configured):
    c, ui = client
    if hasattr(ui, 'read_service'):
        async def read_service(service, user):
            return configured, {'connected': True, 'version': '1.2', 'node_count': 0}
        monkeypatch.setattr(ui, 'read_service', read_service)
    response = c.get('/ui/integrations/topology', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    service = response.json()['services'][0]
    expected = 'unknown' if configured is None or configured == {} else 'disabled' if configured.get('enabled') is False else 'healthy'
    assert service['status'] == expected
    assert service['nodes'] == (0 if expected == 'healthy' else None)


def test_topology_withholds_gitlab_before_reading(client, monkeypatch):
    c, ui = client
    if hasattr(ui, 'gitlab_api'):
        async def forbidden(**kwargs):
            pytest.fail('GitLab source called without template:read')
        monkeypatch.setattr(ui.gitlab_api, 'get_gitlab_config_endpoint', forbidden)
    response = c.get('/ui/integrations/topology', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    gitlab = next(item for item in response.json()['services'] if item['id'] == 'gitlab')
    assert gitlab['state'] == 'withheld'
    assert gitlab['endpoint'] is None
    assert 'withheld' in c.get('/ui/integrations/topology').text.lower()


def test_topology_drops_secrets_and_url_credentials(client, monkeypatch):
    c, ui = client
    # Runtime-generated sentinel cannot accidentally become a committed credential.
    sentinel = 'sensitive-' + str(id(c))
    if hasattr(ui, 'read_service'):
        async def read_service(service, user):
            return {'enabled': True, 'url': 'https://user:' + sentinel + '@host/path?token=' + sentinel, 'token': sentinel}, {
                'connected': True, 'password': sentinel, 'api_key': sentinel, 'error': sentinel, 'node_count': 0,
            }
        monkeypatch.setattr(ui, 'read_service', read_service)
    for headers in [{}, {'Accept': 'application/json'}]:
        response = c.get('/ui/integrations/topology', headers=headers)
        assert response.status_code == 200
        assert sentinel not in response.text
        assert 'user:' not in response.text
        assert '?token' not in response.text
    model = c.get('/ui/integrations/topology', headers={'Accept': 'application/json'}).json()
    assert model['services'][0]['endpoint'] == 'https://host/path'
    assert model['services'][0]['nodes'] == 0


def test_topology_requires_page_permission(client):
    c, ui = client
    if hasattr(ui, 'PERMISSION'):
        def denied():
            raise HTTPException(403, 'Forbidden')
        c.app.dependency_overrides[ui.PERMISSION] = denied
    assert c.get('/ui/integrations/topology').status_code == 403


def test_truncated_endpoint_is_not_mistaken_for_a_safe_hostname():
    from ion.web.ui._integrations_topology import safe_endpoint
    credential = 'credential-' + str(id(object())) * 8
    truncated = ('https://' + credential + '@host')[:50] + '...'
    assert safe_endpoint(truncated) is None


def test_ollama_default_model_uses_actual_api_field(client, monkeypatch):
    c, ui = client
    async def read_service(service, user):
        return {'available': True, 'default_model': 'example-model'}, {'available': True, 'default_model': 'example-model'}
    monkeypatch.setattr(ui, 'read_service', read_service)
    model = c.get('/ui/integrations/topology', headers={'Accept': 'application/json'}).json()
    ollama = next(item for item in model['services'] if item['id'] == 'ollama')
    assert ollama['model'] == 'example-model'


@pytest.mark.parametrize('status,expected', [('degraded','error'), ('error','error'), ({},'unknown'), (['healthy'],'unknown')])
def test_explicit_failure_and_malformed_status_never_look_healthy(client, monkeypatch, status, expected):
    c, ui = client
    async def read_service(service, user):
        return {'enabled': True}, {'connected': True, 'status': status}
    monkeypatch.setattr(ui, 'read_service', read_service)
    response = c.get('/ui/integrations/topology', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    assert response.json()['services'][0]['status'] == expected
