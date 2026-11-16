from types import SimpleNamespace

import pytest
from fastapi import Request


@pytest.mark.parametrize('path', ['/observables', '/forensics'])
def test_page_supplies_authenticated_user_to_permission_controls(monkeypatch, path):
    from ion.web import server
    endpoint = next(route.endpoint for route in server.app.routes if getattr(route, 'path', None) == path)
    user = SimpleNamespace(has_permission=lambda permission: True)
    captured = {}

    def render(**kwargs):
        captured.update(kwargs)
        return 'rendered'

    monkeypatch.setattr(server.templates, 'TemplateResponse', render)
    request = Request({'type': 'http', 'method': 'GET', 'path': path, 'headers': []})
    assert endpoint(request=request, user=user) == 'rendered'
    assert captured['context']['current_user'] is user
