from types import SimpleNamespace
import importlib

import pytest


@pytest.mark.parametrize('format', ['password={}', 'token="{}"', 'api_key: {}', 'Authorization: Bearer {}', 'https://user:{}@host/path?token={}', 'postgresql://user:{}@host/db'])
def test_diagnostic_credentials_are_removed_without_losing_message(format):
    try:
        module = importlib.import_module('ion.web.ui._integration_safety')
        redact = module.safe_diagnostic
    except ModuleNotFoundError:
        redact = lambda value: value
    secret = 'private-' + str(id(format))
    result = redact('Connection failed: ' + format.format(secret, secret))
    assert secret not in result
    assert 'Connection failed' in result


def test_configured_secret_is_redacted_even_without_a_label(monkeypatch):
    try:
        module = importlib.import_module('ion.web.ui._integration_safety')
    except ModuleNotFoundError:
        module = SimpleNamespace(safe_diagnostic=lambda value: value, get_config=lambda: None)
    secret = 'private-' + str(id(monkeypatch))
    monkeypatch.setattr(module, 'get_config', lambda: SimpleNamespace(elasticsearch_api_key=secret))
    assert module.safe_diagnostic('Remote rejected ' + secret) == 'Remote rejected [redacted]'
