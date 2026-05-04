"""Integration tests: /cyab/studio is now a 301 redirect to /cyab/systems[/:id].

Kept for one minor version (v0.19.x). Drop in v0.20.0.
"""

import pytest


def test_studio_without_system_redirects_to_systems_list(client):
    r = client.get("/cyab/studio", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] in ("/cyab/systems", "/cyab")


def test_studio_with_system_redirects_to_per_system_page(client):
    r = client.get("/cyab/studio?system=123", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "/cyab/systems/123"
