"""The /cyab/studio redirect was dropped in v0.20.0.

Verify that the old URL now returns 404 (no redirect stub present).
"""


def test_studio_url_is_gone(client):
    r = client.get("/cyab/studio", follow_redirects=False)
    assert r.status_code == 404


def test_studio_url_with_system_is_gone(client):
    r = client.get("/cyab/studio?system=123", follow_redirects=False)
    assert r.status_code == 404
