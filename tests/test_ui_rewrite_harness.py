"""Guards for the UI rewrite: every route still renders, nothing silently lost.

Rewriting 81,191 lines of templates produces breakage that no existing test
catches, because the two most likely failures are both silent: a dropped
_ion-s-* hashed class renders an unstyled element, and a raw inline style is
refused by style-src-attr 'none' with no error and no log line.

These are the net that makes bulk delegation defensible. Without them, a
114-template migration is unreviewable at the diff level.
"""

import subprocess
import sys

from fastapi.testclient import TestClient

from ion.web.server import app


def test_audit_reports_no_losses_against_baseline():
    """The rewrite may change markup freely; it may not drop a CSP hashed class
    or add a raw inline style."""
    result = subprocess.run(
        [sys.executable, "tools/ui_rewrite_audit.py", "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_get_page_route_renders():
    """A rewritten template with a Jinja syntax error 500s. This catches that
    across every page in one run, which reading diffs does not.

    Only 5xx counts as failure: auth redirects (3xx) and permission denials
    (4xx) are correct behaviour for an unauthenticated test client.
    """
    client = TestClient(app, raise_server_exceptions=False)
    failures = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        # Parameterless GET pages only — templated paths need fixtures this
        # harness deliberately does not build.
        if "GET" not in methods or "{" in path or path.startswith("/api"):
            continue
        response = client.get(path)
        if response.status_code >= 500:
            failures.append(f"{path} -> {response.status_code}")
    assert not failures, f"routes failing to render: {failures}"
