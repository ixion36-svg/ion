"""ION-02: webhook management must not be reachable with alert:read.

require_integration_access() accepts integration:read OR alert:read. It was
written for the integrations dashboard -- ES health, connector status, logs --
where letting any analyst look is deliberate. It was then reused on the webhook
mutations, so create, update, delete and token regeneration were all reachable
by six of the nine seeded roles (analyst, senior_analyst, principal_analyst,
lead, forensic, soc_engineer all hold alert:read without integration:manage).

The structural test is the important one: the failure mode here was not a wrong
permission string, it was a read dependency being reused on a new mutation. A
test that reads the route table catches the next one of those; a test that
exercises one endpoint does not.
"""

import re
from pathlib import Path

from ion.auth.dependencies import require_permission

API = Path(__file__).resolve().parent.parent / "src" / "ion" / "web" / "integration_api.py"

MANAGE = 'require_permission("integration:manage")'
READ_DEP = "require_integration_access"

# Authenticated by possession of the webhook token, by design -- it is the
# inbound receiver third parties POST to, not an operator endpoint.
UNAUTHENTICATED_BY_DESIGN = {"/webhooks/receive/{token}"}


def _routes():
    lines = API.read_text(encoding="utf-8").split("\n")
    for i, line in enumerate(lines):
        m = re.match(r'@router\.(get|post|put|patch|delete)\("([^"]*)"', line.strip())
        if m:
            block = "\n".join(lines[i : i + 14])
            yield m.group(1).upper(), m.group(2), block


def test_webhook_mutations_require_integration_manage():
    offenders = []
    for method, path, block in _routes():
        if method == "GET" or path in UNAUTHENTICATED_BY_DESIGN:
            continue
        if not path.startswith("/webhooks"):
            continue
        if MANAGE not in block:
            offenders.append(f"{method} {path}")
    assert not offenders, "webhook mutations reachable without integration:manage: " + ", ".join(offenders)


def test_no_webhook_mutation_uses_the_read_dependency():
    offenders = [f"{method} {path}" for method, path, block in _routes() if method != "GET" and path.startswith("/webhooks") and path not in UNAUTHENTICATED_BY_DESIGN and READ_DEP in block]
    assert not offenders, f"{READ_DEP} accepts alert:read and must not guard a mutation: " + ", ".join(offenders)


def test_read_endpoints_still_accept_alert_read():
    """Over-correcting would lock analysts out of the integrations page."""
    reads = [p for m, p, b in _routes() if m == "GET" and READ_DEP in b]
    assert len(reads) >= 8, f"expected the dashboard reads to stay open, got {reads}"


class _User:
    def __init__(self, *perms):
        self._perms = set(perms)

    def has_permission(self, name):
        return name in self._perms


def test_alert_read_alone_is_rejected_by_the_manage_dependency():
    import pytest
    from fastapi import HTTPException

    dep = require_permission("integration:manage")
    with pytest.raises(HTTPException) as exc:
        dep(user=_User("alert:read", "integration:read"))
    assert exc.value.status_code == 403

    assert dep(user=_User("integration:manage"))._perms == {"integration:manage"}
