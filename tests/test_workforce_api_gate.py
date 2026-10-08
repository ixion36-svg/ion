"""The workforce module is invisible when it is off.

404 rather than 403, so a deployment that does not run the lifecycle is
indistinguishable from one where the feature does not exist — the same
position the DE module and SOAR response actions take.
"""

import re
from pathlib import Path

import pytest

from ion.web import workforce_api

SRC = Path(__file__).resolve().parents[1] / "src" / "ion"


class _Cfg:
    def __init__(self, enabled):
        self.workforce_enabled = enabled


def test_the_gate_404s_when_the_module_is_off(monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setattr(workforce_api, "get_config", lambda: _Cfg(False))
    with pytest.raises(HTTPException) as caught:
        workforce_api.require_workforce_module()
    assert caught.value.status_code == 404
    assert caught.value.detail == "Not found", "the body must not name the feature either"


def test_the_gate_passes_when_the_module_is_on(monkeypatch):
    monkeypatch.setattr(workforce_api, "get_config", lambda: _Cfg(True))
    assert workforce_api.require_workforce_module() is None


def test_every_route_carries_the_module_gate():
    """A route added without the gate leaks the feature's existence."""
    ungated = []
    for route in workforce_api.router.routes:
        deps = getattr(route, "dependencies", []) or []
        names = {getattr(d.dependency, "__name__", "") for d in deps}
        if "require_workforce_module" not in names:
            ungated.append(route.path)
    assert ungated == [], ungated


def test_the_flag_defaults_on():
    """Reversed deliberately, 2026-10-08.

    This asserted False, on the reasoning that a lifecycle must be opted
    into. The module shipped complete, migrated and inert behind a 404 an
    operator cannot tell apart from broken, and "who is cleared to be on
    this console today, and what did we take off them when they left" is
    not an optional extra for a SOC.

    Being on grants nobody anything: a journey still has to be assigned and
    its requirements verified before sync_granted_roles confers a role. The
    flag stays so a deployment that does not want the module can switch it
    off -- see test_workforce_enabled_by_default.py.
    """
    code = (SRC / "core" / "config.py").read_text(encoding="utf-8")
    match = re.search(r"workforce_enabled:\s*bool\s*=\s*(\w+)", code)
    assert match and match.group(1) == "True"


def test_rule_violations_are_client_errors_not_500s():
    from ion.services.workforce_service import WorkforceError

    denied = workforce_api._err(WorkforceError("Permission denied"))
    assert denied.status_code == 403

    bad = workforce_api._err(WorkforceError("Only a published version can be assigned"))
    assert bad.status_code == 400
    assert "published" in bad.detail


def test_mutating_routes_require_a_permission():
    """A write path with only get_current_user would let any analyst edit roles."""
    writes = [r for r in workforce_api.router.routes
              if set(getattr(r, "methods", set())) & {"POST", "DELETE", "PUT", "PATCH"}]
    assert writes, "expected write routes"

    source = (SRC / "web" / "workforce_api.py").read_text(encoding="utf-8")
    # Routes that check authorisation inside the service take get_current_user
    # deliberately; they must still hand the caller to the service.
    # Only routes whose authorisation is genuinely data-dependent (owner or
    # sponsor) stay single-layer; static-permission writes carry BOTH the route
    # dependency and the in-service check.
    # record_equivalent is here for the same reason as verify: the
    # authorisation is _may_verify, which depends on whether the caller
    # sponsors THIS journey, so it cannot be a static route dependency.
    # acknowledge_duty joins them: only the person ON duty may
    # acknowledge it, which depends on the row rather than on a role, so
    # it cannot be a static route dependency either.
    service_checked = ("verify", "submit_item", "withdraw_item",
                       "record_equivalent", "acknowledge_duty")
    for route in writes:
        name = route.name
        if name in service_checked:
            block = source.split("def " + name + "(")[1].split("\n\n\n")[0]
            assert "user: User = Depends(get_current_user)" in block, name
            assert re.search(r"(assigner|verifier|raiser|submitter|actor|assessor)=user", block), \
                f"{name} must pass the caller to the service for the check"
        else:
            block = source.split("def " + name + "(")[1].split("\n\n\n")[0]
            assert "require_permission(" in block, f"{name} has no permission dependency"
