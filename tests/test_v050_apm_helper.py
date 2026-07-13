"""v0.50.0 — safety contract for the ion.core.apm wrappers.

These helpers wrap the Elastic APM agent and MUST be pure no-ops when the agent
isn't running (APM disabled / no active transaction), never raising into the
business logic they wrap. The full end-to-end trace path is proven against a
live APM Server; this module pins the always-on safety guarantees.
"""

import asyncio

import pytest

from ion.core import apm


def test_background_transaction_yields_when_no_client(monkeypatch):
    """With no APM client, the wrapper is a transparent pass-through."""
    monkeypatch.setattr(apm, "_client", lambda: None)
    ran = False
    with apm.background_transaction("unit_loop"):
        ran = True
    assert ran is True


def test_background_transaction_reraises(monkeypatch):
    """The loop's own error handling must still see the exception."""
    monkeypatch.setattr(apm, "_client", lambda: None)
    with pytest.raises(ValueError):
        with apm.background_transaction("unit_loop"):
            raise ValueError("boom")


def test_capture_span_no_active_transaction_is_noop():
    """capture_span must yield cleanly with no active transaction/agent."""
    ran = False
    with apm.capture_span("unit.span", "task", foo="bar"):
        ran = True
    assert ran is True


def test_span_decorator_preserves_call():
    @apm.span("unit.sync", "task")
    def add(a, b):
        return a + b

    assert add(2, 3) == 5


def test_async_span_decorator_preserves_call():
    @apm.async_span("unit.async", "task")
    async def add(a, b):
        return a + b

    assert asyncio.run(add(2, 3)) == 5


def test_set_user_and_label_never_raise():
    # No active transaction — these are safe no-ops, must not raise.
    apm.set_user(username="admin", user_id=1, email="a@b.c")
    apm.label(rule_id="R1", verdict="malicious", dropped=None)


def test_helpers_noop_when_apm_flag_off(monkeypatch):
    """Simulate the library-missing / disabled path (_APM False)."""
    monkeypatch.setattr(apm, "_APM", False)
    with apm.capture_span("x"):
        pass
    with apm.background_transaction("x"):
        pass

    @apm.span("x")
    def f():
        return 42

    @apm.async_span("x")
    async def g():
        return 43

    assert f() == 42
    assert asyncio.run(g()) == 43
    apm.set_user(username="u")
    apm.label(k="v")
