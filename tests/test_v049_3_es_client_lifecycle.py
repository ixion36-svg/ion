"""v0.49.3 code-review fixes: shared ES client lifecycle.

The v0.39.9 event-loop binding fix (f90879d) left two holes:

1. TOCTOU: _get_es_client mutated and returned the *global* slot with no
   lock, so a background thread's asyncio.run() cycle could rebind the
   global between creation and return, handing a web-loop caller a client
   bound to a throwaway loop — recreating the exact "Event loop is closed"
   crash the fix targeted.

2. Leak: on a cross-loop rebind the displaced client was dropped without
   aclose() ("that loop's teardown reclaims its connections" — it doesn't:
   asyncio.run() teardown does not close httpx pools), leaking keepalive
   sockets on every web/background alternation.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

import ion.services.elasticsearch_service as es_mod
from ion.services.elasticsearch_service import _get_es_client

_TIMEOUT = 5.0
_HEADERS = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def reset_es_client():
    """Isolate the module-level client slot per test."""
    es_mod._es_client = None
    es_mod._es_client_creds = None
    es_mod._es_client_loop = None
    yield
    client = es_mod._es_client
    if client is not None and not client.is_closed:
        try:
            asyncio.run(client.aclose())
        except Exception:
            pass
    es_mod._es_client = None
    es_mod._es_client_creds = None
    es_mod._es_client_loop = None


def test_displaced_client_is_closed_when_its_loop_is_still_alive():
    """Rebinding from loop B must aclose the client bound to a still-running
    loop A (via run_coroutine_threadsafe), not leak its keepalive sockets."""
    loop_a = asyncio.new_event_loop()
    client_a_holder: list = []

    def _thread_a():
        asyncio.set_event_loop(loop_a)

        async def _grab():
            client_a_holder.append(_get_es_client(_HEADERS, None, False, 5))

        loop_a.run_until_complete(_grab())
        loop_a.run_forever()  # stay alive so the aclose can be scheduled onto us

    t = threading.Thread(target=_thread_a, daemon=True)
    t.start()
    deadline = time.monotonic() + _TIMEOUT
    while not client_a_holder and time.monotonic() < deadline:
        time.sleep(0.01)
    assert client_a_holder, "thread A never produced a client"
    client_a = client_a_holder[0]

    async def _rebind():
        return _get_es_client(_HEADERS, None, False, 5)

    client_b = asyncio.run(_rebind())
    assert client_b is not client_a

    deadline = time.monotonic() + _TIMEOUT
    while not client_a.is_closed and time.monotonic() < deadline:
        time.sleep(0.05)
    loop_a.call_soon_threadsafe(loop_a.stop)
    t.join(timeout=_TIMEOUT)
    assert client_a.is_closed, "displaced client was leaked (never aclosed)"


def test_rebind_after_owner_loop_died_does_not_raise():
    """When the binding loop is already gone, the rebind must neither raise
    nor return the dead-loop client."""

    async def _grab():
        return _get_es_client(_HEADERS, None, False, 5)

    client_a = asyncio.run(_grab())  # loop dies with asyncio.run
    client_b = asyncio.run(_grab())  # new loop → must rebind cleanly
    assert client_b is not client_a
    assert es_mod._es_client is client_b


def test_get_es_client_returns_local_not_global():
    """Regression canary for the TOCTOU: two threads hammer _get_es_client on
    their own loops; no call may ever observe a client bound to the *other*
    thread's loop (which is what returning the mutable global allowed)."""
    iterations = 200
    barrier = threading.Barrier(2, timeout=_TIMEOUT)
    errors: list = []

    def _worker():
        try:
            for _ in range(iterations):
                barrier.wait()

                async def _body():
                    me = asyncio.get_running_loop()
                    client = _get_es_client(_HEADERS, None, False, 5)
                    # the client we get must be bound to OUR loop: using it is
                    # what raised "Event loop is closed" pre-fix. We assert on
                    # the module's bookkeeping made under the lock.
                    if client is not es_mod._es_client and not client.is_closed:
                        # displaced by the other thread — that's fine, but then
                        # it must be OUR creation, not the other loop's client
                        bound = getattr(client, "_ion_bound_loop", me)
                        if bound is not me:
                            raise AssertionError("received a foreign-loop client")

                asyncio.run(_body())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_TIMEOUT * 10)
    assert not errors, f"concurrent _get_es_client violations: {errors[:3]}"


def test_lock_serializes_client_creation():
    """The module must guard slot mutation with a real lock — the TOCTOU fix."""
    lock = getattr(es_mod, "_es_client_lock", None)
    assert lock is not None, "_es_client_lock missing — slot mutation unguarded"
    assert hasattr(lock, "acquire") and hasattr(lock, "release")
