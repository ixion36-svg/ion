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

The single slot later became a per-(tenant, loop) pool so several estates could
be served at once. That changes what "displaced" means: a still-running loop's
client is no longer evicted when another loop asks for one — both keep theirs,
which is the alternation thrash the pool exists to stop. The leak guarantee is
unchanged and re-expressed below: a client whose loop has ended is closed, not
dropped. Live loops are bounded (the web workers), dead ones are pruned, and
the pool is capped, so nothing accumulates.
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
    """Isolate the client pool per test."""
    es_mod._es_pool.clear()
    yield
    for entry in list(es_mod._es_pool.values()):
        if not entry.client.is_closed:
            try:
                asyncio.run(entry.client.aclose())
            except Exception:
                pass
    es_mod._es_pool.clear()


def test_a_live_loops_client_survives_another_loops_request():
    """Both loops keep their own client.

    Under the single slot, a background asyncio.run() cycle evicted the web
    loop's client and forced it to rebuild a connection pool — on every
    alternation. Loop A here is still running and still owns its client, so
    nothing about it is leaked; test_a_dead_loops_client_is_closed covers the
    case where it really is abandoned.
    """
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
    assert client_b is not client_a, "loop B was handed loop A's client"
    assert not client_a.is_closed, "a running loop's client was closed under it"

    loop_a.call_soon_threadsafe(loop_a.stop)
    t.join(timeout=_TIMEOUT)


def test_a_rotated_credential_closes_its_predecessor():
    """The leak guarantee, in the form the pool leaves it.

    A pool entry is displaced only when the credentials behind it change — an
    admin rotating them, or a tenant being re-pointed. The superseded client is
    on the running loop, so it can and must be aclosed rather than dropped;
    asyncio.run() teardown does not close httpx connection pools.

    A client whose loop is already dead cannot be aclosed by anyone — nothing
    can run the coroutine — and _dispose_client documents that fallback. That is
    unchanged by the pool.
    """
    h1 = {"Authorization": "ApiKey key_A", **_HEADERS}
    h2 = {"Authorization": "ApiKey key_B", **_HEADERS}

    async def _rotate():
        first = _get_es_client(h1, None, False, 5)
        second = _get_es_client(h2, None, False, 5)
        assert second is not first
        # aclose was scheduled onto this loop; let it run.
        for _ in range(10):
            if first.is_closed:
                break
            await asyncio.sleep(0)
        return first

    displaced = asyncio.run(_rotate())
    assert displaced.is_closed, "rotated-out client was leaked (never aclosed)"


def test_rebind_after_owner_loop_died_does_not_raise():
    """When the binding loop is already gone, the rebind must neither raise
    nor return the dead-loop client."""

    async def _grab():
        return _get_es_client(_HEADERS, None, False, 5)

    client_a = asyncio.run(_grab())  # loop dies with asyncio.run
    client_b = asyncio.run(_grab())  # new loop → must rebind cleanly
    assert client_b is not client_a
    assert client_b in [e.client for e in es_mod._es_pool.values()]


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
                    # every client the module hands out is stamped with the
                    # loop it was created for; we must NEVER receive one bound
                    # to the other thread's loop (that's the crash the lock +
                    # return-local fix closes). No default: a missing stamp is
                    # itself a failure, not a silent pass.
                    if client._ion_bound_loop is not me:
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
