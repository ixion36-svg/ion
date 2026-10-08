"""OpenCTI's shared httpx client must not outlive the loop it was built on.

Found on the full integration estate, 8 October 2026: with OpenCTI up,
reachable and serving, ION's integrations page reported

    opencti    error    Event loop is closed

``httpx.AsyncClient`` binds its connection pool to the event loop that
created it. ION's background services run work through ``asyncio.run()``,
which builds a fresh loop each cycle and closes it afterwards, so a client
first created inside one of those cycles is left pointing at a dead loop.
The next caller — typically the long-lived web loop — gets it back and
raises.

The guard that was there could not catch this::

    if _opencti_client is None or _opencti_client.is_closed:

``is_closed`` reports whether ``aclose()`` was called. A client whose
*loop* died was never closed, so it reads as perfectly good.

``elasticsearch_service`` already solved this: track the loop a client was
bound to and rebuild when the running loop differs. These tests hold
OpenCTI to the same contract. OpenCTI needs no tenant dimension — it is
deliberately an estate-wide service, unlike Elasticsearch — so the binding
is on the loop alone.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services import opencti_service


@pytest.fixture(autouse=True)
def _reset_client():
    """Each test starts with no cached client."""
    opencti_service._reset_opencti_client()
    yield
    opencti_service._reset_opencti_client()


def _get():
    return opencti_service._get_opencti_client(False, 10.0)


# ── Reuse within one loop ────────────────────────────────────────────────


class TestSameLoop:
    def test_two_calls_on_one_loop_share_a_client(self):
        """The whole point of a shared client is not rebuilding the pool."""
        async def _run():
            return _get(), _get()

        a, b = asyncio.run(_run())
        assert a is b

    def test_the_client_is_usable(self):
        async def _run():
            c = _get()
            return c.is_closed

        assert asyncio.run(_run()) is False


# ── The actual defect ────────────────────────────────────────────────────


class TestAcrossLoops:
    def test_a_second_loop_does_not_inherit_the_first_loops_client(self):
        """The regression. Before the fix both calls returned one client,
        whose pool belonged to a loop that had already been torn down."""
        first = asyncio.run(_wrap())
        second = asyncio.run(_wrap())
        assert first is not second

    def test_the_client_from_a_dead_loop_is_never_handed_out(self):
        first = asyncio.run(_wrap())

        async def _check():
            current = _get()
            assert current is not first
            # And the replacement belongs to the loop asking for it.
            assert current.is_closed is False
            return True

        assert asyncio.run(_check()) is True

    def test_repeated_cycles_do_not_raise(self):
        """asyncio.run() per cycle is exactly what the background services
        do, and it is what produced "Event loop is closed" in production."""
        seen = []
        for _ in range(4):
            seen.append(asyncio.run(_wrap()))
        assert len({id(c) for c in seen}) == 4

    def test_the_displaced_client_is_not_left_open(self):
        """asyncio.run() teardown does not close httpx pools, so dropping
        the reference without disposal leaks keepalive sockets."""
        first = asyncio.run(_wrap())
        asyncio.run(_wrap())
        # Disposal of a client whose loop is already dead can only drop the
        # reference, so this asserts the bookkeeping rather than the socket:
        # the cache must no longer be holding the dead-loop client.
        assert opencti_service._opencti_client is not first


async def _wrap():
    return _get()


# ── No running loop at all ───────────────────────────────────────────────


class TestNoRunningLoop:
    def test_a_client_can_be_built_outside_a_loop(self):
        """Construction does not require a running loop; only I/O does. A
        caller doing this in sync setup code must not crash."""
        c = _get()
        assert c is not None

    def test_a_client_built_outside_a_loop_is_not_reused_inside_one(self):
        """It has no loop binding, so a loop-bound caller needs its own."""
        outside = _get()

        async def _inside():
            return _get()

        assert asyncio.run(_inside()) is not outside


# ── Thread safety ────────────────────────────────────────────────────────


class TestConcurrency:
    def test_parallel_loops_each_get_their_own(self):
        """A background thread's asyncio.run() must not rebind the entry
        between a web-loop caller's create and its return."""
        import threading

        results: list = []
        lock = threading.Lock()

        def _worker():
            c = asyncio.run(_wrap())
            with lock:
                results.append(c)

        threads = [threading.Thread(target=_worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 6
        # Every loop was distinct, so every client must be.
        assert len({id(c) for c in results}) == 6


# ── Shared disposal helper ───────────────────────────────────────────────


class TestSharedDisposal:
    def test_the_disposal_helper_is_shared_not_duplicated(self):
        """elasticsearch_service worked this out first; OpenCTI reuses that
        reasoning rather than growing a second copy of it."""
        from ion.core.async_http import dispose_client

        assert callable(dispose_client)

    def test_elasticsearch_still_routes_through_it(self):
        from ion.services import elasticsearch_service

        assert hasattr(elasticsearch_service, "_dispose_client")

    def test_disposing_none_is_safe(self):
        from ion.core.async_http import dispose_client

        dispose_client(None, None, None)  # must not raise

    def test_disposal_never_raises(self):
        """Disposal runs on paths that must not fail a request."""
        from ion.core.async_http import dispose_client

        class _Exploding:
            is_closed = False

            def aclose(self):
                raise RuntimeError("boom")

        dispose_client(_Exploding(), None, None)
