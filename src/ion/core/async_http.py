"""Loop-bound ``httpx.AsyncClient`` management, shared across integrations.

An ``httpx.AsyncClient`` binds its connection pool to the event loop that
created it, and cannot be used from another one. ION's background services
run work through ``asyncio.run()``, which builds a fresh loop each cycle and
closes it afterwards, so any client cached from inside such a cycle is left
pointing at a dead loop. The next caller — usually the long-lived web loop —
gets it back and raises ``RuntimeError: Event loop is closed``.

The obvious guard does not catch this::

    if client is None or client.is_closed:

``is_closed`` reports whether ``aclose()`` was called. A client whose *loop*
died was never closed, so it reads as perfectly healthy.

``elasticsearch_service`` worked this out first and carries the full version
— a pool keyed by tenant and loop, because one estate's client would
otherwise evict another's. This module holds the parts that are not specific
to that pooling, so a second integration does not grow a second copy of the
reasoning.
"""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

__all__ = ["current_loop", "dispose_client", "is_usable_on"]


def current_loop() -> Optional[asyncio.AbstractEventLoop]:
    """The running loop, or None when called outside one.

    Construction of a client does not need a loop; only I/O does. So callers
    in synchronous setup code are handled rather than refused.
    """
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def is_usable_on(
    client: Optional[httpx.AsyncClient],
    bound_loop: Optional[asyncio.AbstractEventLoop],
    loop: Optional[asyncio.AbstractEventLoop],
) -> bool:
    """Whether ``client`` may be handed to a caller running on ``loop``.

    Identity comparison on the loop object, never ``id()``: CPython reuses
    the address of a collected object, so a fresh loop can land on a dead
    one's id and be handed its client. Holding the loop reference also keeps
    it from being collected while the entry exists.
    """
    if client is None or client.is_closed:
        return False
    if bound_loop is not None and bound_loop.is_closed():
        return False
    # A client built outside any loop has no binding yet, but its pool is
    # created on first use, so it belongs to whichever loop gets there
    # first. Treat it as usable only by a caller in the same situation.
    return bound_loop is loop


def dispose_client(
    client: Optional[httpx.AsyncClient],
    bound_loop: Optional[asyncio.AbstractEventLoop],
    loop: Optional[asyncio.AbstractEventLoop],
) -> None:
    """Best-effort ``aclose`` of a displaced client. Never raises.

    ``asyncio.run()`` teardown does NOT close httpx connection pools, so
    simply dropping the reference leaks keepalive sockets. Closing
    cross-loop is safe via ``run_coroutine_threadsafe`` as long as the
    owning loop still runs; only when it is already dead do we fall back to
    dropping the reference and letting GC finalizers reclaim the sockets.
    """
    if client is None or getattr(client, "is_closed", False):
        return
    try:
        if loop is not None and loop is bound_loop:
            loop.create_task(client.aclose())
        elif bound_loop is not None and not bound_loop.is_closed():
            asyncio.run_coroutine_threadsafe(client.aclose(), bound_loop)
        elif bound_loop is None and loop is None:
            asyncio.run(client.aclose())
        # else: the owning loop is already dead — nothing can run its
        # aclose, so drop the reference.
    except Exception:  # noqa: BLE001 — disposal must never break a request
        pass
