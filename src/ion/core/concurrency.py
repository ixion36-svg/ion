"""Bounded-concurrency helper for fan-out over external services.

ION fans out to Elasticsearch, OpenCTI, Arkime and DFIR-IRIS a request at a
time in several places. A bare ``asyncio.gather`` fixes the latency but opens
every connection at once, which an air-gapped single-node OpenCTI or IRIS will
not thank us for. These helpers cap in-flight work instead.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, Iterable, List, Sequence, TypeVar

T = TypeVar("T")

# Concurrent requests per fan-out. Chosen to beat serial latency by an order of
# magnitude while staying under the connection limits of a single-node
# integration; callers with a heavier per-request cost pass their own.
DEFAULT_FANOUT = 8


async def gather_bounded(
    awaitables: Iterable[Awaitable[T]],
    *,
    limit: int = DEFAULT_FANOUT,
    return_exceptions: bool = False,
) -> List[Any]:
    """``asyncio.gather`` with at most ``limit`` awaitables in flight.

    Results keep the order of the input, so callers can zip them back against
    whatever they fanned out over.
    """
    if limit < 1:
        raise ValueError("limit must be >= 1")
    sem = asyncio.Semaphore(limit)

    async def _run(aw: Awaitable[T]) -> T:
        async with sem:
            return await aw

    return await asyncio.gather(
        *(_run(aw) for aw in awaitables), return_exceptions=return_exceptions
    )


async def map_bounded(
    items: Sequence[T],
    fn: Callable[[T], Awaitable[Any]],
    *,
    limit: int = DEFAULT_FANOUT,
    return_exceptions: bool = True,
) -> List[Any]:
    """Apply an async ``fn`` across ``items`` with bounded concurrency.

    Defaults to ``return_exceptions=True``: these fan-outs are best-effort
    enrichment paths where one failing item must not sink the batch. The
    caller gets the exception in that slot and decides.
    """
    return await gather_bounded(
        (fn(item) for item in items), limit=limit, return_exceptions=return_exceptions
    )
