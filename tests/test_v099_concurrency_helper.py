"""Contract for ion.core.concurrency — the fan-out helper the integration
call sites rely on.

Three properties are load-bearing for the callers: results come back in input
order (they zip them against the inputs), one failing item does not sink the
batch, and concurrency really is capped (an air-gapped single-node OpenCTI or
DFIR-IRIS must not see 100 connections at once). Repo pattern is asyncio.run,
not pytest-asyncio.
"""

import asyncio

import pytest

from ion.core.concurrency import DEFAULT_FANOUT, gather_bounded, map_bounded


def test_results_keep_input_order():
    async def scenario():
        async def work(i):
            # Reverse the completion order: without ordering guarantees the
            # result list would come back backwards.
            await asyncio.sleep((10 - i) * 0.005)
            return i * 2

        return await map_bounded(list(range(10)), work, limit=10)

    assert asyncio.run(scenario()) == [i * 2 for i in range(10)]


def test_one_failure_does_not_sink_the_batch():
    async def scenario():
        async def work(i):
            if i == 2:
                raise RuntimeError("boom")
            return i

        return await map_bounded([1, 2, 3], work, limit=2)

    out = asyncio.run(scenario())
    assert out[0] == 1
    assert isinstance(out[1], RuntimeError)
    assert out[2] == 3


def test_concurrency_is_capped():
    async def scenario():
        live = 0
        peak = 0

        async def work(_i):
            nonlocal live, peak
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.01)
            live -= 1

        await map_bounded(list(range(25)), work, limit=4)
        return peak

    assert asyncio.run(scenario()) <= 4


def test_bounded_run_beats_serial():
    async def scenario():
        async def work(_i):
            await asyncio.sleep(0.02)

        loop = asyncio.get_running_loop()
        start = loop.time()
        await map_bounded(list(range(16)), work, limit=8)
        return loop.time() - start

    # Serial would be 16 * 0.02 = 0.32s; at limit 8 it is two waves (~0.04s).
    assert asyncio.run(scenario()) < 0.2


def test_gather_bounded_propagates_when_asked():
    async def scenario():
        async def boom():
            raise ValueError("nope")

        async def fine():
            return 1

        return await gather_bounded([fine(), boom()], limit=2, return_exceptions=False)

    with pytest.raises(ValueError):
        asyncio.run(scenario())


def test_rejects_a_nonsense_limit():
    async def scenario():
        return await gather_bounded([], limit=0)

    with pytest.raises(ValueError):
        asyncio.run(scenario())


def test_empty_input_is_a_no_op():
    assert asyncio.run(map_bounded([], lambda _x: None)) == []
    assert DEFAULT_FANOUT >= 1
