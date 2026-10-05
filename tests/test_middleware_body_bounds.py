"""Security monitoring must not allocate the request body it only scans.

_buffer_body() used to drain the whole body, join it, and decode all of it
before slicing the decoded string to 10,000 characters — a cap on scanned text,
not on received bytes. The middleware runs before routing, CSRF and auth, so an
anonymous POST to any non-excluded path sized a worker allocation, and the
streaming caps in the upload handlers (read_upload_capped, the 10 MB document
limit) could not protect a layer above them.

It now consumes only the scanning prefix and streams the remainder through, so
the route still sees a complete body this layer never held.
"""

import asyncio

from ion.web.security_middleware import _SCAN_BYTES, SecurityMonitoringMiddleware

_buffer = SecurityMonitoringMiddleware._buffer_body


def _receiver(messages):
    it = iter(messages)

    async def receive():
        return next(it)

    return receive


def _chunks(count, size, final_more=False):
    return [
        {"type": "http.request", "body": b"x" * size,
         "more_body": (i < count - 1) or final_more}
        for i in range(count)
    ]


def test_large_body_is_not_retained():
    """The 12 MB that used to come back is now bounded by the scan window."""
    prefix, _ = asyncio.run(_buffer(_receiver(_chunks(12, 1024 * 1024))))
    assert len(prefix) <= _SCAN_BYTES


def test_oversize_body_stops_reading_early():
    """Reading must stop at the window, not drain the stream to find the end."""
    messages = _chunks(12, 1024 * 1024)
    consumed = []

    async def receive():
        msg = messages[len(consumed)]
        consumed.append(msg)
        return msg

    asyncio.run(_buffer(receive))
    assert len(consumed) == 1, f"drained {len(consumed)} chunks to scan {_SCAN_BYTES} bytes"


def test_route_still_receives_the_whole_body():
    """Bounding the scan must not truncate what the handler reads."""
    messages = _chunks(4, 1024 * 1024)
    _, replay = asyncio.run(_buffer(_receiver(messages)))

    async def drain():
        seen = b""
        while True:
            msg = await replay()
            if msg["type"] != "http.request":
                break
            seen += msg["body"]
            if not msg.get("more_body", False):
                break
        return seen

    assert len(asyncio.run(drain())) == 4 * 1024 * 1024


def test_small_body_is_fully_scanned():
    body = b'{"q": "1 OR 1=1"}'
    prefix, replay = asyncio.run(_buffer(_receiver(
        [{"type": "http.request", "body": body, "more_body": False}])))
    assert prefix == body
    assert asyncio.run(replay())["body"] == body


def test_exhausted_body_replays_a_disconnect_not_a_hang():
    """A handler asking past the end must not block on a drained stream."""
    _, replay = asyncio.run(_buffer(_receiver(
        [{"type": "http.request", "body": b"x", "more_body": False}])))
    asyncio.run(replay())
    assert asyncio.run(replay())["type"] == "http.disconnect"


def test_disconnect_mid_body_is_handled():
    prefix, _ = asyncio.run(_buffer(_receiver([
        {"type": "http.request", "body": b"abc", "more_body": True},
        {"type": "http.disconnect"},
    ])))
    assert prefix == b"abc"


def test_prefix_is_sliced_as_bytes():
    """A multi-byte body must be cut on bytes, so the cap bounds the allocation."""
    body = ("é" * _SCAN_BYTES).encode("utf-8")  # 2 bytes per character
    prefix, _ = asyncio.run(_buffer(_receiver(
        [{"type": "http.request", "body": body, "more_body": False}])))
    assert len(prefix) == _SCAN_BYTES
    prefix.decode("utf-8", errors="ignore")  # a split character must not raise
