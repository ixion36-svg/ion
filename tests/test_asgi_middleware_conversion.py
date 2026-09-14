"""SecurityHeaders and RequestLogging are pure ASGI, not BaseHTTPMiddleware.

BaseHTTPMiddleware builds a Request object and runs the rest of the app in a
separate task for every layer in the chain. Measured on this stack, the two
layers converted here cost ~19% and ~19% of throughput respectively for work
that is only header-setting and timing; the pure-ASGI form of SecurityHeaders
measured ~4.5%.

The risk in that conversion is silent behaviour drift -- a header that stops
being set, a header that starts being set twice because raw ASGI headers are a
list rather than a mapping, or a ContextVar that no longer reaches the
templates. These tests pin the observable behaviour, not the implementation.
"""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ion.web.logging_middleware import (  # noqa: E402
    RequestLoggingMiddleware,
    _client_ip,
    _trace_id,
)
from ion.web.server import SecurityHeadersMiddleware, app  # noqa: E402

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-xss-protection": "1; mode=block",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "server": "ION",
}


@pytest.fixture
async def client():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        yield c


def test_both_are_pure_asgi_not_basehttpmiddleware():
    from starlette.middleware.base import BaseHTTPMiddleware

    for mw in (SecurityHeadersMiddleware, RequestLoggingMiddleware):
        assert not issubclass(mw, BaseHTTPMiddleware), (
            f"{mw.__name__} is back on BaseHTTPMiddleware, which costs ~19% of throughput"
        )
        assert hasattr(mw, "__call__")


@pytest.mark.anyio
async def test_every_security_header_is_present(client):
    r = await client.get("/login")
    for name, value in SECURITY_HEADERS.items():
        assert r.headers.get(name) == value, f"{name} missing or changed"


@pytest.mark.anyio
async def test_no_header_is_emitted_twice(client):
    """Raw ASGI headers are a list, so assignment semantics have to be recreated.

    Appending without removing an existing value yields two Server headers --
    the kind of defect that only shows up in a raw header dump.
    """
    r = await client.get("/login")
    names = [k.decode("latin-1").lower() for k, _ in r.headers.raw]
    for name in (*SECURITY_HEADERS, "content-security-policy", "x-request-id"):
        assert names.count(name) <= 1, f"{name} emitted {names.count(name)} times"


@pytest.mark.anyio
async def test_csp_nonce_in_the_header_matches_the_rendered_page(client):
    """The ContextVar must still reach the Jinja `csp_nonce` global.

    If it did not, every nonced <script> in the page would carry a different
    nonce from the policy and the browser would refuse to run any of them.
    """
    r = await client.get("/login")
    csp = r.headers["content-security-policy"]
    assert "'nonce-" in csp
    nonce = csp.split("'nonce-")[1].split("'")[0]
    assert len(nonce) >= 20
    assert nonce in r.text, "page was rendered with a different nonce than the policy"


@pytest.mark.anyio
async def test_nonce_differs_between_requests(client):
    def nonce_of(resp):
        return resp.headers["content-security-policy"].split("'nonce-")[1].split("'")[0]

    assert nonce_of(await client.get("/login")) != nonce_of(await client.get("/login"))


@pytest.mark.anyio
async def test_hsts_absent_over_plain_http(client):
    """HSTS over HTTP would pin a development origin to a scheme it cannot serve."""
    r = await client.get("/login")
    assert "strict-transport-security" not in r.headers


@pytest.mark.anyio
async def test_hsts_present_when_the_proxy_says_https(client):
    r = await client.get("/login", headers={"X-Forwarded-Proto": "https"})
    assert r.headers.get("strict-transport-security") == (
        "max-age=31536000; includeSubDomains"
    )


@pytest.mark.anyio
async def test_request_id_is_generated_and_returned(client):
    r = await client.get("/login")
    assert r.headers.get("x-request-id")
    assert r.headers.get("x-response-time", "").endswith("ms")


@pytest.mark.anyio
async def test_a_supplied_request_id_is_echoed(client):
    r = await client.get("/login", headers={"X-Request-ID": "supplied-id"})
    assert r.headers["x-request-id"] == "supplied-id"


# --------------------------------------------------------------------------
# The operator-precedence defects fixed during the conversion.
# `a or b if cond else None` parses as `(a or b) if cond else None` -- see
# CLAUDE.md. Both of these silently dropped a caller-supplied value.
# --------------------------------------------------------------------------

def test_supplied_trace_id_survives_without_a_traceparent():
    """The regression: X-Trace-ID was discarded whenever traceparent was absent."""
    headers = [(b"x-trace-id", b"caller-trace-abc")]
    assert _trace_id(headers, "generated") == "caller-trace-abc"


def test_supplied_trace_id_wins_over_traceparent():
    headers = [(b"x-trace-id", b"caller-trace-abc"), (b"traceparent", b"00-tid-sid-01")]
    assert _trace_id(headers, "generated") == "caller-trace-abc"


def test_traceparent_is_used_when_no_trace_id_header():
    assert _trace_id([(b"traceparent", b"00-abc123-def456-01")], "generated") == "abc123"


def test_falls_back_to_request_id():
    assert _trace_id([], "generated") == "generated"
    assert _trace_id([(b"traceparent", b"malformed")], "generated") == "generated"


def test_forwarded_for_survives_without_a_client():
    """The regression: behind a proxy leaving no client in scope, XFF was dropped."""
    assert _client_ip([(b"x-forwarded-for", b"203.0.113.9")], None) == "203.0.113.9"


def test_forwarded_for_takes_the_first_hop():
    headers = [(b"x-forwarded-for", b"203.0.113.9, 10.0.0.1, 10.0.0.2")]
    assert _client_ip(headers, ("10.0.0.9", 51234)) == "203.0.113.9"


def test_real_ip_is_the_second_choice():
    assert _client_ip([(b"x-real-ip", b"198.51.100.4")], ("10.0.0.9", 1)) == "198.51.100.4"


def test_peer_address_is_the_fallback():
    assert _client_ip([], ("10.0.0.9", 51234)) == "10.0.0.9"
    assert _client_ip([], None) == "unknown"
