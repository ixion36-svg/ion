"""ION's five middleware layers are pure ASGI, not BaseHTTPMiddleware.

BaseHTTPMiddleware builds a Request object and runs the rest of the app in a
separate task for every layer in the chain, and ION stacks five of them. An
interleaved A/B of the two implementations measured SecurityHeaders at 19.9% of
throughput as BaseHTTPMiddleware against 5.8% as pure ASGI.

The risk is silent behaviour drift, and it differs per layer:

- headers: one that stops being set, or starts being set twice because raw ASGI
  headers are a list rather than a mapping
- the CSP nonce ContextVar no longer reaching the templates, which would make
  every nonced <script> in the page unrunnable
- the request body, which SecurityMonitoring reads to scan for attack patterns.
  BaseHTTPMiddleware replayed it to the route handler implicitly; in pure ASGI
  that is done by hand, and getting it wrong means POST bodies arrive empty or
  the request hangs on a drained receive.

These tests pin observable behaviour rather than implementation, so the layers
can be rewritten again without rewriting the tests.
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


@pytest.mark.anyio
async def test_response_time_is_withheld_outside_dev(client):
    """Server-side timing is an enumeration oracle on the sign-in route: a real
    account runs bcrypt and an absent one returns early. Developers keep the
    header; a deployment does not."""
    r = await client.get("/login")
    assert r.headers.get("x-response-time") is None


def test_response_time_follows_the_dev_flag(monkeypatch):
    import ion.core.config as _config
    from ion.web.logging_middleware import RequestLoggingMiddleware as _M

    class _Cfg:
        def __init__(self, dev, debug):
            self.dev_mode, self.debug_mode = dev, debug

    for dev, debug, expected in ((False, False, False), (True, False, True), (False, True, True)):
        monkeypatch.setattr(_config, "get_config", lambda d=dev, g=debug: _Cfg(d, g))
        assert _M(app)._expose_timing is expected, (dev, debug)


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


# --------------------------------------------------------------------------
# SecurityMonitoring reads the request body to scan it for attack patterns.
# BaseHTTPMiddleware replayed the body to the route handler implicitly; in pure
# ASGI that has to be done by hand, and getting it wrong means every POST body
# arrives empty, or the request hangs forever waiting on a drained receive.
# --------------------------------------------------------------------------

def _echo_app():
    from fastapi import FastAPI, Request

    from ion.web.security_middleware import SecurityMonitoringMiddleware

    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request):
        raw = await request.body()
        return {"len": len(raw), "body": raw.decode("utf-8", "replace")}

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    app.add_middleware(SecurityMonitoringMiddleware)
    return app


@pytest.mark.anyio
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b'{"note":"benign"}', id="small-json"),
        pytest.param(b"", id="empty"),
        pytest.param(b"x" * 200_000, id="200KB-chunked"),
        pytest.param("café — naïve".encode(), id="utf8"),
        pytest.param(b"' OR 1=1 --", id="attack-pattern"),
    ],
)
async def test_request_body_reaches_the_handler_intact(payload):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_echo_app()), base_url="http://t"
    ) as c:
        r = await c.post("/echo", content=payload)
    assert r.status_code == 200
    assert r.json()["len"] == len(payload), "body was truncated or consumed"


@pytest.mark.anyio
async def test_a_get_is_not_delayed_by_body_buffering():
    """Only POST/PUT/PATCH buffer; a GET must pass receive straight through."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_echo_app()), base_url="http://t"
    ) as c:
        r = await c.get("/ping")
    assert r.status_code == 200


@pytest.mark.anyio
async def test_the_whole_stack_still_serves_a_post():
    """End to end through all five converted layers, not one in isolation."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as c:
        r = await c.post("/api/auth/login", json={"username": "nobody", "password": "wrong"})
    # 401 proves the JSON body was parsed by the handler, not swallowed.
    assert r.status_code == 401
    assert "detail" in r.json()


def test_no_middleware_is_left_on_basehttpmiddleware():
    from starlette.middleware.base import BaseHTTPMiddleware

    from ion.web.csrf_middleware import CSRFMiddleware
    from ion.web.security_middleware import (
        RateLimitSecurityMiddleware,
        SecurityMonitoringMiddleware,
    )

    for mw in (
        SecurityHeadersMiddleware,
        RequestLoggingMiddleware,
        CSRFMiddleware,
        SecurityMonitoringMiddleware,
        RateLimitSecurityMiddleware,
    ):
        assert not issubclass(mw, BaseHTTPMiddleware), f"{mw.__name__} regressed"
