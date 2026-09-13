# CSRF Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reject cross-site state-changing requests to ION with two independent checks: a session-derived CSRF token, and Origin validation.

**Architecture:** One middleware performs both checks on POST/PUT/PATCH/DELETE. The token is `HMAC(key=session_token, msg="ion-csrf-v1")`, so there is no new secret, no migration, and no per-request database lookup. The token is required only when the request carries a session cookie; Bearer-with-no-cookie is exempt because it is not CSRF-able. Origin validation applies regardless of auth method. The token reaches the browser as a `<meta>` tag and is attached by a small static script that patches `window.fetch` and hooks `htmx:configRequest`, covering all 616 existing call sites with no call-site edits.

**Tech Stack:** Python 3.12, FastAPI, Starlette `BaseHTTPMiddleware`, Jinja2, pytest, vanilla ES5-compatible JS (no build step).

**Spec:** `docs/superpowers/specs/2026-09-13-csrf-protection-design.md`

## Global Constraints

- Branch: `feat/csrf-protection`. Baseline v0.91.0 (`6c310c2`).
- Commit messages: no `Co-Authored-By` trailer. Match the repo's `type(scope): subject` convention.
- `src/ion/core/csrf.py` must import no FastAPI, no database, and no service module, so it stays unit-testable and cannot introduce an import cycle.
- The token exemption keys on **absence of the `ion_session` cookie**, never on presence of an `Authorization` header. This is the one mandatory invariant; Task 3 Step 1 tests it by name.
- Session cookie name is `ion_session`, defined as `SESSION_COOKIE_NAME` at `src/ion/auth/dependencies.py:18`. Import that constant, do not re-type the literal.
- Config default for `ION_CSRF_ENABLED` is **on**. This deliberately differs from `response_actions_enabled` and `bob_custom_templates`, which are off-by-default because they add capability rather than restrict it.
- Client JS must be ES5-compatible and CSP-safe: an external file under `static/js/`, loaded with `nonce="{{ csp_nonce }}"`, matching `theme-init.js` and `event-delegation.js`. No inline script body.
- Existing tests must still pass: `python -m pytest tests/ -q`.

## Deviations from the spec, and why

Three, all resolved during planning against the actual code. No approval needed, but they are recorded so a reviewer is not surprised.

1. **`expected_origins` takes primitives, not a `Request`.** The spec sketched `expected_origins(request)`. Taking `host`, `scheme`, `base_url`, `extra` keeps `core/csrf.py` free of FastAPI entirely and makes it trivially testable. The middleware assembles the arguments.
2. **The client script is an external static file, not an inline script.** The spec said "nonce'd inline script". `base.html` loads every other helper as an external nonce'd file. External is cacheable, matches convention, and keeps the CSP story simpler.
3. **The OIDC routes need no exemption entry.** The spec listed them. In fact `/api/auth/oidc/config` and `/api/auth/oidc/callback` are both GET (`src/ion/web/api.py:574,621`), so the unsafe-method gate already excludes them. Adding a dead exemption entry would be misleading.

---

### Task 1: Core primitives and config flags

**Files:**
- Create: `src/ion/core/csrf.py`
- Modify: `src/ion/core/config.py` (three sites: dataclass field, dict loader, env override)
- Test: `tests/test_csrf_primitives.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `derive_token(session_token: str) -> str`
  - `tokens_match(session_token: str, presented: str) -> bool`
  - `expected_origins(host: str, scheme: str, base_url: str, extra: Iterable[str] = ()) -> set[str]`
  - `origin_allowed(origin_header: str, referer_header: str, allowed: set[str]) -> bool`
  - Config attributes `csrf_enabled: bool` and `csrf_extra_origins: str`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_csrf_primitives.py`:

```python
"""Unit tests for the CSRF primitives — no app, no database, no I/O."""

import pytest

from ion.core.csrf import (
    derive_token,
    expected_origins,
    origin_allowed,
    tokens_match,
)


def test_derive_token_is_deterministic():
    assert derive_token("session-abc") == derive_token("session-abc")


def test_derive_token_differs_per_session():
    assert derive_token("session-abc") != derive_token("session-xyz")


def test_derive_token_is_not_the_session_token():
    assert derive_token("session-abc") != "session-abc"


def test_derive_token_empty_session_returns_empty():
    assert derive_token("") == ""


def test_tokens_match_accepts_the_derived_token():
    assert tokens_match("session-abc", derive_token("session-abc")) is True


def test_tokens_match_rejects_another_sessions_token():
    assert tokens_match("session-abc", derive_token("session-xyz")) is False


@pytest.mark.parametrize("presented", ["", "   ", "not-hex", "0" * 64])
def test_tokens_match_rejects_junk(presented):
    assert tokens_match("session-abc", presented) is False


def test_tokens_match_rejects_empty_session():
    assert tokens_match("", derive_token("session-abc")) is False


def test_expected_origins_includes_request_host():
    origins = expected_origins("ion.local:8000", "http", "https://ion.example", ())
    assert "http://ion.local:8000" in origins


def test_expected_origins_includes_configured_base_url():
    origins = expected_origins("ion.local", "http", "https://ion.example", ())
    assert "https://ion.example" in origins


def test_expected_origins_includes_extras_and_strips_paths():
    origins = expected_origins("ion.local", "http", "https://ion.example", ["https://alt.example/ignored"])
    assert "https://alt.example" in origins


def test_expected_origins_ignores_unparseable_values():
    origins = expected_origins("ion.local", "http", "not-a-url", ["also-not-a-url", ""])
    assert origins == {"http://ion.local"}


def test_origin_allowed_when_both_headers_absent():
    # curl / CI / integrations send neither. Rejecting would break automation
    # for no gain, since a hostile client can forge or omit the header anyway.
    assert origin_allowed("", "", {"https://ion.example"}) is True


def test_origin_allowed_when_origin_matches():
    assert origin_allowed("https://ion.example", "", {"https://ion.example"}) is True


def test_origin_rejected_when_origin_is_foreign():
    assert origin_allowed("https://evil.example", "", {"https://ion.example"}) is False


def test_origin_falls_back_to_referer_when_origin_absent():
    assert origin_allowed("", "https://ion.example/alerts", {"https://ion.example"}) is True


def test_origin_rejected_when_referer_is_foreign():
    assert origin_allowed("", "https://evil.example/x", {"https://ion.example"}) is False


def test_origin_rejected_when_literally_null():
    # A sandboxed iframe sends `Origin: null`. Present-but-unparseable must be
    # rejected, not treated as an absent header.
    assert origin_allowed("null", "", {"https://ion.example"}) is False


def test_origin_header_wins_over_referer():
    assert origin_allowed("https://evil.example", "https://ion.example/x", {"https://ion.example"}) is False
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_csrf_primitives.py -q`
Expected: FAIL, collection error `ModuleNotFoundError: No module named 'ion.core.csrf'`

- [ ] **Step 3: Write the implementation**

Create `src/ion/core/csrf.py`:

```python
"""CSRF token derivation and Origin validation primitives.

Deliberately dependency-light: no FastAPI, no database, no service imports. That
keeps the whole module unit-testable in isolation and means importing it from
middleware can never introduce a cycle.

The token is an HMAC keyed on the caller's own session token. That buys three
things a random token would not: no new secret to distribute to an air-gapped
deployment, no migration, and correctness across workers, since every worker
derives the same value from the same session. The token's lifetime is the
session's lifetime, which is the coupling we want — when the session dies the
token is meaningless.

Handing an HMAC of the session token to page JavaScript does not weaken the
session: the derivation is one-way, so an XSS that reads the CSRF token still
cannot reconstruct the session token it came from.
"""
from __future__ import annotations

import hmac
from hashlib import sha256
from typing import Iterable
from urllib.parse import urlsplit

# Versioned so the derivation can be changed later without silently accepting
# tokens minted under the old scheme.
_CSRF_MESSAGE = b"ion-csrf-v1"


def derive_token(session_token: str) -> str:
    """Return the CSRF token bound to ``session_token``.

    Empty in, empty out: an unauthenticated request has no token, and the
    middleware never challenges one.
    """
    if not session_token:
        return ""
    return hmac.new(session_token.encode("utf-8"), _CSRF_MESSAGE, sha256).hexdigest()


def tokens_match(session_token: str, presented: str) -> bool:
    """Constant-time check of ``presented`` against the token for this session."""
    if not session_token or not presented:
        return False
    return hmac.compare_digest(derive_token(session_token), presented)


def _origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` for ``url``, or "" when unparseable.

    "" is the signal for "this was not a usable origin", which callers treat as
    hostile when the header was present and as absent when it was not.
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def expected_origins(
    host: str,
    scheme: str,
    base_url: str,
    extra: Iterable[str] = (),
) -> set[str]:
    """Origins a state-changing request may legitimately claim to come from.

    ``host`` and ``scheme`` are the request's own. Comparing Origin against the
    request's own Host is sound against CSRF: the browser sets Origin to the
    attacking page's site while Host stays ION's, so the two cannot match. It is
    also what makes access by IP or localhost work on the range with no
    configuration at all.

    ``base_url`` is the configured deployment URL, kept as a backstop for
    proxied setups. ``extra`` covers a deployment fronted by another hostname.
    """
    origins: set[str] = set()
    if host and scheme:
        origins.add(f"{scheme}://{host}")
    configured = _origin_of(base_url)
    if configured:
        origins.add(configured)
    for candidate in extra:
        parsed = _origin_of(candidate)
        if parsed:
            origins.add(parsed)
    return origins


def origin_allowed(origin_header: str, referer_header: str, allowed: set[str]) -> bool:
    """True when the browser-supplied origin is absent, or is one of ``allowed``.

    Absent means a non-browser client — curl, CI, an integration. Those are
    allowed: an attacker controlling the client could omit or forge the header
    anyway, so rejecting would break automation for no security gain. This check
    earns its keep against browser-driven attacks specifically, where the browser
    sets Origin and the attacking page cannot suppress it.

    Present-but-unparseable (notably ``Origin: null`` from a sandboxed iframe) is
    rejected rather than treated as absent.
    """
    if origin_header:
        candidate = _origin_of(origin_header)
        return bool(candidate) and candidate in allowed
    if referer_header:
        candidate = _origin_of(referer_header)
        return bool(candidate) and candidate in allowed
    return True
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_csrf_primitives.py -q`
Expected: PASS, 19 passed

- [ ] **Step 5: Add the config flags**

In `src/ion/core/config.py`, add two fields immediately after the `bob_custom_templates` line (find it with `grep -n "bob_custom_templates: bool" src/ion/core/config.py`):

```python
    csrf_enabled: bool = True  # Enforce CSRF token + Origin checks on cookie-authenticated state-changing requests. ON by default: a security control that ships disabled is not a control. Escape hatch for debugging only
    csrf_extra_origins: str = ""  # Comma-separated additional origins accepted by the CSRF Origin check, for deployments fronted by another hostname. The request's own Host and base_url are always accepted
```

In the dict loader, immediately after the `bob_custom_templates=data.get(...)` line (find with `grep -n "bob_custom_templates=data.get" src/ion/core/config.py`):

```python
            csrf_enabled=data.get("csrf_enabled", True),
            csrf_extra_origins=data.get("csrf_extra_origins", ""),
```

In the env-override block, immediately after the `_config.bob_custom_templates = _get_env_bool(...)` line (find with `grep -n "_config.bob_custom_templates = " src/ion/core/config.py`):

```python
            _config.csrf_enabled = _get_env_bool("ION_CSRF_ENABLED", True)
            _env_csrf_origins = os.environ.get("ION_CSRF_EXTRA_ORIGINS", "").strip()
            if _env_csrf_origins:
                _config.csrf_extra_origins = _env_csrf_origins
```

Note the explicit `True` default passed to `_get_env_bool`, which defaults to `False`. Omitting it would silently disable CSRF whenever the env var is unset.

- [ ] **Step 6: Verify the config loads with the intended defaults**

Run:

```bash
python -c "from ion.core.config import get_config; c=get_config(); print('csrf_enabled=', c.csrf_enabled); print('extra=', repr(c.csrf_extra_origins))"
```

Expected: `csrf_enabled= True` and `extra= ''`

- [ ] **Step 7: Confirm nothing else broke**

Run: `python -m pytest tests/ -q -x`
Expected: PASS, same count as before this task plus 19

- [ ] **Step 8: Commit**

```bash
git add src/ion/core/csrf.py src/ion/core/config.py tests/test_csrf_primitives.py
git commit -m "feat(security): CSRF token derivation and Origin validation primitives

Session-derived HMAC token (no new secret, no migration, multi-worker safe)
plus Origin/Referer comparison helpers. Pure module: no FastAPI, no database,
no service imports, so it cannot introduce an import cycle.

Origin: null and other present-but-unparseable values are rejected rather
than treated as an absent header. Absent stays allowed so curl and CI work.

Adds ION_CSRF_ENABLED (default on) and ION_CSRF_EXTRA_ORIGINS."
```

---

### Task 2: Per-request token context and Jinja global

**Files:**
- Create: `src/ion/web/_csrf_token.py`
- Modify: `src/ion/web/templating.py`
- Modify: `src/ion/web/server.py` (the `templates.env.globals` block near `grep -n 'templates.env.globals\["csp_nonce"\]' src/ion/web/server.py`)
- Test: `tests/test_csrf_token_global.py`

**Interfaces:**
- Consumes: `derive_token` from Task 1.
- Produces:
  - `_csrf_token_var: ContextVar[str]` — set by the middleware in Task 3
  - `_CSRFTokenProxy` — registered as the `csrf_token` Jinja global
  - Templates can then use `{{ csrf_token }}` and `{% if csrf_token %}`

This mirrors `src/ion/web/_csp_nonce.py` exactly, which is the established pattern for getting a per-request value into templates without threading it through every route handler.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_csrf_token_global.py`:

```python
"""The csrf_token Jinja global resolves per-request and is falsy when absent."""

from ion.web._csrf_token import _CSRFTokenProxy, _csrf_token_var


def test_proxy_is_empty_outside_a_request():
    proxy = _CSRFTokenProxy()
    assert str(proxy) == ""


def test_proxy_is_falsy_when_empty():
    # base.html guards the meta tag with `{% if csrf_token %}`, so the proxy
    # must be falsy for anonymous pages rather than always-truthy like a bare
    # object would be.
    assert not _CSRFTokenProxy()


def test_proxy_resolves_the_current_value():
    token = _csrf_token_var.set("deadbeef")
    try:
        assert str(_CSRFTokenProxy()) == "deadbeef"
        assert bool(_CSRFTokenProxy()) is True
    finally:
        _csrf_token_var.reset(token)


def test_proxy_html_escapes_to_the_same_value():
    token = _csrf_token_var.set("deadbeef")
    try:
        assert _CSRFTokenProxy().__html__() == "deadbeef"
    finally:
        _csrf_token_var.reset(token)


def test_make_templates_registers_the_global():
    from ion.web.templating import make_templates

    templates = make_templates()
    assert "csrf_token" in templates.env.globals


def test_template_renders_the_current_token():
    from ion.web.templating import make_templates

    templates = make_templates()
    tpl = templates.env.from_string("{% if csrf_token %}{{ csrf_token }}{% else %}none{% endif %}")
    assert tpl.render() == "none"
    token = _csrf_token_var.set("abc123")
    try:
        assert tpl.render() == "abc123"
    finally:
        _csrf_token_var.reset(token)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_csrf_token_global.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'ion.web._csrf_token'`

- [ ] **Step 3: Write the module**

Create `src/ion/web/_csrf_token.py`:

```python
"""Per-request CSRF token shared across all Jinja2Templates instances.

Mirrors _csp_nonce.py. CSRFMiddleware sets the token in _csrf_token_var at the
start of every request; templates read it as the `csrf_token` global, so no
route handler has to thread it through.

The proxy is falsy when empty. base.html relies on that to skip the meta tag
entirely on anonymous pages — a bare object would always be truthy and would
emit an empty, pointless tag to logged-out visitors.
"""
from __future__ import annotations

import contextvars

_csrf_token_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "csrf_token", default=""
)


class _CSRFTokenProxy:
    """Resolves to the current request's CSRF token when Jinja2 interpolates it."""

    def __str__(self) -> str:
        return _csrf_token_var.get()

    def __html__(self) -> str:
        return _csrf_token_var.get()

    def __bool__(self) -> bool:
        return bool(_csrf_token_var.get())
```

- [ ] **Step 4: Register the global in the shared factory**

In `src/ion/web/templating.py`, add the import next to the existing `_csp_nonce` import:

```python
from ion.web._csrf_token import _CSRFTokenProxy
```

and register it immediately after the `csp_nonce` line inside `make_templates`:

```python
    templates.env.globals["csrf_token"] = _CSRFTokenProxy()
```

- [ ] **Step 5: Register the global in server.py**

`server.py` builds its own `Jinja2Templates` rather than calling `make_templates()`, so it needs the same line. Add the import alongside the existing `_CSPNonceProxy` import, then after the `templates.env.globals["csp_nonce"] = _CSPNonceProxy()` line add:

```python
# CSRF token as a global proxy, same mechanism as csp_nonce above. Templates
# read it as `{{ csrf_token }}`; it is falsy for anonymous requests so
# base.html can skip the meta tag entirely.
templates.env.globals["csrf_token"] = _CSRFTokenProxy()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_csrf_token_global.py -q`
Expected: PASS, 6 passed

- [ ] **Step 7: Commit**

```bash
git add src/ion/web/_csrf_token.py src/ion/web/templating.py src/ion/web/server.py tests/test_csrf_token_global.py
git commit -m "feat(security): per-request CSRF token context and Jinja global

Mirrors the _csp_nonce.py pattern so templates read {{ csrf_token }} without
any route handler threading it through. Registered in both make_templates()
and server.py's own env, since server.py does not use the shared factory.

The proxy is falsy when empty so base.html can skip the meta tag for
anonymous pages instead of emitting an empty one."
```

---

### Task 3: The middleware

**Files:**
- Create: `src/ion/web/csrf_middleware.py`
- Modify: `src/ion/web/server.py` (registration, next to `SecurityHeadersMiddleware`)
- Test: `tests/test_csrf_protection.py`

**Interfaces:**
- Consumes: `derive_token`, `tokens_match`, `expected_origins`, `origin_allowed` (Task 1); `_csrf_token_var` (Task 2); `SESSION_COOKIE_NAME` from `ion.auth.dependencies`.
- Produces: `CSRFMiddleware`, `is_exempt(path: str) -> bool`, `CSRF_HEADER = "X-CSRF-Token"`.

Tests build a minimal FastAPI app with only this middleware and a dummy route. That is deliberate: it tests the middleware rather than ION's whole app, needs no database, and runs in milliseconds. Path exemption is covered by direct unit tests on `is_exempt`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_csrf_protection.py`:

```python
"""CSRF middleware: token check, Origin check, and the exemption rules.

Exercised against a minimal app carrying only CSRFMiddleware, so these test the
control itself rather than ION's routing and database.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.core.csrf import derive_token
from ion.web.csrf_middleware import CSRF_HEADER, CSRFMiddleware, is_exempt

SESSION = "test-session-token"
OTHER_SESSION = "someone-elses-session"
HOST = "ion.test"
ORIGIN = f"http://{HOST}"


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/api/things")
    async def create_thing():
        return {"ok": True}

    @app.get("/api/things")
    async def list_things():
        return {"ok": True}

    @app.post("/api/auth/login")
    async def login():
        return {"ok": True}

    @app.post("/api/integrations/webhooks/receive/{token}")
    async def receive(token: str):
        return {"ok": True}

    return app


@pytest.fixture
def client():
    return TestClient(_app(), base_url=ORIGIN, raise_server_exceptions=False)


def _cookie(client):
    client.cookies.set("ion_session", SESSION)
    return client


# --- Token check -------------------------------------------------------------

def test_cookie_post_without_token_is_rejected(client):
    r = _cookie(client).post("/api/things")
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_cookie_post_with_valid_token_succeeds(client):
    r = _cookie(client).post("/api/things", headers={CSRF_HEADER: derive_token(SESSION)})
    assert r.status_code == 200


def test_cookie_post_with_another_sessions_token_is_rejected(client):
    r = _cookie(client).post("/api/things", headers={CSRF_HEADER: derive_token(OTHER_SESSION)})
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_bearer_header_does_not_exempt_cookie_request(client):
    """The bypass this whole control lives or dies on.

    Keyed on Bearer PRESENCE instead of cookie ABSENCE, an attacker appends a
    junk Authorization header, the middleware waves the request through, and the
    cookie still authenticates it because get_session_token() reads the cookie
    first. Must stay 403.
    """
    r = _cookie(client).post(
        "/api/things",
        headers={"Authorization": "Bearer junk"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_invalid"


def test_bearer_without_cookie_is_exempt(client):
    r = client.post("/api/things", headers={"Authorization": "Bearer real-api-token"})
    assert r.status_code == 200


def test_anonymous_post_without_cookie_is_not_challenged(client):
    r = client.post("/api/things")
    assert r.status_code == 200


# --- Method gate -------------------------------------------------------------

def test_get_is_never_challenged(client):
    assert _cookie(client).get("/api/things").status_code == 200


def test_options_is_never_challenged(client):
    assert _cookie(client).options("/api/things").status_code in (200, 405)


# --- Exemptions --------------------------------------------------------------

def test_login_is_exempt(client):
    assert _cookie(client).post("/api/auth/login").status_code == 200


def test_webhook_receive_is_exempt(client):
    assert _cookie(client).post("/api/integrations/webhooks/receive/abc123").status_code == 200


def test_is_exempt_matches_login_exactly():
    assert is_exempt("/api/auth/login") is True
    assert is_exempt("/api/auth/login/extra") is False


def test_is_exempt_matches_webhook_prefix():
    assert is_exempt("/api/integrations/webhooks/receive/tok") is True
    assert is_exempt("/api/integrations/webhooks") is False


def test_ordinary_paths_are_not_exempt():
    assert is_exempt("/api/things") is False
    assert is_exempt("/api/response/actions/1/approve") is False


# --- Origin check ------------------------------------------------------------

def test_foreign_origin_is_rejected(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_matching_origin_succeeds(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Origin": ORIGIN},
    )
    assert r.status_code == 200


def test_absent_origin_and_referer_is_allowed(client):
    """curl and CI send neither. Must keep working."""
    r = client.post("/api/things", headers={"Authorization": "Bearer t"})
    assert r.status_code == 200


def test_foreign_referer_is_rejected_when_origin_absent(client):
    r = _cookie(client).post(
        "/api/things",
        headers={CSRF_HEADER: derive_token(SESSION), "Referer": "https://evil.example/x"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_origin_is_checked_for_bearer_requests_too(client):
    """Origin validation is orthogonal to auth method, unlike the token."""
    r = client.post(
        "/api/things",
        headers={"Authorization": "Bearer t", "Origin": "https://evil.example"},
    )
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


def test_origin_is_checked_before_the_token(client):
    """A foreign origin is reported as such even with no token, so logs name the
    real reason rather than blaming a missing token."""
    r = _cookie(client).post("/api/things", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.json()["code"] == "origin_invalid"


# --- Kill switch -------------------------------------------------------------

def test_disabling_the_flag_turns_both_checks_off(client, monkeypatch):
    from ion.core import config as config_module

    cfg = config_module.get_config()
    monkeypatch.setattr(cfg, "csrf_enabled", False)
    r = _cookie(client).post("/api/things", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200


# --- Context var -------------------------------------------------------------

def test_token_is_published_to_the_context_var_for_templates(client):
    from ion.web._csrf_token import _csrf_token_var

    seen = {}

    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.get("/peek")
    async def peek():
        seen["token"] = _csrf_token_var.get()
        return {"ok": True}

    c = TestClient(app, base_url=ORIGIN)
    c.cookies.set("ion_session", SESSION)
    c.get("/peek")
    assert seen["token"] == derive_token(SESSION)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_csrf_protection.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'ion.web.csrf_middleware'`

- [ ] **Step 3: Write the middleware**

Create `src/ion/web/csrf_middleware.py`:

```python
"""CSRF enforcement: session-derived token plus Origin validation.

Two independent checks. The token proves the request came from a page ION
rendered. The Origin check proves it came from ION's site. Either alone stops a
classic CSRF, and neither depends on the other, so a defect in one does not
silently disarm the control.

The token is demanded only when the request carries a session COOKIE. A request
authenticating with `Authorization: Bearer` and no cookie is exempt, because CSRF
exploits credentials the browser attaches automatically and a Bearer token is not
one of those — an attacker who knows the token does not need the victim's browser
at all. Origin validation still applies to those requests.

THE INVARIANT: the exemption keys on cookie ABSENCE, never on Bearer PRESENCE.
Keyed the other way round, an attacker appends `Authorization: Bearer junk` to a
cookie-carrying request, this middleware waves it through, and the cookie still
authenticates it downstream because get_session_token() reads the cookie first.
That is a total bypass. Guarded by
test_csrf_protection.py::test_bearer_header_does_not_exempt_cookie_request.

Context: the session cookie is already HttpOnly + SameSite=strict, so current
browsers do not attach it cross-site at all. This middleware is defence in depth
against a future SameSite relaxation, same-site attacker positions, and older or
buggy clients.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from ion.auth.dependencies import SESSION_COOKIE_NAME
from ion.core.client_ip import get_client_ip
from ion.core.config import get_config
from ion.core.csrf import derive_token, expected_origins, origin_allowed, tokens_match
from ion.web._csrf_token import _csrf_token_var

logger = logging.getLogger(__name__)

CSRF_HEADER = "X-CSRF-Token"

# Only these can change state, so only these are challenged.
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Exact-match exemptions. Keep this list short; every entry needs a reason.
_EXEMPT_PATHS = frozenset({
    # No session exists yet to bind a token to. Already rate limited at 10/min.
    "/api/auth/login",
})

# Prefix exemptions, for routes carrying a variable path segment.
_EXEMPT_PREFIXES = (
    # Inbound from external systems, authenticated by the token in the path
    # (integration_api.py). No browser involved, so no CSRF surface.
    "/api/integrations/webhooks/receive/",
)

# The OIDC routes deliberately have no entry here: /api/auth/oidc/config and
# /api/auth/oidc/callback are both GET, so the method gate already excludes
# them. A dead exemption entry would only mislead the next reader.


def is_exempt(path: str) -> bool:
    """True when ``path`` is excused from the token check."""
    if path in _EXEMPT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _EXEMPT_PREFIXES)


def _request_scheme(request: Request) -> str:
    """Scheme as the client sees it, honouring the proxy header.

    Mirrors the X-Forwarded-Proto handling SecurityHeadersMiddleware already
    uses, so a TLS-terminating proxy does not make every Origin look foreign.
    """
    if request.headers.get("X-Forwarded-Proto") == "https":
        return "https"
    return request.url.scheme


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject cross-site state-changing requests; publish the token for templates."""

    async def dispatch(self, request: Request, call_next):
        session_token = request.cookies.get(SESSION_COOKIE_NAME) or ""

        # Publish on every request, including GETs, so the page being rendered
        # can put the token in its meta tag.
        ctx_token = _csrf_token_var.set(derive_token(session_token))
        try:
            rejection = self._check(request, session_token)
            if rejection is not None:
                return rejection
            return await call_next(request)
        finally:
            _csrf_token_var.reset(ctx_token)

    def _check(self, request: Request, session_token: str):
        """Return a 403 response when the request must be rejected, else None."""
        if request.method not in _UNSAFE_METHODS:
            return None

        config = get_config()
        if not config.csrf_enabled:
            return None

        path = request.url.path

        # Origin first, and before the exemption check, so a cross-site request
        # to an exempt route is still caught and the log names the real reason.
        allowed = expected_origins(
            host=request.headers.get("Host", ""),
            scheme=_request_scheme(request),
            base_url=getattr(config, "base_url", ""),
            extra=[o for o in getattr(config, "csrf_extra_origins", "").split(",") if o.strip()],
        )
        if not origin_allowed(
            request.headers.get("Origin", ""),
            request.headers.get("Referer", ""),
            allowed,
        ):
            return self._reject(request, "origin_invalid", "Cross-origin request rejected")

        if is_exempt(path):
            return None

        # The invariant. Absence of a cookie, never presence of a Bearer header.
        if not session_token:
            return None

        if not tokens_match(session_token, request.headers.get(CSRF_HEADER, "")):
            return self._reject(request, "csrf_invalid", "Missing or invalid CSRF token")

        return None

    def _reject(self, request: Request, code: str, detail: str) -> JSONResponse:
        logger.warning(
            "CSRF rejection (%s): %s %s from %s",
            code,
            request.method,
            request.url.path,
            get_client_ip(request),
        )
        return JSONResponse(status_code=403, content={"detail": detail, "code": code})
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_csrf_protection.py -q`
Expected: PASS, 22 passed

If `get_client_ip` has a different signature, check it with `grep -n "def get_client_ip" src/ion/core/client_ip.py` and adjust the call. Do not drop the client IP from the log line; a rejection nobody can attribute is close to useless.

- [ ] **Step 5: Register the middleware**

In `src/ion/web/server.py`, add the import near the other web-module imports:

```python
from ion.web.csrf_middleware import CSRFMiddleware
```

Then, immediately after the `app.add_middleware(SecurityHeadersMiddleware)` line, add:

```python
# CSRF: token + Origin checks on cookie-authenticated state-changing requests.
# Sits inside the rate limiter and the monitoring middleware in execution order,
# so rejections are still counted and logged by those.
app.add_middleware(CSRFMiddleware)
```

Starlette runs the last-added middleware outermost, so this position puts CSRF after `RequestLogging`, `RateLimitSecurity` and `SecurityMonitoring` and before the route. That is what we want: a rejected request is still logged and still counts against the rate limiter.

- [ ] **Step 6: Verify the app still boots and routes still work**

Run:

```bash
python -c "from ion.web.server import app; print('routes:', len(app.routes))"
```

Expected: a route count printed with no exception.

- [ ] **Step 7: Run the whole suite**

Run: `python -m pytest tests/ -q`
Expected: PASS. Any pre-existing test that POSTs with a session cookie and no CSRF token will now fail with 403. That is the control working. Fix such a test by adding `headers={"X-CSRF-Token": derive_token(<session>)}`, never by weakening the middleware.

- [ ] **Step 8: Commit**

```bash
git add src/ion/web/csrf_middleware.py src/ion/web/server.py tests/test_csrf_protection.py
git commit -m "feat(security): CSRF middleware — token + Origin validation

Global default-deny on POST/PUT/PATCH/DELETE for cookie-authenticated
requests. Origin validation runs first and applies regardless of auth method,
so it covers Bearer-authenticated browser requests the token check does not.

The token exemption keys on cookie absence, never on Bearer presence: the
other way round is a total bypass, since get_session_token() reads the cookie
first. Named regression test guards it.

Exemptions are login and inbound webhook receive. The OIDC routes need none —
both are GET, so the method gate already excludes them."
```

---

### Task 4: Client wiring

**Files:**
- Create: `src/ion/web/static/js/csrf.js`
- Modify: `src/ion/web/templates/base.html`
- Test: `tests/test_csrf_client_wiring.py`

**Interfaces:**
- Consumes: the `csrf_token` Jinja global (Task 2), the `X-CSRF-Token` header name and the `csrf_invalid` error code (Task 3).
- Produces: automatic `X-CSRF-Token` on same-origin unsafe `fetch` calls and HTMX requests, and a redirect to login when the server reports `csrf_invalid`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_csrf_client_wiring.py`:

```python
"""base.html carries the token and loads the attaching script."""

from pathlib import Path

BASE_HTML = Path("src/ion/web/templates/base.html")
CSRF_JS = Path("src/ion/web/static/js/csrf.js")


def test_csrf_script_file_exists():
    assert CSRF_JS.is_file()


def test_base_html_renders_the_meta_tag_guarded_by_the_token():
    html = BASE_HTML.read_text(encoding="utf-8")
    assert '{% if csrf_token %}' in html
    assert 'name="csrf-token"' in html
    assert '{{ csrf_token }}' in html


def test_base_html_loads_the_script_with_a_nonce():
    html = BASE_HTML.read_text(encoding="utf-8")
    assert '/static/js/csrf.js' in html
    for line in html.splitlines():
        if '/static/js/csrf.js' in line:
            assert 'nonce="{{ csp_nonce }}"' in line
            return
    raise AssertionError("csrf.js script tag not found")


def test_script_attaches_only_to_unsafe_same_origin_requests():
    js = CSRF_JS.read_text(encoding="utf-8")
    assert "X-CSRF-Token" in js
    assert "htmx:configRequest" in js
    # Cross-origin requests must be left alone so the token never leaks outbound.
    assert "sameOrigin" in js


def test_script_redirects_to_login_on_csrf_invalid():
    # Spec, Failure handling: a stale token means the session is gone, so the
    # only sane recovery is re-login. Matches app.js's existing redirect shape.
    js = CSRF_JS.read_text(encoding="utf-8")
    assert "csrf_invalid" in js
    assert "/login?redirect=" in js


def test_script_is_es5_safe():
    js = CSRF_JS.read_text(encoding="utf-8")
    for banned in ("=>", "const ", "let ", "`"):
        assert banned not in js, f"{banned!r} is not ES5-safe"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_csrf_client_wiring.py -q`
Expected: FAIL on `test_csrf_script_file_exists`

- [ ] **Step 3: Write the script**

Create `src/ion/web/static/js/csrf.js`:

```javascript
/* Attach the CSRF token to same-origin state-changing requests.
 *
 * ION has 616 fetch call sites across templates and static JS and no central
 * wrapper. Patching window.fetch here covers every one of them, and everything
 * written later, without touching a single call site. The htmx:configRequest
 * listener does the same for hx-post / hx-put attributes.
 *
 * Cross-origin requests are deliberately left untouched, so the token is never
 * sent to a third party.
 *
 * ES5 only: no arrow functions, no const/let, no template literals. Matches the
 * rest of static/js and avoids a build step.
 */
(function () {
    "use strict";

    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute("content") : "";
    if (!token) {
        return;  // Anonymous page: nothing to attach, nothing to protect.
    }

    var UNSAFE = /^(POST|PUT|PATCH|DELETE)$/i;
    var HEADER = "X-CSRF-Token";

    function sameOrigin(url) {
        try {
            return new URL(url, window.location.href).origin === window.location.origin;
        } catch (e) {
            return false;  // Unparseable: treat as foreign and send nothing.
        }
    }

    var nativeFetch = window.fetch;
    if (typeof nativeFetch === "function") {
        window.fetch = function (input, init) {
            var opts = init || {};
            var isRequest = (typeof Request !== "undefined") && (input instanceof Request);
            var url = isRequest ? input.url : String(input);
            var method = opts.method || (isRequest ? input.method : "GET");

            if (UNSAFE.test(method) && sameOrigin(url)) {
                var headers = new Headers(opts.headers || (isRequest ? input.headers : {}));
                if (!headers.has(HEADER)) {
                    headers.set(HEADER, token);
                }
                var merged = {};
                for (var key in opts) {
                    if (Object.prototype.hasOwnProperty.call(opts, key)) {
                        merged[key] = opts[key];
                    }
                }
                merged.headers = headers;
                opts = merged;
            }
            return nativeFetch.call(this, input, opts).then(function (response) {
                if (response.status === 403) {
                    // Clone before reading: the caller still needs the body.
                    response.clone().json().then(function (body) {
                        if (body && body.code === "csrf_invalid") {
                            // The token is derived from the session, so an
                            // invalid token means the session itself is gone.
                            // Nothing to refresh to — send them to re-login.
                            window.location.href = "/login?redirect=" +
                                encodeURIComponent(window.location.pathname);
                        }
                    })["catch"](function () {
                        // A 403 that is not ours (permission denied, or a
                        // non-JSON body). Leave it to the caller.
                    });
                }
                return response;
            });
        };
    }

    // Listen on document rather than document.body: this script may run from
    // <head>, before body exists. htmx events bubble to document.
    document.addEventListener("htmx:configRequest", function (evt) {
        if (evt.detail && UNSAFE.test(evt.detail.verb || "")) {
            evt.detail.headers[HEADER] = token;
        }
    });
})();
```

- [ ] **Step 4: Wire it into base.html**

Find the htmx script tag with `grep -n 'htmx.min.js' src/ion/web/templates/base.html`. Immediately after that line, add:

```html
    {# CSRF token for state-changing requests. Guarded so anonymous pages emit
       nothing. csrf.js reads this and attaches it to same-origin unsafe fetch
       and htmx requests — see src/ion/web/csrf_middleware.py for the server
       side. #}
    {% if csrf_token %}<meta name="csrf-token" content="{{ csrf_token }}">{% endif %}
    <script nonce="{{ csp_nonce }}" src="/static/js/csrf.js?v={{ ion_version }}"></script>
```

Placing it after `htmx.min.js` guarantees htmx exists before the listener registers, and before any page-level script that might fire a fetch.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_csrf_client_wiring.py -q`
Expected: PASS, 5 passed

- [ ] **Step 6: Confirm the rendered page actually carries the token**

Run:

```bash
python -m pytest tests/ -q
```

Expected: PASS across the suite.

- [ ] **Step 7: Commit**

```bash
git add src/ion/web/static/js/csrf.js src/ion/web/templates/base.html tests/test_csrf_client_wiring.py
git commit -m "feat(security): attach CSRF token to fetch and htmx requests

One meta tag and one ES5 static script cover all 616 existing fetch call
sites plus the 20 hx-post/hx-put attributes, with no call-site edits and
nothing for future code to remember.

Cross-origin requests are left untouched so the token never leaks outbound.
The listener binds to document, not document.body, since the script loads
from <head>.

A 403 carrying code=csrf_invalid redirects to login: the token is derived
from the session, so an invalid one means the session is gone and there is
nothing to refresh to. Other 403s are left to the caller."
```

---

### Task 5: Documentation and release notes

**Files:**
- Modify: `SECURITY_ASSESSMENT.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/SECURE_BY_DESIGN.md`

- [ ] **Step 1: Update the SECURITY_ASSESSMENT.md control table**

`SECURITY_ASSESSMENT.md:529` currently reads:

```
| CSRF | Protected — OIDC state parameter, SameSite cookies |
```

Replace that row with:

```
| CSRF | Protected — per-session HMAC token (`X-CSRF-Token`) + Origin/Referer validation on all cookie-authenticated POST/PUT/PATCH/DELETE, plus OIDC state parameter and `SameSite=strict` cookies. `ION_CSRF_ENABLED`, on by default. Bearer-without-cookie is exempt by design: not CSRF-able. See `src/ion/web/csrf_middleware.py` |
```

Confirm the line number first, since earlier tasks do not touch this file but the repo may have moved on:

```bash
grep -n "| CSRF |" SECURITY_ASSESSMENT.md
```

- [ ] **Step 2: Add the CHANGELOG entry**

Entries are `## vX.Y.Z — YYYY-MM-DD` followed by a bold one-line summary and a
bullet list. This is a security control rather than a feature, and it changes
behaviour for existing callers, so it warrants its own version bump. Follow the
repo's release process (`.claude/skills/release-bump/SKILL.md`) rather than
hand-editing the version metadata at the top of the file.

The entry must state:

- The new middleware, and that enforcement is on by default
- `ION_CSRF_ENABLED` (default on) and `ION_CSRF_EXTRA_ORIGINS` (default empty)
- The client script attaching the header automatically, so the UI needs no change
- **The breaking note:** any external caller that POSTs to ION with a browser
  session cookie must now send `X-CSRF-Token`. Callers using
  `Authorization: Bearer` with no cookie are unaffected.
- That `SameSite=strict` already blocked the primary vector, so this is defence
  in depth. Do not oversell it.

- [ ] **Step 3: Add CSRF to docs/SECURE_BY_DESIGN.md**

That document currently has no CSRF mention (`grep -i csrf docs/SECURE_BY_DESIGN.md`
returns nothing). Find the control or defence-in-depth section it does maintain:

```bash
grep -n "^## \|^### " docs/SECURE_BY_DESIGN.md | head -30
```

Add an entry in that section's established style, covering the two independent
checks, why Bearer is exempt, and the pointer to `src/ion/web/csrf_middleware.py`.
Keep it to a short paragraph; the spec is the long-form record.

- [ ] **Step 4: Commit**

```bash
git add SECURITY_ASSESSMENT.md CHANGELOG.md docs/SECURE_BY_DESIGN.md
git commit -m "docs(security): record CSRF token + Origin validation control

Updates the SECURITY_ASSESSMENT control table row, which credited only the
OIDC state parameter and SameSite cookies, and notes the breaking change for
external callers that POST with a browser cookie."
```

---

## Verification before calling this done

- [ ] `python -m pytest tests/ -q` passes in full
- [ ] `python -c "from ion.web.server import app; print(len(app.routes))"` runs clean
- [ ] `grep -n 'headers.get("Authorization"' src/ion/web/csrf_middleware.py` returns nothing — the invariant holds, and the middleware never *reads* that header. Prose mentions of `Authorization` in the module docstring are expected and fine; it is the read that would be the bug
- [ ] `test_bearer_header_does_not_exempt_cookie_request` is present and passing
- [ ] With the stack running, a logged-in page shows `<meta name="csrf-token">` in view-source and a state-changing action still works from the UI
- [ ] `ION_CSRF_ENABLED=false` restores the old behaviour, confirming the escape hatch
