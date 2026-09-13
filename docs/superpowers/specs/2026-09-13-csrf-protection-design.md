# CSRF Protection Design

Date: 2026-09-13
Status: approved, pending implementation
Baseline: v0.91.0 (`6c310c2`)

## Problem

ION has no CSRF token middleware. The only CSRF handling in the codebase is the
OIDC `state` parameter on the auth callback. There is no synchronizer or
double-submit token on any state-changing route, and no Origin or Referer
validation anywhere in `src/`.

`get_session_token` (`src/ion/auth/dependencies.py:38`) resolves the session from
the `ion_session` cookie *before* falling back to the `Authorization: Bearer`
header. Every state-changing route is therefore reachable with an ambient
browser cookie: 273 POST, 57 DELETE, 48 PUT, 22 PATCH.

The exposure grew in v0.91. `response_api.py` now ships request/approve/reject
routes for SOAR response actions, and `verdict_review_api.py` ships verdict
acceptance. Those are exactly the actions an attacker would want to trigger on a
logged-in analyst. Both are feature-gated off by default today.

## Threat model, honestly stated

The session cookie is already `HttpOnly` and `SameSite=strict`
(`src/ion/web/api.py:298`). In any current browser a cross-site POST does not
carry it, so the headline "analyst tricked from another site" scenario is
largely blocked before this work starts.

ION also registers no `CORSMiddleware` and sends no CORS headers, so a
cross-origin page cannot set an `Authorization` header at all: the preflight
never succeeds.

This work is therefore defence in depth, not a hole being plugged. It defends
against:

- A future change that relaxes `SameSite` for an OAuth or embedding reason
- Same-site attacker positions, such as a compromised sibling host
- Browser bugs and older clients that mishandle `SameSite`
- A regression that reorders or removes the existing cookie flags

For a security product these are worth covering. The urgency is lower than the
raw finding suggests, and this spec says so rather than overselling it.

## Design

Two independent checks in one middleware. The token proves the request came from
an ION page. The Origin check proves it came from the ION site. Neither depends
on the other, and either alone stops a classic CSRF.

### Check 1: session-derived HMAC token

Token is `HMAC(key=session_token, msg="ion-csrf-v1")`, hex-encoded, compared in
constant time with `hmac.compare_digest`.

Chosen because it needs no new secret in config, no database migration, and no
per-request session lookup, and it is correct across multiple workers because
every worker derives the same value from the same session token. The token's
lifetime is the session's lifetime, which is the correct coupling: when the
session dies the token is meaningless.

The session cookie is `HttpOnly`, so client JavaScript cannot derive the token
itself. The server renders it into the page instead (see Client below).

Exposing an HMAC of the session token to JavaScript does not weaken the session:
the derivation is one-way, so an XSS that reads the CSRF token still cannot
reconstruct the session token.

### Check 2: Origin validation

Reject a state-changing request whose `Origin` header is present and does not
match the expected host. Fall back to the `Referer` origin when `Origin` is
absent but `Referer` is present.

When neither header is present, allow. Non-browser clients such as curl, CI, and
integrations send neither, and treating absent as hostile would break them for
no security gain, since an attacker who controls the client can omit or forge
the header anyway. The value here is specifically against browser-driven
attacks, where the browser sets `Origin` and the attacker cannot suppress it.

This check is orthogonal to authentication method, so unlike the token it also
covers Bearer-authenticated browser requests.

### Trigger condition

The token is required only when the request authenticated **via cookie**,
determined by the presence of the `ion_session` cookie.

A request carrying `Authorization: Bearer` and no cookie is exempt from the
token check. This is safe rather than a concession: CSRF exploits ambient
credentials that the browser attaches automatically, and a Bearer token is not
ambient. An attacker who knows the token does not need the victim's browser.

The Origin check still applies to those requests.

### The bypass trap

The token exemption MUST key on **absence of the `ion_session` cookie**, never on
**presence of an `Authorization` header**.

Keyed the wrong way round, an attacker appends `Authorization: Bearer junk` to a
cookie-carrying request. The middleware sees Bearer and exempts it. The cookie
still authenticates it, because `get_session_token` checks the cookie first. That
is a complete bypass of the control.

This is called out here because it is the single most likely implementation
error, and it has a named regression test (T4 below).

## Components

### Server

`src/ion/core/csrf.py` (new)

- `derive_token(session_token: str) -> str`
- `tokens_match(session_token: str, presented: str) -> bool`, constant time
- `expected_origins(request) -> set[str]`
- No FastAPI imports beyond the `Request` type, so it stays unit-testable

`expected_origins` returns, in order of contribution:

1. The request's own origin: `Host` header combined with the scheme, honouring
   `X-Forwarded-Proto` exactly as `server.py:232` already does. Comparing Origin
   against the request's own host is sound against CSRF, because the browser
   sets `Origin` to the attacker's site while `Host` remains ION's, so the two
   cannot match. This is what makes access by IP or `localhost` work in dev and
   on the range without any configuration.
2. The origin parsed from `config.base_url` (default
   `https://ion.guardedglass.internal`), always accepted as a backstop.
3. `ION_CSRF_EXTRA_ORIGINS`, a new optional comma-separated config, default
   empty, for deployments fronted by an additional hostname.

`src/ion/web/csrf_middleware.py` (new)

Placed as a flat module to match `src/ion/web/`, which holds 88 flat modules and
no `middleware/` package. The existing middleware classes are defined inline in
`server.py`, but that file is already 2419 lines, so a new class goes in its own
module and is imported for registration.

- `CSRFMiddleware`, engaging only on POST, PUT, PATCH, DELETE
- Reads `X-CSRF-Token`
- Returns 403 with body `{"detail": "...", "code": "csrf_invalid"}` on token
  failure and `code: "origin_invalid"` on Origin failure, so the two are
  distinguishable in logs and in the frontend
- Logs rejections at warning level with path and client IP via the existing
  `get_client_ip` helper, so failures are visible rather than silent

`src/ion/web/server.py`

- Register the middleware next to `SecurityHeadersMiddleware` and
  `SecurityMonitoringMiddleware`

### Client

`src/ion/web/templates/base.html`

- Render `<meta name="csrf-token" content="{{ csrf_token }}">` on authenticated
  pages only
- Add a nonce'd inline script, consistent with the existing CSP nonce pattern,
  that:
  - Patches `window.fetch` to attach `X-CSRF-Token` to same-origin requests
    using an unsafe method. Cross-origin requests are left untouched so the
    token is never sent to a third party.
  - Registers an `htmx:configRequest` listener that sets the same header

This covers all 616 existing call sites (559 inline in templates, 57 in
`static/js/`) and the 20 `hx-post` / `hx-put` attributes with no call-site edits,
and covers anything written later by default.

The context processor that supplies `csrf_token` to templates must derive it from
the current session and render nothing when unauthenticated.

## Exemptions

| Route | Reason |
|---|---|
| `POST /api/auth/login` | No session exists yet to bind a token to. Already rate limited at 10/min. |
| OIDC login and callback routes | GET, and already protected by the `state` parameter. |
| `POST /webhooks/receive/{token}` | Inbound from external systems (`integration_api.py:458`), authenticated by the path token. No browser involved. |
| Any request with no `ion_session` cookie | Not CSRF-able. See trigger condition above. |

Exemptions are matched on exact path or documented prefix, held in one list in
the middleware module, with a comment on each entry explaining why. The list is
deliberately short and additions should be justified in review.

## Failure handling

A token mismatch means the session changed or expired, because the token is
derived from the session. There is nothing valid to refresh to, so there is no
retry dance. The frontend treats a 403 carrying `code: "csrf_invalid"` as a
session loss and redirects to login.

## Config

`ION_CSRF_ENABLED`, default **on**.

It exists as a debugging escape hatch, not a rollout gate. A security control
that ships disabled is not a control. This differs deliberately from the
`ION_RESPONSE_ACTIONS_ENABLED` and `bob_custom_templates` pattern, where
off-by-default is correct because those add capability rather than restrict it.

## Testing

New `tests/test_csrf_protection.py`:

- T1: cookie-authenticated POST with no token returns 403 `csrf_invalid`
- T2: cookie-authenticated POST with a valid token succeeds
- T3: cookie-authenticated POST carrying a *different* session's token returns 403
- T4: **bypass regression.** Cookie-authenticated POST with
  `Authorization: Bearer junk` and no CSRF token returns 403, proving the
  exemption keys on cookie absence rather than header presence
- T5: Bearer-authenticated POST with no cookie and no token succeeds
- T6: GET, HEAD, OPTIONS are never challenged
- T7: each exempt route is reachable without a token
- T8: POST with a foreign `Origin` returns 403 `origin_invalid`
- T9: POST with no `Origin` and no `Referer` is allowed, so CI and curl work
- T10: POST whose `Origin` matches the request `Host` succeeds
- T11: POST whose `Origin` matches `config.base_url` but not `Host` succeeds,
  covering the backstop
- T12: `Referer` is used when `Origin` is absent, and a foreign `Referer` is
  rejected
- T13: `ION_CSRF_ENABLED=false` disables both checks

Unit tests for `derive_token` and `tokens_match` cover determinism, difference
across sessions, and rejection of empty or malformed input.

## Out of scope

- Rotating the CSRF token independently of the session. The derivation makes this
  impossible by construction; it would need the synchronizer-token design and a
  migration, and there is no threat here that it addresses.
- Adding `CORSMiddleware`. ION currently sends no CORS headers, which is the
  safer default. Introducing CORS in order to then constrain it would add risk.
- Token theft, replay, and XSS exfiltration of Bearer tokens. Real concerns,
  different problem, different mitigations (short TTL, scoping, audit).
- Changing the cookie-before-header precedence in `get_session_token`. Worth
  revisiting separately, but changing auth resolution while adding a security
  control couples two risky changes.

## Files touched

New:

- `src/ion/core/csrf.py`
- `src/ion/web/csrf_middleware.py`
- `tests/test_csrf_protection.py`

Modified:

- `src/ion/web/server.py` (register middleware, context processor)
- `src/ion/web/templates/base.html` (meta tag, fetch patch, htmx hook)
- `src/ion/core/config.py` (`ION_CSRF_ENABLED`, `ION_CSRF_EXTRA_ORIGINS`)
