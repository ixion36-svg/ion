"""Shared factory for fully-configured Jinja2Templates instances.

Historically each router created its own bare ``Jinja2Templates`` and wired
only the ``csp_nonce`` global, so 11 of 12 envs lacked the bytecode cache, the
``auto_reload`` gating, and the ``ion_version`` global — meaning any template
rendered through them had no compiled-template cache and resolved
``{{ ion_version }}`` (used for static-asset cache-busting) to *undefined*.

``make_templates()`` applies the identical configuration server.py uses, from
one place. It imports only leaf modules (``_csp_nonce``, ``config``, the ``ion``
package metadata) and never a router, so it introduces no import cycle — which
is why the per-module copies existed in the first place.
"""
from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates
from jinja2 import FileSystemBytecodeCache

import ion
from ion.core.config import get_config
from ion.licensing.gating import de_module_available
from ion.web import nav
from ion.web._csp_nonce import _CSPNonceProxy
from ion.web._csrf_token import _CSRFTokenProxy

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_BYTECODE_CACHE_DIR = Path("/tmp/ion-jinja2-cache")


def _workforce_available() -> bool:
    return bool(getattr(get_config(), "workforce_enabled", False))


def _nav_visible(item: nav.Item) -> bool:
    """Whether a nav entry's licence gate is open, read per render."""
    if item.gate == "de":
        return de_module_available()
    if item.gate == "workforce":
        return _workforce_available()
    return True


def _ts_parts(value: object) -> dict | None:
    """Split a timestamp into the instant, a fallback string, and whether it
    can honestly be localised.

    The `ts` macro in templates/_fragments/_time.html is the only caller.

    A timezone-aware value carries its offset, so a browser can put it on
    the viewer's clock and the fallback can name UTC. A naive value cannot:
    ION stores audit and event timestamps in a naive `DateTime` column
    defaulting to the database's `func.now()`, which is UTC on SQLite and
    the session timezone on Postgres, and nothing in the row records which.

    So a naive value is not localised. Emitting it without an offset and
    localising anyway would be worse than leaving it alone, because
    JavaScript parses a zoneless ISO date-time as LOCAL time, so the
    browser would read the digits as the viewer's clock, convert from a
    zone the value was never in, and display a time that is wrong by the
    viewer's offset while looking authoritative.

    The JavaScript this replaces had exactly that shape: it passed the
    naive string to `new Date()` and called `toLocaleString()`, which
    parsed as local and formatted as local, so it showed the stored digits
    unchanged and unlabelled. Showing the same digits with a note saying
    whose clock they are on is strictly more information, and is why this
    returns `localise` rather than guessing a zone.

    An unknown zone is not UTC, the same way unmeasured is not zero.
    """
    import re
    from datetime import datetime, timezone

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        if value.tzinfo is not None:
            as_utc = value.astimezone(timezone.utc)
            return {
                "iso": value.isoformat(),
                "shown": as_utc.strftime("%Y-%m-%d %H:%M UTC"),
                "localise": True,
                "note": "",
            }
        return {
            "iso": value.isoformat(),
            "shown": value.strftime("%Y-%m-%d %H:%M"),
            "localise": False,
            "note": "Server time. This record stores no timezone.",
        }

    text = str(value)
    # Z, +00:00, +0000. A date-only string has no time to place in a zone.
    if re.search(r"(Z|[+-]\d{2}:?\d{2})$", text):
        return {"iso": text, "shown": text, "localise": True, "note": ""}
    return {
        "iso": text,
        "shown": text,
        "localise": False,
        "note": "Server time. This record stores no timezone.",
    }


def _safe_url(value: object, fallback: str = "") -> str:
    """A stored URL, or the fallback if its scheme is not one a link may use.

    Jinja escapes characters, not schemes. `href="{{ row.url }}"` with
    `javascript:alert(1)` in that column renders a link that executes on
    click, and the hand-rolled `esc()` helpers the fragments replaced had
    exactly the same hole, so it is not a regression but it is still a hole.
    Two fragments render a GitLab issue URL straight out of the database.

    Allowed: http, https, mailto, and a site-relative path. Everything else
    returns the fallback, so the template renders plain text rather than a
    link that does something other than navigate.

    ASCII whitespace and control characters are stripped before the scheme
    is read, because a browser strips them too: `java	script:alert(1)` and a
    leading newline both navigate, so a naive `startswith` check passes
    something the browser then executes.
    """
    if not value:
        return fallback

    text = str(value)
    # The same characters a browser ignores when parsing the scheme.
    stripped = "".join(c for c in text if ord(c) > 0x20)
    lowered = stripped.lower()

    if lowered.startswith(("http://", "https://", "mailto:")):
        return text
    # Protocol-relative. A valid URL, but it changes origin, which a stored
    # link has no business doing. Rejected before the bare-path check below,
    # which otherwise accepts it: "//evil.example/x".split("/")[0] is the
    # empty string, which contains no colon and looks like a relative path.
    if stripped.startswith("//"):
        return fallback
    # A site-relative path.
    if stripped.startswith("/"):
        return text
    # No scheme and no leading slash: a bare path such as "docs/x". Safe,
    # and rejecting it would break ordinary relative links.
    if ":" not in lowered.split("/")[0]:
        return text
    return fallback


def make_templates(directory: Path | None = None) -> Jinja2Templates:
    """Return a Jinja2Templates env configured identically across the app.

    Applies: shared filesystem bytecode cache, ``auto_reload`` only in debug,
    the ``ion_version`` global (static-asset cache-busting), and the per-request
    ``csp_nonce`` proxy.
    """
    templates = Jinja2Templates(directory=directory or _TEMPLATES_DIR)
    try:
        _BYTECODE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        templates.env.bytecode_cache = FileSystemBytecodeCache(str(_BYTECODE_CACHE_DIR))
    except OSError:
        # The bytecode cache is a pure optimisation — never fail template
        # setup if the cache dir can't be created (e.g. read-only /tmp).
        pass
    templates.env.auto_reload = bool(getattr(get_config(), "debug_mode", False))
    templates.env.globals["ion_version"] = ion.__version__
    # base.html renders the whole navigation from this registry: the desktop
    # dropdowns, the mobile panel and the `g` key table. Every env needs these
    # or any page extending base.html raises UndefinedError. The helpers are
    # callables, not values, so a licence change is read per render without a
    # template reload.
    templates.env.globals["ts_parts"] = _ts_parts
    templates.env.filters["safe_url"] = _safe_url
    templates.env.globals["nav_items"] = nav.NAV
    templates.env.globals["nav_mobile_items"] = nav.mobile_items
    templates.env.globals["nav_shortcuts"] = nav.shortcuts
    templates.env.globals["nav_visible"] = _nav_visible
    templates.env.globals["csp_nonce"] = _CSPNonceProxy()
    templates.env.globals["csrf_token"] = _CSRFTokenProxy()
    return templates
