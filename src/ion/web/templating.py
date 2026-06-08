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
from ion.web._csp_nonce import _CSPNonceProxy

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_BYTECODE_CACHE_DIR = Path("/tmp/ion-jinja2-cache")


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
    templates.env.globals["csp_nonce"] = _CSPNonceProxy()
    return templates
