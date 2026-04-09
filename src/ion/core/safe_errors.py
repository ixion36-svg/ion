"""Safe error message helpers.

Functions in this module sanitize exception details before they are returned to
HTTP clients so that file paths, line numbers, secrets, or stack frames never
leak through API responses (CodeQL `py/stack-trace-exposure`).

The full traceback is always sent to the application log, so debugging is
unaffected — only the *response body* is sanitized.

Usage:

    from ion.core.safe_errors import safe_error

    try:
        do_thing()
    except Exception as e:
        return {"success": False, "error": safe_error(e, "do_thing")}

The returned value is the exception class name (e.g. ``ConnectionError``,
``TimeoutError``, ``ValueError``). Callers can wrap it with their own context
string for UX, e.g. ``f"Connection failed: {safe_error(e)}"``.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("ion.safe_errors")


def safe_error(exc: BaseException, context: Optional[str] = None) -> str:
    """Log the full traceback and return a sanitized error label safe for clients.

    Args:
        exc: The exception that was caught.
        context: Optional human-readable context string used in the server log
            (never returned to the client).

    Returns:
        The exception's class name. Always safe to embed in API responses.
    """
    label = type(exc).__name__
    if context:
        logger.exception("safe_error: %s in %s", label, context)
    else:
        logger.exception("safe_error: %s", label)
    return label
