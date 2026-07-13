"""Thin, safe wrappers around the Elastic APM agent.

Every helper here is a **no-op** when the agent isn't running (APM disabled via
``ION_APM_ENABLED`` unset, or the library missing), so call sites never need
their own guards and carry ~zero cost when observability is off. The elastic-apm
module-level functions (``label``, ``set_user_context``, ``capture_span``)
already no-op without an active transaction; this module adds a background-loop
transaction wrapper and swallows any agent-side error so instrumentation can
never break business logic.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Optional

try:  # elastic-apm is a hard dep, but guard anyway (feature is opt-in)
    import elasticapm

    _APM = True
except Exception:  # pragma: no cover
    _APM = False


def _client():
    if not _APM:
        return None
    try:
        return elasticapm.get_client()
    except Exception:
        return None


@contextmanager
def capture_span(name: str, span_type: str = "custom", **labels):
    """Record a named child span for a first-party hot path (Bob, PCAP, …).

    No-op when APM is off or there is no active transaction.
    """
    if not _APM:
        yield
        return
    try:
        with elasticapm.capture_span(name, span_type=span_type, labels=labels or None):
            yield
    except Exception:
        # A broken span must never take down the wrapped operation.
        yield


@contextmanager
def background_transaction(name: str, txn_type: str = "scheduled"):
    """Wrap one background-loop *tick* as its own APM transaction.

    Background threads produce no HTTP transaction, so without this the loops are
    invisible to APM. Exceptions are captured as APM errors and re-raised so the
    loop's own error handling is unchanged. No-op when APM is off.
    """
    client = _client()
    if client is None:
        yield
        return
    try:
        client.begin_transaction(txn_type)
    except Exception:
        yield
        return
    outcome = "success"
    try:
        yield
    except Exception:
        outcome = "failure"
        try:
            client.capture_exception()
        except Exception:
            pass
        raise
    finally:
        try:
            elasticapm.set_transaction_name(name, override=False)
            client.end_transaction(name, outcome)
        except Exception:
            pass


def span(name: str, span_type: str = "custom"):
    """Decorator: record a sync function as a named span. No-op if APM off."""
    def deco(fn):
        if not _APM:
            return fn
        try:
            return elasticapm.capture_span(name, span_type=span_type)(fn)
        except Exception:
            return fn
    return deco


def async_span(name: str, span_type: str = "custom"):
    """Decorator: record an async function as a named span. No-op if APM off."""
    def deco(fn):
        if not _APM:
            return fn
        try:
            return elasticapm.async_capture_span(name, span_type=span_type)(fn)
        except Exception:
            return fn
    return deco


def set_user(username: Optional[str] = None, user_id=None, email: Optional[str] = None) -> None:
    """Attach the current analyst to the active transaction (filter APM by user)."""
    if not _APM:
        return
    try:
        elasticapm.set_user_context(username=username, user_id=user_id, email=email)
    except Exception:
        pass


def label(**kwargs) -> None:
    """Attach domain labels (rule_id, verdict, …) to the active transaction.

    None-valued labels are dropped. Safe no-op without an active transaction.
    """
    if not _APM:
        return
    try:
        clean = {k: v for k, v in kwargs.items() if v is not None}
        if clean:
            elasticapm.label(**clean)
    except Exception:
        pass
