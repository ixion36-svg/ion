"""v0.49.3 audit-refined logging policy for elasticsearch_service:

- Handlers catching ONLY ElasticsearchError MAY log the exception value —
  it is ION's own domain exception whose message carries the sanitized ES
  'reason' (the operationally load-bearing detail: version conflict, mapping
  error, read-only block), and any embedded request URL is the redacted one
  (userinfo stripped at construction; auth goes via header).
- Handlers catching anything broader (bare Exception, httpx classes) must log
  only type(e).__name__ — raw transport exceptions are the CodeQL
  clear-text-logging surface the original fix targeted.
"""

from __future__ import annotations

import ast
import pathlib

_SRC = pathlib.Path("src/ion/services/elasticsearch_service.py")
_EXC_NAMES = {"e", "exc", "ex", "err", "error"}


def _handler_catches_only_domain(handler: ast.ExceptHandler) -> bool:
    t = handler.type
    if isinstance(t, ast.Name):
        return t.id == "ElasticsearchError"
    if isinstance(t, ast.Tuple):
        return all(isinstance(el, ast.Name) and el.id == "ElasticsearchError" for el in t.elts)
    return False


def _logged_exception_args(call: ast.Call):
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in _EXC_NAMES:
            yield arg
        if isinstance(arg, ast.JoinedStr):
            for v in arg.values:
                if (
                    isinstance(v, ast.FormattedValue)
                    and isinstance(v.value, ast.Name)
                    and v.value.id in _EXC_NAMES
                ):
                    yield v


def test_raw_exceptions_logged_only_in_domain_handlers():
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    offenders = []
    for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
        domain_only = _handler_catches_only_domain(handler)
        for node in ast.walk(handler):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"
            ):
                if not domain_only and any(True for _ in _logged_exception_args(node)):
                    offenders.append(node.lineno)
    assert not offenders, (
        f"raw exception logged in a broad handler at lines: {sorted(set(offenders))}"
    )


def test_domain_handlers_keep_diagnostic_detail():
    """The inverse guard: ElasticsearchError handlers at WARNING+ must log the
    exception VALUE, not just its type — on-call needs the ES reason."""
    src_text = _SRC.read_text(encoding="utf-8")
    tree = ast.parse(src_text)
    bare_type_only = []
    for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
        if not _handler_catches_only_domain(handler):
            continue
        for node in ast.walk(handler):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "logger"
                and node.func.attr in ("warning", "error")
            ):
                logs_value = any(True for _ in _logged_exception_args(node))
                logs_type_only = any(
                    isinstance(a, ast.Call)
                    and isinstance(a.func, ast.Name) and a.func.id == "type"
                    for a in node.args
                )
                if logs_type_only and not logs_value:
                    bare_type_only.append(node.lineno)
    # the process-event resolver (original CodeQL fix) is the one deliberate
    # type-only site — identified by its explicit in-code comment.
    src_lines = src_text.splitlines()
    unexpected = []
    for ln in bare_type_only:
        ctx = "\n".join(src_lines[max(0, ln - 10):ln])
        if "Log only the exception TYPE" not in ctx:
            unexpected.append(ln)
    assert not unexpected, (
        f"domain-exception warnings lost their diagnostic detail at: {unexpected}"
    )
