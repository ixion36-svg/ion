"""v0.49.3 code-review fix: no ES-service logger call may log a raw exception
object (its str() can embed internal ES URLs / index paths — CodeQL
clear-text-logging). Handlers log type(e).__name__; the surrounding log message
already carries the operational context (case/alert id, operation).
"""

from __future__ import annotations

import ast
import pathlib

_SRC = pathlib.Path("src/ion/services/elasticsearch_service.py")


def _logger_calls(tree):
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "logger"
        ):
            yield node


def test_no_logger_logs_raw_exception_object():
    tree = ast.parse(_SRC.read_text(encoding="utf-8"))
    offenders = []
    for call in _logger_calls(tree):
        for arg in call.args:
            # bare `e` / `exc` passed as a %-arg
            if isinstance(arg, ast.Name) and arg.id in {"e", "exc", "ex", "err", "error"}:
                offenders.append(call.lineno)
            # f-string interpolating the exception, e.g. f"...{e}"
            if isinstance(arg, ast.JoinedStr):
                for v in arg.values:
                    if (
                        isinstance(v, ast.FormattedValue)
                        and isinstance(v.value, ast.Name)
                        and v.value.id in {"e", "exc", "ex", "err", "error"}
                    ):
                        offenders.append(call.lineno)
    assert not offenders, f"raw exception logged at lines: {sorted(set(offenders))}"
