"""Every statement ION sends TIDE must get past TIDE 6's keyword filter.

TIDE refuses a query when one of these words appears anywhere in it, comments
and quoted text included (sigeauk/TIDE 6.4.0, app/api/external_sharing.py).
A comment calling a filter "load-bearing" took the whole posture query down
against a live 6.4.0, so this reads every SQL string in the modules that
query TIDE and checks it the way TIDE does, after ION strips its comments.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from ion.services.tide_service import _strip_sql_comments

_TIDE_FORBIDDEN = re.compile(
    r"\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|REPLACE|TRUNCATE|ATTACH|DETACH|"
    r"COPY|EXPORT|IMPORT|INSTALL|LOAD|CALL|PRAGMA|GRANT|REVOKE|SET|"
    r"READ_CSV(?:_AUTO)?|READ_PARQUET|READ_JSON(?:_AUTO)?|READ_NDJSON(?:_AUTO)?|"
    r"READ_TEXT|READ_BLOB|READ_XLSX|GLOB|SNIFF_CSV|"
    r"SQLITE_SCAN|POSTGRES_SCAN|ICEBERG_SCAN|DELTA_SCAN)\b",
    re.IGNORECASE,
)

_SRC = Path(__file__).resolve().parents[2] / "src" / "ion"
_MODULES = ["services/tide_service.py", "services/d3fend_service.py", "services/vulnerability_service.py"]


def _statements():
    for rel in _MODULES:
        tree = ast.parse((_SRC / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = "".join(v.value if isinstance(v, ast.Constant) else "x" for v in node.values)
            else:
                continue
            if re.search(r"\bSELECT\b", text) and re.search(r"\bFROM\b", text):
                yield f"{rel}:{node.lineno}", text


STATEMENTS = list(_statements())


def test_the_scan_found_the_queries():
    assert len(STATEMENTS) > 40


@pytest.mark.parametrize("where,sql", STATEMENTS, ids=[w for w, _ in STATEMENTS])
def test_no_statement_trips_tides_keyword_filter(where, sql):
    hit = _TIDE_FORBIDDEN.search(_strip_sql_comments(sql))
    assert hit is None, f"{where}: TIDE refuses the word {hit.group(0)!r}"


@pytest.mark.parametrize("where,sql", STATEMENTS, ids=[w for w, _ in STATEMENTS])
def test_no_statement_reads_the_attack_catalogue_from_tide(where, sql):
    assert "mitre_techniques" not in sql, f"{where}: TIDE 6 refuses mitre_techniques"
