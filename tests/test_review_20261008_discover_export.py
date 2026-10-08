"""Discover CSV export (review 2026-10-08, §9).

The Export CSV button called a function whose whole body was::

    showToast('Export functionality coming soon', 'info');

The review's instruction was to finish the control or remove it. It is
now finished, and the export carries the query provenance the review
asked for: the query, the index scope, the time window, the execution
time, the returned count and whether the result set was truncated. A
spreadsheet of hits with none of that behind it is not evidence of
anything.

There is no JS test harness in this repository, so these tests extract
the page's script block, strip the Jinja expressions and exercise the
real export functions under node with a stubbed DOM. They skip when node
is unavailable rather than silently passing.
"""

from __future__ import annotations

import csv
import io
import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_TEMPLATE = (
    Path(__file__).resolve().parent.parent
    / "src" / "ion" / "web" / "templates" / "discover.html"
)

_NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(_NODE is None, reason="node is not installed")


def _script_body() -> str:
    src = _TEMPLATE.read_text(encoding="utf-8")
    match = re.search(r"<script[^>]*>(.*?)</script>", src, re.S)
    assert match, "discover.html has no <script> block"
    body = match.group(1)
    # The page is a Jinja template; node only needs valid JS.
    body = re.sub(r"\{\{.*?\}\}", '"JINJA"', body, flags=re.S)
    body = re.sub(r"\{%.*?%\}", "", body, flags=re.S)
    return body


def _run_export(tmp_path: Path, search_state: dict) -> dict:
    """Load the page's JS under node and export `search_state`.

    Returns ``{"csv": <text>, "toasts": [...], "download": <filename>}``.
    """
    harness = textwrap.dedent(
        """
        // ---- minimal DOM / browser stubs -------------------------------
        const _toasts = [];
        let _captured = null;
        let _download = null;

        globalThis.Blob = class { constructor(parts) { _captured = parts.join(''); } };
        globalThis.URL = {
            createObjectURL: () => 'blob:stub',
            revokeObjectURL: () => {},
        };
        globalThis.document = {
            getElementById: () => ({ value: '', checked: false }),
            createElement: () => ({
                set download(v) { _download = v; },
                get download() { return _download; },
                href: '', click() {},
            }),
            body: { appendChild() {}, removeChild() {} },
            addEventListener() {},
            querySelectorAll: () => [],
        };
        globalThis.window = { location: { search: '' }, addEventListener() {} };
        globalThis.URLSearchParams = class { get() { return null; } };
        globalThis.fetch = () => Promise.reject(new Error('no network in test'));

        // ---- the page's own code ---------------------------------------
        __PAGE_JS__

        // Replace the page's own showToast only AFTER loading it: its
        // function declaration would otherwise shadow the stub, and the
        // real one wants a live DOM container.
        showToast = (msg, kind) => _toasts.push({msg, kind});

        // ---- drive the export ------------------------------------------
        _lastDiscoverSearch = __STATE__;
        exportSearchResults();

        process.stdout.write(JSON.stringify({
            csv: _captured,
            toasts: _toasts,
            download: _download,
        }));
        """
    )
    script = harness.replace("__PAGE_JS__", _script_body()).replace(
        "__STATE__", json.dumps(search_state)
    )
    path = tmp_path / "harness.js"
    path.write_text(script, encoding="utf-8")

    # encoding is explicit: text=True would decode node's stdout with the
    # Windows locale codepage, turning the CSV's UTF-8 BOM into mojibake.
    proc = subprocess.run(
        [_NODE, str(path)],
        capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert proc.returncode == 0, f"node failed:\n{proc.stderr}"
    return json.loads(proc.stdout)


def _state(**over) -> dict:
    base = {
        "executed_at": "2026-10-08T01:30:00.000Z",
        "index_pattern": "logs-*",
        "query": 'event.action: "user-login"',
        "time_field": "@timestamp",
        "time_from": "now-24h",
        "time_to": "now",
        "requested_size": 500,
        "total_hits": 2,
        "returned_hits": 2,
        "took_ms": 42,
        "hits": [
            {"@timestamp": "2026-10-08T01:00:00Z", "host.name": "PT-LAB-04",
             "message": "login ok", "user.name": "jbloggs"},
            {"@timestamp": "2026-10-08T01:05:00Z", "host.name": "PT-LAB-05",
             "message": 'said "hello", then left', "user.name": "asmith"},
        ],
    }
    base.update(over)
    return base


def _data_rows(csv_text: str) -> list[dict]:
    """Parse the export, skipping the commented provenance header."""
    body = "\n".join(
        line for line in csv_text.lstrip("﻿").splitlines()
        if line and not line.startswith("#")
    )
    return list(csv.DictReader(io.StringIO(body)))


def _header(csv_text: str) -> dict:
    """Parse the ``# key,"value"`` provenance block.

    The value is read with the csv module rather than stripped of quotes
    by hand, so a value that itself contains quotes round-trips.
    """
    out = {}
    for line in csv_text.lstrip("﻿").splitlines():
        if not line.startswith("# "):
            continue
        key, sep, raw = line[2:].partition(",")
        if not sep:
            continue
        out[key] = next(csv.reader(io.StringIO(raw)))[0]
    return out


# ── The stub is gone ──────────────────────────────────────────────────────


def test_the_coming_soon_stub_is_gone():
    assert "Export functionality coming soon" not in _TEMPLATE.read_text(
        encoding="utf-8"
    )


# ── The rows ──────────────────────────────────────────────────────────────


class TestExportedRows:
    def test_every_hit_is_exported(self, tmp_path):
        out = _run_export(tmp_path, _state())
        assert len(_data_rows(out["csv"])) == 2

    def test_all_fields_are_exported_not_just_displayed_columns(self, tmp_path):
        out = _run_export(tmp_path, _state())
        rows = _data_rows(out["csv"])
        assert set(rows[0]) == {"@timestamp", "host.name", "message", "user.name"}

    def test_embedded_quotes_survive_a_round_trip(self, tmp_path):
        out = _run_export(tmp_path, _state())
        rows = _data_rows(out["csv"])
        assert rows[1]["message"] == 'said "hello", then left'

    def test_missing_fields_become_empty_not_undefined(self, tmp_path):
        state = _state(hits=[
            {"@timestamp": "2026-10-08T01:00:00Z", "host.name": "A"},
            {"@timestamp": "2026-10-08T01:01:00Z"},
        ], total_hits=2, returned_hits=2)
        rows = _data_rows(_run_export(tmp_path, state)["csv"])
        assert rows[1]["host.name"] == ""

    def test_nested_objects_are_serialised_as_json(self, tmp_path):
        state = _state(hits=[{"a": {"nested": 1}}], total_hits=1, returned_hits=1)
        rows = _data_rows(_run_export(tmp_path, state)["csv"])
        assert json.loads(rows[0]["a"]) == {"nested": 1}

    def test_a_formula_like_value_is_neutralised(self, tmp_path):
        """Log text is untrusted; a spreadsheet must not execute it."""
        state = _state(
            hits=[{"message": '=cmd|\' /c calc\'!A0'}],
            total_hits=1, returned_hits=1,
        )
        rows = _data_rows(_run_export(tmp_path, state)["csv"])
        assert rows[0]["message"].startswith("'="), rows[0]["message"]


# ── The provenance the review asked for ───────────────────────────────────


class TestQueryProvenance:
    def test_header_records_the_query_and_scope(self, tmp_path):
        header = _header(_run_export(tmp_path, _state())["csv"])
        assert header["query"] == 'event.action: "user-login"'
        assert header["index_pattern"] == "logs-*"

    def test_header_records_the_time_window(self, tmp_path):
        header = _header(_run_export(tmp_path, _state())["csv"])
        assert header["time_field"] == "@timestamp"
        assert header["time_from"] == "now-24h"
        assert header["time_to"] == "now"

    def test_header_records_execution_time_and_counts(self, tmp_path):
        header = _header(_run_export(tmp_path, _state())["csv"])
        assert header["took_ms"] == "42"
        assert header["total_hits"] == "2"
        assert header["returned_hits"] == "2"

    def test_header_records_when_the_search_ran_and_when_it_was_exported(self, tmp_path):
        header = _header(_run_export(tmp_path, _state())["csv"])
        assert header["executed_at"] == "2026-10-08T01:30:00.000Z"
        assert header["exported_at"]

    def test_an_empty_query_is_recorded_as_match_all(self, tmp_path):
        header = _header(_run_export(tmp_path, _state(query=""))["csv"])
        assert header["query"] == "(match all)"


class TestTruncationIsDeclared:
    def test_a_complete_result_set_says_not_truncated(self, tmp_path):
        header = _header(_run_export(tmp_path, _state())["csv"])
        assert header["truncated"] == "no"

    def test_a_truncated_result_set_says_so(self, tmp_path):
        out = _run_export(tmp_path, _state(total_hits=98_000, returned_hits=2))
        header = _header(out["csv"])
        assert header["truncated"] == "yes"
        assert "98000" in header["note"]

    def test_the_toast_mentions_truncation(self, tmp_path):
        out = _run_export(tmp_path, _state(total_hits=98_000, returned_hits=2))
        assert any("truncated" in t["msg"] for t in out["toasts"])


class TestExportHousekeeping:
    def test_nothing_to_export_is_a_message_not_a_file(self, tmp_path):
        out = _run_export(tmp_path, _state(hits=[], returned_hits=0, total_hits=0))
        assert out["csv"] is None
        assert any("Run a search first" in t["msg"] for t in out["toasts"])

    def test_the_filename_is_timestamped(self, tmp_path):
        out = _run_export(tmp_path, _state())
        assert out["download"].startswith("ion-discover-")
        assert out["download"].endswith(".csv")
        # ':' and '.' are illegal in Windows filenames.
        assert ":" not in out["download"]

    def test_the_file_opens_as_utf8_in_excel(self, tmp_path):
        out = _run_export(tmp_path, _state())
        assert out["csv"].startswith("﻿")

    def test_rows_use_crlf_per_rfc4180(self, tmp_path):
        out = _run_export(tmp_path, _state())
        assert "\r\n" in out["csv"]
