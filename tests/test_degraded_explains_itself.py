"""A non-healthy integration status must say why.

Found on the full estate, 8 October 2026. Elasticsearch and Kibana both
reported::

    elasticsearch   degraded   connected: true   error: None

A status with no stated reason is not actionable: the operator cannot tell
whether it is a credential, a version, a cluster colour or a network path,
and "degraded with no explanation" invites being ignored, which is the same
end state as not reporting it.

The reason existed the whole time. ``ConnectorBase.health_check`` sets
DEGRADED when the detected version falls outside ``SUPPORTED_VERSIONS`` and
puts the explanation in ``HealthCheckResult.message``::

    status = ConnectorStatus.DEGRADED
    message = compat["message"]
    # "Version 9.4.4 is above the maximum tested version (9.3.0)..."

but the row is persisted with ``error_message=result.error``, which is
``None`` for a degraded result, and ``_status_for`` surfaces only that. The
text survived in ``metadata.version_compatibility.message`` where nothing
read it.

So this adds ``reason``: the explanation for whatever status is shown,
whether or not it is an error. The rule the tests enforce is that a
non-healthy status is never left unexplained -- and when no reason was
recorded, it says *that*, rather than rendering an empty space that reads
as "no problem".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.integration_api import IntegrationStatusResponse, _explain_status

VERSION_MSG = (
    "Version 9.4.4 is above the maximum tested version (9.3.0). "
    "ION has not been validated against this version."
)


def _row(status, error=None, metadata=None) -> IntegrationStatusResponse:
    row = IntegrationStatusResponse(
        type="elasticsearch",
        display_name="Elasticsearch",
        is_configured=True,
        is_enabled=True,
        status=status,
        error=error,
        metadata=metadata or {},
    )
    return _explain_status(row)


# ── The case that was found ──────────────────────────────────────────────


class TestVersionDegradation:
    def test_degraded_on_version_explains_itself(self):
        row = _row("degraded", metadata={
            "version_compatibility": {"in_range": False, "message": VERSION_MSG}
        })
        assert row.reason == VERSION_MSG

    def test_the_reason_names_the_versions(self):
        """An operator needs the numbers, not just "unsupported"."""
        row = _row("degraded", metadata={
            "version_compatibility": {"in_range": False, "message": VERSION_MSG}
        })
        assert "9.4.4" in row.reason and "9.3.0" in row.reason

    def test_an_in_range_version_is_not_used_as_a_reason(self):
        """"Version 9.0 is within the tested range" explains nothing about
        why something is degraded, so it must not be offered as the cause."""
        row = _row("degraded", metadata={
            "version_compatibility": {
                "in_range": True,
                "message": "Version 9.0.0 is within tested range (8.0.0 - 9.3.0)",
            }
        })
        assert "within tested range" not in (row.reason or "")


# ── An explicit error always wins ────────────────────────────────────────


class TestErrorPrecedence:
    def test_an_error_is_the_reason(self):
        row = _row("error", error="HTTP 401")
        assert row.reason == "HTTP 401"

    def test_an_error_beats_a_version_note(self):
        """If something actually failed, that is the reason, not a version
        remark that happens to also be recorded."""
        row = _row("error", error="HTTP 401", metadata={
            "version_compatibility": {"in_range": False, "message": VERSION_MSG}
        })
        assert row.reason == "HTTP 401"


# ── Nothing recorded ─────────────────────────────────────────────────────


class TestUnexplained:
    def test_a_degraded_row_with_nothing_recorded_says_so(self):
        """An empty explanation renders as blank, which reads as "fine".
        Saying no reason was recorded is both honest and a bug report."""
        row = _row("degraded")
        assert row.reason
        assert "no reason" in row.reason.lower()

    def test_an_error_row_with_nothing_recorded_says_so(self):
        row = _row("error")
        assert row.reason
        assert "no reason" in row.reason.lower()

    def test_unknown_is_explained_too(self):
        """`unknown` comes from the staleness rule, which sets its own
        error; if it somehow did not, this must not be blank either."""
        row = _row("unknown")
        assert row.reason


# ── Healthy and disabled need no excuse ──────────────────────────────────


class TestNoReasonNeeded:
    def test_healthy_has_no_reason(self):
        """A reason on a healthy row is noise that trains people to ignore
        the column."""
        assert _row("healthy").reason is None

    def test_disabled_has_no_reason(self):
        assert _row("disabled").reason is None

    def test_healthy_keeps_a_genuine_message_out_of_the_way(self):
        row = _row("healthy", metadata={
            "version_compatibility": {"in_range": True, "message": "fine"}
        })
        assert row.reason is None


# ── The invariant ────────────────────────────────────────────────────────


class TestInvariant:
    @pytest.mark.parametrize("status", ["degraded", "error", "unknown"])
    def test_no_non_healthy_status_is_ever_unexplained(self, status):
        """The rule this whole change exists to enforce."""
        assert _row(status).reason

    @pytest.mark.parametrize("status", ["healthy", "disabled"])
    def test_benign_statuses_stay_quiet(self, status):
        assert _row(status).reason is None

    def test_a_missing_status_is_not_crashed_on(self):
        row = _row(None)
        assert row.reason is None or isinstance(row.reason, str)

    def test_malformed_metadata_does_not_raise(self):
        """metadata is a free JSON column; a non-object must not 500 the
        page that reports which integration is broken."""
        for bad in ("a string", 42, [1, 2], None):
            row = IntegrationStatusResponse(
                type="x", display_name="X", is_configured=True,
                is_enabled=True, status="degraded", metadata=None,
            )
            row.metadata = bad
            assert _explain_status(row).reason


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    def test_the_response_model_exposes_reason(self):
        assert "reason" in IntegrationStatusResponse.model_fields

    def test_the_status_builder_applies_it(self):
        src = (_SRC / "ion" / "web" / "integration_api.py").read_text(encoding="utf-8")
        block = src.split("def _status_for(")[1][:3500]
        assert "_explain_status" in block
