"""An old health check must not be reported as current health.

Found by bringing the full integration estate up on 8 October 2026 and
comparing ION's integrations page against the services themselves.

``GET /api/integrations/status`` reported every integration ``healthy``,
with a response time, from a check dated **6 September** — a month earlier.
In that month Kibana had been replaced (the stored metadata still said
8.19.11; the running container was 9.4.4). Forcing a real check with
``POST /api/integrations/healthcheck`` returned the truth: Arkime in error
on HTTP 401, OpenCTI in error, Elasticsearch and Kibana degraded.

The mechanism is that health checks are written *only* by that POST — there
is no background sweep — and ``/status`` serves the newest stored row
verbatim, with its ``checked_at`` carried in ``last_check`` but nothing
reading it. So an estate nobody has actively probed reports itself healthy
indefinitely, and the page that exists to tell an analyst which integration
is broken is the one thing that will not.

The fix is not to hide the old row, which would be its own kind of lying,
nor to probe every integration on page load, which makes a dashboard a
load generator. It is to report the row's *age* and refuse to present a
stale one as a health verdict: past the threshold the status becomes
``unknown``, with the age and the reason attached.

``DISABLED`` is deliberately exempt. "This integration is switched off" is
a statement about configuration, not a measurement, and does not decay.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.integration_api import (
    STALE_HEALTH_CHECK_SECONDS,
    IntegrationStatusResponse,
    _apply_check_freshness,
)


def _utc(seconds_ago: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)


def _row(status="healthy", checked_at=None, **over) -> IntegrationStatusResponse:
    payload = dict(
        type="kibana_cases",
        display_name="Kibana Cases",
        is_configured=True,
        is_enabled=True,
        status=status,
        response_time_ms=5.4,
    )
    payload.update(over)
    row = IntegrationStatusResponse(**payload)
    return _apply_check_freshness(row, checked_at)


# ── A fresh check is left alone ──────────────────────────────────────────


class TestFreshCheck:
    def test_a_recent_healthy_check_stays_healthy(self):
        row = _row(checked_at=_utc(30))
        assert row.status == "healthy"
        assert row.is_stale is False

    def test_a_recent_check_reports_its_age(self):
        """The age is always present, not only when it is bad news."""
        row = _row(checked_at=_utc(30))
        assert row.check_age_seconds is not None
        assert 25 <= row.check_age_seconds <= 60

    def test_a_recent_error_is_untouched(self):
        row = _row(status="error", checked_at=_utc(10), error="HTTP 401")
        assert row.status == "error"
        assert row.error == "HTTP 401"

    def test_the_boundary_is_not_stale(self):
        row = _row(checked_at=_utc(STALE_HEALTH_CHECK_SECONDS - 5))
        assert row.is_stale is False
        assert row.status == "healthy"


# ── A stale check is not a health verdict ────────────────────────────────


class TestStaleCheck:
    def test_a_month_old_healthy_check_is_not_healthy(self):
        """The exact case found on the estate."""
        row = _row(checked_at=_utc(32 * 86400))
        assert row.status == "unknown"
        assert row.is_stale is True

    def test_a_stale_check_explains_itself(self):
        row = _row(checked_at=_utc(32 * 86400))
        assert row.error
        assert "stale" in row.error.lower() or "old" in row.error.lower()

    def test_a_stale_check_keeps_the_age_visible(self):
        row = _row(checked_at=_utc(32 * 86400))
        assert row.check_age_seconds > 30 * 86400

    def test_a_stale_check_drops_the_response_time(self):
        """A latency from a month ago is not this integration's latency, and
        rendering it beside "unknown" invites reading it as current."""
        row = _row(checked_at=_utc(32 * 86400))
        assert row.response_time_ms is None

    def test_a_stale_error_is_also_downgraded(self):
        """A month-old failure is no more current than a month-old success:
        the integration may well have been fixed since."""
        row = _row(status="error", checked_at=_utc(32 * 86400), error="HTTP 401")
        assert row.status == "unknown"
        assert "HTTP 401" not in (row.error or "")

    def test_just_past_the_threshold_is_stale(self):
        row = _row(checked_at=_utc(STALE_HEALTH_CHECK_SECONDS + 5))
        assert row.is_stale is True
        assert row.status == "unknown"

    def test_the_stale_reason_names_the_refresh_action(self):
        """An analyst reading "unknown" needs to know what to do about it."""
        row = _row(checked_at=_utc(32 * 86400))
        assert "healthcheck" in (row.error or "").lower()


# ── Disabled does not decay ──────────────────────────────────────────────


class TestDisabled:
    def test_a_stale_disabled_row_stays_disabled(self):
        """Switched off is a configuration fact, not a measurement."""
        row = _row(status="disabled", checked_at=_utc(32 * 86400))
        assert row.status == "disabled"
        assert row.is_stale is True

    def test_a_stale_disabled_row_still_reports_its_age(self):
        row = _row(status="disabled", checked_at=_utc(32 * 86400))
        assert row.check_age_seconds > 30 * 86400


# ── Never checked at all ─────────────────────────────────────────────────


class TestNeverChecked:
    def test_no_check_is_unknown_not_healthy(self):
        """A fresh install has no stored row. Defaulting to healthy would be
        the same lie with no data behind it at all."""
        row = _row(status=None, checked_at=None)
        assert row.status == "unknown"
        assert row.is_stale is True

    def test_no_check_has_no_age(self):
        """Zero would read as "checked just now"."""
        row = _row(status=None, checked_at=None)
        assert row.check_age_seconds is None

    def test_no_check_says_so(self):
        row = _row(status=None, checked_at=None)
        assert "never" in (row.error or "").lower()


# ── Naive timestamps ─────────────────────────────────────────────────────


class TestNaiveTimestamps:
    def test_a_naive_timestamp_is_treated_as_utc(self):
        """checked_at comes back naive from the database. Comparing it to an
        aware now() raises, and assuming local time would mis-age every row
        by the host's offset."""
        naive = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=30)
        row = _row(checked_at=naive)
        assert row.is_stale is False
        assert 25 <= row.check_age_seconds <= 60

    def test_a_naive_stale_timestamp_is_still_stale(self):
        naive = (datetime.now(timezone.utc) - timedelta(days=32)).replace(tzinfo=None)
        row = _row(checked_at=naive)
        assert row.is_stale is True

    def test_a_future_timestamp_does_not_produce_a_negative_age(self):
        """Clock skew between ION and its database should not make a row
        look impossibly fresh, nor report a negative age."""
        row = _row(checked_at=_utc(-120))
        assert row.check_age_seconds >= 0
        assert row.is_stale is False


# ── The endpoint applies it ──────────────────────────────────────────────


class TestWiring:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "integration_api.py").read_text(encoding="utf-8")

    def test_the_status_builder_applies_freshness(self):
        src = self._api()
        block = src.split("def _status_for(")[1][:3000]
        assert "_apply_check_freshness" in block

    def test_the_row_with_no_stored_check_also_goes_through_it(self):
        """The early return for "no check" must not bypass the downgrade."""
        src = self._api()
        block = src.split("def _status_for(")[1][:3000]
        before_return = block.split("if not latest_check:")[1][:400]
        assert "_apply_check_freshness" in before_return

    def test_the_threshold_is_configurable(self):
        assert "ION_INTEGRATION_STALE_AFTER_SECONDS" in self._api()

    def test_the_response_model_exposes_both_fields(self):
        assert "is_stale" in IntegrationStatusResponse.model_fields
        assert "check_age_seconds" in IntegrationStatusResponse.model_fields
