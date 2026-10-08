"""Label estate routing accurately (8 Oct 2026 review, §22, stage 5).

    "Tenant code explicitly documents incomplete local case/triage and
    background-job isolation."

    "Improve: ... Label estate routing accurately until full isolation is
    delivered."

The header switcher says **Estate** and lists client names. An analyst
switching from one to another sees the alert data change, because
Elasticsearch and Kibana are routed per tenant — and sees the *same* cases,
the same notes and the same scheduled jobs, because ``tenant_id`` exists on
``users`` and nowhere else.

That is not a cosmetic gap. A control labelled as an estate switch, which
changes some of the estate and not the rest, invites someone to act on one
client's case while the header says they are in another client's estate.
The model docstring is candid about it; the interface was not.

The fix is a scope statement the API returns and the switcher shows. The
important design choice is that it is **derived from the model metadata**,
not written down: ``tenant_scope()`` asks which mapped tables actually carry
a ``tenant_id`` column. When phase 2 adds the column to cases and triage,
the label corrects itself. A hand-maintained list would say "cases are not
isolated" for as long as nobody remembered to edit it, which is the same
class of error in a new place.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import ion.models  # noqa: F401
from ion.models.base import Base
from ion.services.tenant_service import (
    TENANT_SCOPE_COLUMN,
    tenant_scope,
)


@pytest.fixture()
def scope():
    return tenant_scope()


# ── Derived, not asserted ────────────────────────────────────────────────


class TestDerivation:
    def test_the_scoped_tables_are_the_ones_with_the_column(self, scope):
        """The whole point: the claim is computed from the schema."""
        actual = {
            name for name, table in Base.metadata.tables.items()
            if TENANT_SCOPE_COLUMN in table.columns
        }
        assert set(scope["scoped_tables"]) == actual

    def test_users_is_currently_scoped(self, scope):
        """Sanity check on the derivation: this is the one that has it."""
        assert "users" in scope["scoped_tables"]

    def test_cases_are_currently_not_scoped(self, scope):
        """Phase 2's job. If this starts failing because the column landed,
        the label has already corrected itself and the test should be
        updated to match -- which is the behaviour being bought here."""
        assert "alert_cases" not in scope["scoped_tables"]

    def test_the_column_name_is_stated(self):
        assert TENANT_SCOPE_COLUMN == "tenant_id"

    def test_the_scoped_table_list_is_sorted_and_deduplicated(self, scope):
        tables = scope["scoped_tables"]
        assert tables == sorted(set(tables))


# ── What the switch actually does ────────────────────────────────────────


class TestScopeStatement:
    def test_the_routed_surfaces_are_named(self, scope):
        routed = " ".join(scope["switch_changes"]).lower()
        assert "elasticsearch" in routed
        assert "kibana" in routed

    def test_the_shared_surfaces_are_named(self, scope):
        """An analyst needs to know what does *not* change."""
        shared = " ".join(scope["switch_does_not_change"]).lower()
        assert "case" in shared
        assert "job" in shared or "schedul" in shared

    def test_arkime_and_opencti_are_declared_shared(self, scope):
        """Deliberately estate-wide. Saying so stops it reading as an
        oversight, and stops anyone assuming PCAP is isolated."""
        shared = " ".join(scope["switch_does_not_change"]).lower()
        assert "arkime" in shared
        assert "opencti" in shared

    def test_the_isolation_is_not_described_as_complete(self, scope):
        assert scope["complete"] is False

    def test_there_is_a_one_line_summary_for_the_control(self, scope):
        """The switcher has room for one sentence, so one sentence has to
        carry the caveat."""
        assert scope["summary"]
        assert len(scope["summary"]) < 200
        assert "elasticsearch" in scope["summary"].lower()

    def test_the_summary_says_what_is_shared(self, scope):
        assert "shared" in scope["summary"].lower() or \
            "not" in scope["summary"].lower()

    def test_nothing_claims_full_tenancy(self, scope):
        """Guards against a future edit quietly upgrading the wording."""
        text = " ".join(
            [scope["summary"]]
            + list(scope["switch_changes"])
            + list(scope["switch_does_not_change"])
        ).lower()
        for overclaim in ("fully isolated", "complete isolation",
                          "full multi-tenancy", "fully separated"):
            assert overclaim not in text

    def test_the_statement_is_stable_across_calls(self, scope):
        assert tenant_scope() == scope


# ── The API carries it ───────────────────────────────────────────────────


class TestApi:
    @staticmethod
    def _api():
        return (_SRC / "ion" / "web" / "tenant_api.py").read_text(encoding="utf-8")

    def test_the_state_model_exposes_the_scope(self):
        from ion.web.tenant_api import TenantState

        assert "isolation" in TenantState.model_fields

    def test_a_disabled_deployment_still_reports_the_scope(self):
        """Single-estate deploys show no switcher, but an admin reading the
        endpoint should still get a straight answer."""
        assert "isolation=tenant_scope()" in self._api().replace(" ", "")

    def test_the_endpoint_builds_the_scope_from_the_service(self):
        assert "tenant_scope" in self._api()


# ── The control says it ──────────────────────────────────────────────────


class TestSwitcher:
    @staticmethod
    def _js():
        return (_SRC / "ion" / "web" / "static" / "js" / "tenant-switcher.js"
                ).read_text(encoding="utf-8")

    def test_the_switcher_renders_the_caveat(self):
        js = self._js()
        assert "isolation" in js
        assert "summary" in js

    def test_the_caveat_is_not_only_a_title_attribute(self):
        """A tooltip nobody hovers is not a label. There has to be something
        visible beside the control."""
        js = self._js()
        assert "tenant-scope-note" in js

    def test_the_switcher_does_not_hardcode_the_wording(self):
        """The server derives it; a copy in the client would drift."""
        js = self._js().lower()
        assert "arkime" not in js
        assert "opencti" not in js
