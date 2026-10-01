"""Tests for service_account_service — review cadence, staleness, risk rollup.

This module was at 0% when the coverage ratchet first measured the tree. Its
review workflow is cited against PCI 7.2.4, ISO A.5.16 and NIST 800-53
AC-2(j) in the model, so the behaviour that matters most is the one an
auditor would ask about: an account that has never been reviewed must read as
overdue, and an account whose password was never set must read as stale.
Both are fail-safe defaults, and both are the kind of thing a refactor
silently inverts.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from ion.models.oncall import ServiceAccount
from ion.models.user import User
from ion.services import service_account_service as svc


def _acct(session, name="svc-backup", **kw):
    acct = ServiceAccount(account_name=name, **kw)
    session.add(acct)
    session.flush()
    return acct


def _user(session, username="reviewer"):
    u = User(username=username, email=f"{username}@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


def _ago(days):
    return datetime.utcnow() - timedelta(days=days)


class TestReviewDueLogic:
    """When an account counts as due, overdue, or neither."""

    def test_never_reviewed_is_overdue(self, session):
        """Fail-safe: no review on record means overdue, not 'not yet due'."""
        acct = _acct(session)
        d = svc.get_service_account(session, acct.id)
        assert d["review_overdue"] is True
        assert d["next_review_due"] is None

    def test_recent_review_is_not_overdue(self, session):
        acct = _acct(session, last_reviewed_at=_ago(10), review_cadence_days=90)
        d = svc.get_service_account(session, acct.id)
        assert d["review_overdue"] is False
        assert d["days_until_due"] == 80

    def test_review_older_than_the_cadence_is_overdue(self, session):
        acct = _acct(session, last_reviewed_at=_ago(100), review_cadence_days=90)
        d = svc.get_service_account(session, acct.id)
        assert d["review_overdue"] is True
        assert d["days_until_due"] == -10

    def test_cadence_defaults_to_ninety_days(self):
        """The `or 90` fallback guards rows predating the NOT NULL column.

        Such a row cannot be created through the ORM any more, so this works
        on a transient object rather than pretending the database allows it.
        """
        acct = ServiceAccount(account_name="legacy", last_reviewed_at=_ago(10))
        acct.review_cadence_days = None

        d = svc._account_to_dict(acct)

        assert d["review_cadence_days"] == 90
        assert d["days_until_due"] == 80

    def test_a_shorter_cadence_brings_the_date_forward(self, session):
        acct = _acct(session, last_reviewed_at=_ago(40), review_cadence_days=30)
        assert svc.get_service_account(session, acct.id)["review_overdue"] is True

    def test_legacy_review_date_is_used_when_never_reviewed(self, session):
        """The manual override still governs rows the workflow never touched."""
        future = date.today() + timedelta(days=5)
        acct = _acct(session, review_date=future)
        d = svc.get_service_account(session, acct.id)
        assert d["review_overdue"] is False
        assert d["next_review_due"] == future.isoformat()
        assert d["days_until_due"] == 5

    def test_a_past_legacy_review_date_is_overdue(self, session):
        acct = _acct(session, review_date=date.today() - timedelta(days=3))
        assert svc.get_service_account(session, acct.id)["review_overdue"] is True

    def test_an_actual_review_wins_over_the_legacy_date(self, session):
        """last_reviewed_at is the workflow's answer; review_date is the old one."""
        acct = _acct(
            session,
            last_reviewed_at=_ago(1),
            review_cadence_days=90,
            review_date=date.today() - timedelta(days=300),
        )
        assert svc.get_service_account(session, acct.id)["review_overdue"] is False

    def test_missing_account_returns_empty(self, session):
        assert svc.get_service_account(session, 999_999) == {}


class TestSerialisedFields:
    def test_systems_and_permissions_come_back_parsed(self, session):
        acct = _acct(session, systems='["dc01", "dc02"]',
                     permissions='{"groups": ["Domain Admins"]}')
        d = svc.get_service_account(session, acct.id)
        assert d["systems"] == ["dc01", "dc02"]
        assert d["permissions"] == {"groups": ["Domain Admins"]}

    @pytest.mark.parametrize("raw", ["not json", "", "{unclosed"])
    def test_malformed_json_reads_as_none_rather_than_raising(self, session, raw):
        """One bad row must not break the whole account list."""
        acct = _acct(session, systems=raw)
        assert svc.get_service_account(session, acct.id)["systems"] is None

    def test_owner_username_is_resolved(self, session):
        owner = _user(session, "alice")
        acct = _acct(session, owner_id=owner.id)
        assert svc.get_service_account(session, acct.id)["owner_username"] == "alice"

    def test_no_owner_reads_as_none(self, session):
        acct = _acct(session)
        assert svc.get_service_account(session, acct.id)["owner_username"] is None


class TestMarkReviewed:
    def test_missing_account_returns_empty(self, session):
        assert svc.mark_reviewed(session, 999_999, reviewer_id=1) == {}

    def test_recording_a_review_clears_overdue(self, session):
        acct = _acct(session, last_reviewed_at=_ago(200), review_cadence_days=90)
        reviewer = _user(session)
        assert svc.get_service_account(session, acct.id)["review_overdue"] is True

        d = svc.mark_reviewed(session, acct.id, reviewer_id=reviewer.id)

        assert d["review_overdue"] is False
        assert d["last_reviewed_by_id"] == reviewer.id
        assert d["last_reviewed_by_username"] == "reviewer"

    def test_notes_are_stored(self, session):
        acct = _acct(session)
        d = svc.mark_reviewed(session, acct.id, reviewer_id=1, notes="still needed")
        assert d["review_notes"] == "still needed"

    def test_omitting_notes_leaves_the_previous_ones(self, session):
        """Re-reviewing without a comment must not wipe the audit note."""
        acct = _acct(session, review_notes="original")
        d = svc.mark_reviewed(session, acct.id, reviewer_id=1, notes=None)
        assert d["review_notes"] == "original"

    def test_a_new_cadence_is_applied(self, session):
        acct = _acct(session)
        d = svc.mark_reviewed(session, acct.id, reviewer_id=1, cadence_days=30)
        assert d["review_cadence_days"] == 30

    @pytest.mark.parametrize("bad", [0, -30])
    def test_a_nonpositive_cadence_is_ignored(self, session, bad):
        """A zero cadence would make every account permanently overdue."""
        acct = _acct(session, review_cadence_days=90)
        d = svc.mark_reviewed(session, acct.id, reviewer_id=1, cadence_days=bad)
        assert d["review_cadence_days"] == 90


class TestOverdueReviews:
    def test_only_live_accounts_are_chased(self, session):
        """Decommissioned accounts are not an outstanding review action."""
        _acct(session, "live", status="active")
        _acct(session, "pending", status="pending_review")
        _acct(session, "off", status="disabled")
        _acct(session, "gone", status="decommissioned")

        names = {a["account_name"] for a in svc.get_overdue_reviews(session)}

        assert names == {"live", "pending"}

    def test_most_overdue_first(self, session):
        _acct(session, "slightly", last_reviewed_at=_ago(95), review_cadence_days=90)
        _acct(session, "badly", last_reviewed_at=_ago(300), review_cadence_days=90)

        names = [a["account_name"] for a in svc.get_overdue_reviews(session)]

        assert names == ["badly", "slightly"]

    def test_never_reviewed_sorts_above_merely_late(self, session):
        _acct(session, "late", last_reviewed_at=_ago(95), review_cadence_days=90)
        _acct(session, "never")

        assert svc.get_overdue_reviews(session)[0]["account_name"] == "never"

    def test_an_account_within_cadence_is_absent(self, session):
        _acct(session, "fresh", last_reviewed_at=_ago(1), review_cadence_days=90)
        assert svc.get_overdue_reviews(session) == []


class TestListingAndFilters:
    def test_ordered_by_account_name(self, session):
        _acct(session, "zeta")
        _acct(session, "alpha")
        names = [a["account_name"] for a in svc.get_service_accounts(session)]
        assert names == ["alpha", "zeta"]

    def test_filtered_by_status(self, session):
        _acct(session, "on", status="active")
        _acct(session, "off", status="disabled")
        out = svc.get_service_accounts(session, status="disabled")
        assert [a["account_name"] for a in out] == ["off"]

    def test_filtered_by_risk_level(self, session):
        _acct(session, "crit", risk_level="critical")
        _acct(session, "low", risk_level="low")
        out = svc.get_service_accounts(session, risk_level="critical")
        assert [a["account_name"] for a in out] == ["crit"]

    def test_both_filters_apply_together(self, session):
        _acct(session, "a", status="active", risk_level="critical")
        _acct(session, "b", status="disabled", risk_level="critical")
        out = svc.get_service_accounts(session, status="active", risk_level="critical")
        assert [a["account_name"] for a in out] == ["a"]


class TestCreateAndUpdate:
    def test_list_and_dict_fields_are_serialised_on_create(self, session):
        d = svc.create_service_account(
            session, account_name="svc-app",
            systems=["dc01"], permissions={"groups": ["Backup Operators"]},
        )
        assert d["systems"] == ["dc01"]
        assert d["permissions"] == {"groups": ["Backup Operators"]}

    def test_a_json_string_is_passed_through_untouched(self, session):
        d = svc.create_service_account(session, account_name="svc-raw",
                                       systems='["already-json"]')
        assert d["systems"] == ["already-json"]

    def test_update_missing_account_returns_empty(self, session):
        assert svc.update_service_account(session, 999_999, risk_level="low") == {}

    def test_update_serialises_lists_too(self, session):
        acct = _acct(session)
        d = svc.update_service_account(session, acct.id, systems=["new01", "new02"])
        assert d["systems"] == ["new01", "new02"]

    def test_unknown_fields_are_ignored(self, session):
        """A stray key from a caller must not raise or land on the row."""
        acct = _acct(session)
        d = svc.update_service_account(session, acct.id, not_a_column="x",
                                       risk_level="high")
        assert d["risk_level"] == "high"
        assert not hasattr(acct, "not_a_column")


class TestStaleAccounts:
    def test_a_password_older_than_the_window_is_stale(self, session):
        _acct(session, "old", password_last_set=_ago(200))
        out = svc.get_stale_accounts(session, stale_days=90)
        assert [a["account_name"] for a in out] == ["old"]
        assert out[0]["days_since_rotation"] >= 199

    def test_a_password_never_set_counts_as_stale(self, session):
        """Fail-safe: unknown rotation is treated as bad, not as fine."""
        _acct(session, "unknown", password_last_set=None)
        out = svc.get_stale_accounts(session, stale_days=90)
        assert [a["account_name"] for a in out] == ["unknown"]
        assert out[0]["days_since_rotation"] is None

    def test_a_recently_rotated_password_is_not_stale(self, session):
        _acct(session, "fresh", password_last_set=_ago(5))
        assert svc.get_stale_accounts(session, stale_days=90) == []

    def test_disabled_accounts_are_excluded(self, session):
        _acct(session, "off", status="disabled", password_last_set=_ago(500))
        assert svc.get_stale_accounts(session, stale_days=90) == []

    def test_the_window_is_configurable(self, session):
        _acct(session, "thirty", password_last_set=_ago(40))
        assert svc.get_stale_accounts(session, stale_days=90) == []
        assert len(svc.get_stale_accounts(session, stale_days=30)) == 1

    def test_oldest_first_with_unknown_rotation_at_the_top(self, session):
        _acct(session, "older", password_last_set=_ago(300))
        _acct(session, "old", password_last_set=_ago(100))
        _acct(session, "unknown", password_last_set=None)

        names = [a["account_name"] for a in svc.get_stale_accounts(session)]

        assert names == ["unknown", "older", "old"]


class TestRiskSummary:
    def test_counts_live_accounts_by_risk_level(self, session):
        _acct(session, "c1", risk_level="critical")
        _acct(session, "c2", risk_level="critical")
        _acct(session, "l1", risk_level="low")

        summary = svc.get_account_risk_summary(session)

        assert summary["total_active"] == 3
        assert summary["by_risk_level"] == {"critical": 2, "low": 1}

    def test_decommissioned_accounts_are_left_out(self, session):
        _acct(session, "live", risk_level="high")
        _acct(session, "gone", risk_level="high", status="decommissioned")

        summary = svc.get_account_risk_summary(session)

        assert summary["total_active"] == 1
        assert summary["by_risk_level"] == {"high": 1}

    def test_stale_and_never_expires_are_counted(self, session):
        _acct(session, "stale", password_last_set=_ago(200))
        _acct(session, "forever", password_last_set=_ago(1),
              password_never_expires=True)
        _acct(session, "ok", password_last_set=_ago(1))

        summary = svc.get_account_risk_summary(session)

        assert summary["stale_count"] == 1
        assert summary["never_expires_count"] == 1

    def test_an_empty_estate_reports_zeroes_not_nulls(self, session):
        summary = svc.get_account_risk_summary(session)
        assert summary == {
            "total_active": 0,
            "by_risk_level": {},
            "stale_count": 0,
            "never_expires_count": 0,
        }


def test_timezone_naive_password_dates_do_not_crash_the_stale_sweep(session):
    """SQLite returns naive datetimes; the sweep compares against an aware now."""
    _acct(session, "naive", password_last_set=datetime.utcnow() - timedelta(days=120))
    out = svc.get_stale_accounts(session, stale_days=90)
    assert out[0]["days_since_rotation"] >= 119


def test_aware_password_dates_are_handled_too(session):
    _acct(session, "aware",
          password_last_set=datetime.now(timezone.utc) - timedelta(days=120))
    out = svc.get_stale_accounts(session, stale_days=90)
    assert out[0]["days_since_rotation"] >= 119
