"""The allowlist has to actually stop observables being created.

The matcher is tested on its own in test_observable_allowlist.py. This is
the half that matters operationally: that it is wired into the automatic
extraction paths, that a suppression is counted rather than silent, and
that it does not reach the paths where an analyst is deliberately adding
something.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.base import Base
from ion.models.observable import ObservableType
from ion.models.observable_allowlist import ObservableAllowlist
from ion.services import observable_allowlist_service as allowlist
from ion.services.observable_service import ObservableService


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    allowlist.invalidate_cache()
    yield s
    s.close()
    allowlist.invalidate_cache()


@pytest.fixture
def service(session):
    return ObservableService(session)


def add(session, **kw):
    kw.setdefault("reason", "corporate range, not an indicator")
    entry = allowlist.add_entry(session, **kw)
    session.commit()
    allowlist.invalidate_cache()
    return entry


# -- Suppression ----------------------------------------------------------


class TestSuppression:
    def test_an_allowlisted_value_is_suppressed(self, session, service):
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            observable_type="ip")
        assert service._allowlisted("source_ip", "10.20.30.40") is True

    def test_a_value_outside_the_rule_is_not(self, session, service):
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            observable_type="ip")
        assert service._allowlisted("source_ip", "203.0.113.9") is False

    def test_with_an_empty_allowlist_nothing_is_suppressed(self, service):
        assert service._allowlisted("source_ip", "10.20.30.40") is False

    def test_a_domain_suffix_covers_subdomains(self, session, service):
        add(session, match_type="domain_suffix", pattern="corp.example",
            observable_type="domain")
        assert service._allowlisted("domain", "mail.corp.example") is True
        assert service._allowlisted("domain", "notcorp.example") is False


# -- Suppression is counted, not silent -----------------------------------


class TestItIsCounted:
    def test_a_hit_increments_the_entry(self, session, service):
        entry = add(session, match_type="cidr", pattern="10.0.0.0/8",
                    observable_type="ip")
        service._allowlisted("source_ip", "10.1.1.1")
        service._allowlisted("source_ip", "10.2.2.2")
        session.commit()
        session.refresh(entry)
        assert entry.hit_count == 2

    def test_the_last_value_is_recorded(self, session, service):
        """So a reviewer can see what an entry is catching without having
        to reconstruct it from logs."""
        entry = add(session, match_type="cidr", pattern="10.0.0.0/8",
                    observable_type="ip")
        service._allowlisted("source_ip", "10.9.9.9")
        session.commit()
        session.refresh(entry)
        assert entry.last_hit_value == "10.9.9.9"
        assert entry.last_hit_at is not None

    def test_a_miss_does_not_increment(self, session, service):
        entry = add(session, match_type="cidr", pattern="10.0.0.0/8",
                    observable_type="ip")
        service._allowlisted("source_ip", "203.0.113.9")
        session.commit()
        session.refresh(entry)
        assert entry.hit_count == 0


# -- Lifecycle ------------------------------------------------------------


class TestLifecycle:
    def test_deactivating_stops_suppression(self, session, service):
        entry = add(session, match_type="cidr", pattern="10.0.0.0/8",
                    observable_type="ip")
        assert service._allowlisted("source_ip", "10.1.1.1") is True
        allowlist.set_active(session, entry.id, False)
        session.commit()
        assert service._allowlisted("source_ip", "10.1.1.1") is False

    def test_an_expired_entry_stops_suppressing(self, session, service):
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            observable_type="ip",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        assert service._allowlisted("source_ip", "10.1.1.1") is False

    def test_a_new_entry_takes_effect_without_waiting_for_the_cache(
        self, session, service
    ):
        """add_entry drops the cache. If it did not, an operator would add
        an entry, watch the noise continue, and conclude it does not work."""
        assert service._allowlisted("source_ip", "10.1.1.1") is False
        allowlist.add_entry(session, match_type="cidr", pattern="10.0.0.0/8",
                            observable_type="ip", reason="corporate range")
        session.commit()
        assert service._allowlisted("source_ip", "10.1.1.1") is True


# -- Validation -----------------------------------------------------------


class TestValidation:
    def test_a_reason_is_required(self, session):
        with pytest.raises(allowlist.AllowlistError) as exc:
            allowlist.add_entry(session, match_type="cidr",
                                pattern="10.0.0.0/8", reason="  ")
        assert "reason" in str(exc.value).lower()

    def test_a_duplicate_is_refused_and_names_the_existing_reason(self, session):
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            reason="corporate range")
        with pytest.raises(allowlist.AllowlistError) as exc:
            allowlist.add_entry(session, match_type="cidr",
                                pattern="10.0.0.0/8", reason="different reason")
        assert "corporate range" in str(exc.value)

    def test_a_catch_all_cidr_is_refused(self, session):
        with pytest.raises(allowlist.AllowlistError):
            allowlist.add_entry(session, match_type="cidr",
                                pattern="0.0.0.0/0", reason="everything")

    def test_an_unknown_match_type_is_refused(self, session):
        with pytest.raises(allowlist.AllowlistError):
            allowlist.add_entry(session, match_type="telepathy",
                                pattern="x", reason="y")

    def test_a_cidr_is_stored_canonicalised(self, session):
        """10.0.0.5/8 reads as one host and covers sixteen million."""
        entry = add(session, match_type="cidr", pattern="10.0.0.5/8")
        assert entry.pattern == "10.0.0.0/8"


# -- Deliberate analyst action is not blocked -----------------------------


class TestDeliberateCreationIsUnaffected:
    def test_get_or_create_still_creates_an_allowlisted_value(
        self, session, service
    ):
        """An allowlist silences automatic noise. It must not stop an
        analyst recording something they have decided matters -- the CSV
        and STIX importers go straight to get_or_create for that reason."""
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            observable_type="ip")
        obs, created = service.get_or_create(ObservableType.IPV4, "10.1.1.1")
        assert created is True
        assert obs.value == "10.1.1.1"


# -- Failure must not take extraction down --------------------------------


class TestFailureMode:
    def test_a_broken_allowlist_does_not_suppress_and_does_not_raise(
        self, service, monkeypatch
    ):
        """Erring toward extracting is the right way round: a missing
        suppression is noise an analyst can see and report, a missing
        observable is a sighting nobody knows was dropped."""
        def boom(*a, **k):
            raise RuntimeError("table is gone")

        monkeypatch.setattr(allowlist, "suppressed", boom)
        assert service._allowlisted("source_ip", "10.1.1.1") is False


# -- The review view ------------------------------------------------------


class TestReviewSummary:
    def test_it_counts_what_an_allowlist_drifts_into(self, session, service):
        add(session, match_type="cidr", pattern="10.0.0.0/8",
            observable_type="ip", reason="used")
        add(session, match_type="cidr", pattern="172.16.0.0/12",
            observable_type="ip", reason="never matches anything")
        add(session, match_type="cidr", pattern="192.168.0.0/16",
            observable_type="ip", reason="temporary",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1))
        service._allowlisted("source_ip", "10.1.1.1")
        session.commit()

        s = allowlist.review_summary(session)
        assert s["total"] == 3
        assert s["never_matched"] == 2
        assert s["expired"] == 1
        assert s["total_suppressed"] == 1
