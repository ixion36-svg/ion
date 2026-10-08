"""A managed way to say "this observable is not interesting".

ION already had three per-observable switches -- ``is_whitelisted``,
``is_ignored``, ``ignore_similarity`` -- but all three are reactive: the
observable has to exist and be wrong before anyone can mark it. On an
estate where a rule fires hundreds of times a day, that means marking the
same value over and over, and the record of *why* lives nowhere.

This is the proactive half: a list of values, ranges and domain suffixes
that never become observables in the first place.

The design is shaped by how allowlists fail rather than by how they work.
An allowlist is a thing that stops you seeing something, so every property
here exists to keep that from happening quietly:

* a reason is mandatory -- an entry with no reason cannot be reviewed, and
  an entry nobody can review is permanent;
* every suppression is counted, so an entry matching nothing (stale, safe
  to remove) and an entry matching thousands (too broad, hiding real
  sightings) are both visible instead of both being silent;
* an expired entry stops matching rather than quietly carrying on;
* matching is anchored. ``example.com`` must not swallow
  ``notexample.com``, and a CIDR must not match across address families.
  A too-greedy allowlist entry is indistinguishable from a blind spot.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.observable_allowlist import (
    AllowlistRule,
    MatchType,
    normalise_pattern,
)

NOW = datetime.now(timezone.utc)


def rule(pattern, match_type, obs_type=None, expires_at=None, is_active=True):
    return AllowlistRule(
        pattern=pattern, match_type=match_type, observable_type=obs_type,
        expires_at=expires_at, is_active=is_active,
    )


# -- Exact values ---------------------------------------------------------


class TestExact:
    def test_an_exact_value_matches(self):
        r = rule("10.1.2.3", MatchType.EXACT)
        assert r.matches("ip", "10.1.2.3")

    def test_a_different_value_does_not(self):
        assert not rule("10.1.2.3", MatchType.EXACT).matches("ip", "10.1.2.4")

    def test_a_longer_value_containing_it_does_not(self):
        """Substring matching is how an allowlist becomes a blind spot."""
        assert not rule("10.1.2.3", MatchType.EXACT).matches("ip", "10.1.2.30")

    def test_matching_ignores_case_and_surrounding_space(self):
        r = rule("Corp-Proxy.Internal", MatchType.EXACT)
        assert r.matches("domain", "  corp-proxy.internal  ")


# -- CIDR ranges ----------------------------------------------------------


class TestCidr:
    def test_an_address_inside_the_range_matches(self):
        assert rule("10.0.0.0/8", MatchType.CIDR).matches("ip", "10.20.30.40")

    def test_an_address_outside_does_not(self):
        assert not rule("10.0.0.0/8", MatchType.CIDR).matches("ip", "192.168.1.1")

    def test_a_single_host_cidr_works(self):
        r = rule("192.168.1.1/32", MatchType.CIDR)
        assert r.matches("ip", "192.168.1.1")
        assert not r.matches("ip", "192.168.1.2")

    def test_ipv6_ranges_work(self):
        assert rule("2001:db8::/32", MatchType.CIDR).matches("ip", "2001:db8::1")

    def test_a_v4_address_does_not_match_a_v6_range(self):
        assert not rule("2001:db8::/32", MatchType.CIDR).matches("ip", "10.0.0.1")

    def test_a_value_that_is_not_an_address_does_not_match_and_does_not_raise(self):
        """Observable values arrive from log data and are not all addresses."""
        r = rule("10.0.0.0/8", MatchType.CIDR)
        assert r.matches("ip", "not-an-ip") is False
        assert r.matches("domain", "example.com") is False


# -- Domain suffixes ------------------------------------------------------


class TestDomainSuffix:
    def test_the_domain_itself_matches(self):
        assert rule("corp.example", MatchType.DOMAIN_SUFFIX).matches(
            "domain", "corp.example")

    def test_a_subdomain_matches(self):
        assert rule("corp.example", MatchType.DOMAIN_SUFFIX).matches(
            "domain", "mail.eu.corp.example")

    def test_a_look_alike_does_not(self):
        """notcorp.example is a different organisation. This is the same
        anchoring bug the reference-host check already had to fix."""
        assert not rule("corp.example", MatchType.DOMAIN_SUFFIX).matches(
            "domain", "notcorp.example")

    def test_a_suffix_appearing_mid_name_does_not(self):
        assert not rule("corp.example", MatchType.DOMAIN_SUFFIX).matches(
            "domain", "corp.example.attacker.test")

    def test_a_url_is_matched_on_its_host(self):
        r = rule("corp.example", MatchType.DOMAIN_SUFFIX)
        assert r.matches("url", "https://intranet.corp.example/page?q=1")

    def test_a_trailing_dot_is_ignored(self):
        assert rule("corp.example", MatchType.DOMAIN_SUFFIX).matches(
            "domain", "host.corp.example.")


# -- Wildcards ------------------------------------------------------------


class TestWildcard:
    def test_a_trailing_wildcard_matches(self):
        assert rule("svc-*", MatchType.WILDCARD).matches("user", "svc-backup")

    def test_a_wildcard_is_anchored_at_both_ends(self):
        """`svc-*` must not match `nosvc-backup`: an unanchored pattern
        suppresses far more than its author intended."""
        assert not rule("svc-*", MatchType.WILDCARD).matches("user", "nosvc-backup")

    def test_a_question_mark_matches_one_character(self):
        r = rule("WKS-??", MatchType.WILDCARD)
        assert r.matches("hostname", "WKS-07")
        assert not r.matches("hostname", "WKS-007")

    def test_regex_metacharacters_in_a_wildcard_are_literal(self):
        """The pattern is a glob, not a regex. A dot must mean a dot, or
        `10.0.0.1` would match `10x0y0z1`."""
        r = rule("10.0.0.1", MatchType.WILDCARD)
        assert r.matches("ip", "10.0.0.1")
        assert not r.matches("ip", "10x0y0z1")


# -- Scoping by observable type -------------------------------------------


class TestTypeScope:
    def test_an_unscoped_rule_matches_any_type(self):
        r = rule("corp.example", MatchType.EXACT, obs_type=None)
        assert r.matches("domain", "corp.example")
        assert r.matches("hostname", "corp.example")

    def test_a_scoped_rule_only_matches_its_type(self):
        """Allowlisting the hostname `backup` must not allowlist a user
        called `backup`."""
        r = rule("backup", MatchType.EXACT, obs_type="hostname")
        assert r.matches("hostname", "backup")
        assert not r.matches("user", "backup")

    def test_type_scope_accepts_the_context_type_variants(self):
        """The extractor emits context types like source_ip and
        destination_ip; a rule scoped to `ip` has to cover both or it will
        appear not to work."""
        r = rule("10.0.0.0/8", MatchType.CIDR, obs_type="ip")
        assert r.matches("source_ip", "10.1.1.1")
        assert r.matches("destination_ip", "10.1.1.1")
        assert r.matches("host_ip", "10.1.1.1")


# -- Lifecycle ------------------------------------------------------------


class TestLifecycle:
    def test_an_inactive_rule_never_matches(self):
        r = rule("10.0.0.0/8", MatchType.CIDR, is_active=False)
        assert not r.matches("ip", "10.1.1.1")

    def test_an_expired_rule_stops_matching(self):
        """An expiry that does not expire is a comment, not a control."""
        r = rule("10.0.0.0/8", MatchType.CIDR,
                 expires_at=NOW - timedelta(minutes=1))
        assert not r.matches("ip", "10.1.1.1")

    def test_a_future_expiry_still_matches(self):
        r = rule("10.0.0.0/8", MatchType.CIDR,
                 expires_at=NOW + timedelta(days=1))
        assert r.matches("ip", "10.1.1.1")

    def test_a_naive_expiry_is_treated_as_utc(self):
        """Postgres hands back naive datetimes here. Comparing a naive to
        an aware datetime raises, and an allowlist that raises mid-extraction
        takes the ingest path down with it."""
        r = rule("10.0.0.0/8", MatchType.CIDR,
                 expires_at=(NOW + timedelta(days=1)).replace(tzinfo=None))
        assert r.matches("ip", "10.1.1.1") is True


# -- Robustness -----------------------------------------------------------


class TestRobustness:
    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_an_empty_value_never_matches(self, value):
        assert rule("10.0.0.0/8", MatchType.CIDR).matches("ip", value) is False

    def test_a_malformed_cidr_pattern_does_not_match_or_raise(self):
        assert rule("not/a/cidr", MatchType.CIDR).matches("ip", "10.0.0.1") is False

    def test_the_result_is_always_a_bool(self):
        assert rule("10.0.0.1", MatchType.EXACT).matches("ip", "10.0.0.1") is True
        assert rule("10.0.0.1", MatchType.EXACT).matches("ip", "10.0.0.2") is False


# -- Validation at creation ----------------------------------------------


class TestNormalisation:
    def test_a_cidr_pattern_is_validated(self):
        with pytest.raises(ValueError):
            normalise_pattern(MatchType.CIDR, "999.0.0.0/8")

    def test_a_bare_ip_is_accepted_as_a_cidr(self):
        """Operators type an address far more often than a /32."""
        assert normalise_pattern(MatchType.CIDR, "10.0.0.1") == "10.0.0.1/32"

    def test_a_cidr_with_host_bits_set_is_normalised(self):
        """10.0.0.5/8 means 10.0.0.0/8. Storing it as typed makes the list
        read as if it covers one host when it covers sixteen million."""
        assert normalise_pattern(MatchType.CIDR, "10.0.0.5/8") == "10.0.0.0/8"

    def test_a_domain_suffix_is_lowercased_and_stripped(self):
        assert normalise_pattern(
            MatchType.DOMAIN_SUFFIX, "  .Corp.Example. ") == "corp.example"

    def test_an_empty_pattern_is_rejected(self):
        for mt in MatchType:
            with pytest.raises(ValueError):
                normalise_pattern(mt, "   ")

    def test_a_wildcard_that_matches_everything_is_rejected(self):
        """`*` allowlists the entire estate. If someone genuinely wants
        that they can switch extraction off, which at least is visible."""
        for pattern in ("*", "**", "  *  "):
            with pytest.raises(ValueError):
                normalise_pattern(MatchType.WILDCARD, pattern)

    def test_a_cidr_covering_the_whole_internet_is_rejected(self):
        for pattern in ("0.0.0.0/0", "::/0"):
            with pytest.raises(ValueError):
                normalise_pattern(MatchType.CIDR, pattern)
