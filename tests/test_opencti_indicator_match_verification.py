"""A fuzzy text hit is not an IOC match.

Found on the real estate, 8 October 2026, with OpenCTI seeded from live
abuse.ch URLhaus data. Enriching the benign domain ``github.com`` returned::

    found: True
    observable: None
    indicators: [ https://github.com/.../bundle.zip (malware_download) ]

Nothing in OpenCTI asserts that ``github.com`` is malicious -- the domain
observable does not exist there. What matched was an indicator for a
*malicious URL hosted on* GitHub, because ``_search_indicators`` hands the
observable value to OpenCTI's ``search:`` argument, which is a full-text
match across name, description and pattern, and then accepts every row it
gets back as a match for that observable.

The consequences are not subtle:

* Every shared hosting platform used for malware delivery -- github.com,
  gitlab.com, cdn.discordapp.com, any S3 or R2 bucket domain -- becomes a
  standing false positive.
* The indicator descriptions carry the reporter, tags and reference URL, so
  a lookup of any word in a description matches too. An analyst pasting a
  CVE id, a hostname or a vendor name can get "found".
* It is silently worse than no enrichment, because ``found: True`` is what
  the UI escalates on.

ION already holds what it needs to tell the difference: each indicator
carries its STIX ``pattern``, which states exactly which observable it is
about. The rule these tests enforce is that a candidate counts only when its
pattern asserts the value that was actually looked up, for a compatible
observable type. A search that returns candidates none of which verify is
``found: False`` -- the honest answer.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.opencti_service import pattern_asserts


# -- The case that was found ---------------------------------------------


class TestTheGithubCase:
    URL_PATTERN = (
        "[url:value = 'https://github.com/12312d12e1/31/releases/download/"
        "michael/bundle.zip']"
    )

    def test_a_url_indicator_does_not_assert_its_host_domain(self):
        """The exact false positive: a malicious URL on a benign platform."""
        assert not pattern_asserts(self.URL_PATTERN, "domain-name", "github.com")

    def test_the_same_pattern_does_assert_the_full_url(self):
        """Verification must not break the true positive it is guarding."""
        url = (
            "https://github.com/12312d12e1/31/releases/download/michael/"
            "bundle.zip"
        )
        assert pattern_asserts(self.URL_PATTERN, "url", url)

    def test_a_url_indicator_does_not_assert_a_host_ip(self):
        pattern = "[url:value = 'http://120.28.164.12:49818/bin.sh']"
        assert not pattern_asserts(pattern, "ipv4-addr", "120.28.164.12")


# -- Straightforward true positives --------------------------------------


class TestRealMatches:
    @pytest.mark.parametrize("obs_type,value,pattern", [
        ("ipv4-addr", "91.92.242.236", "[ipv4-addr:value = '91.92.242.236']"),
        ("domain-name", "nd.tdpqnf.com", "[domain-name:value = 'nd.tdpqnf.com']"),
        ("url", "http://x.test/a", "[url:value = 'http://x.test/a']"),
        ("email-addr", "a@b.test", "[email-addr:value = 'a@b.test']"),
    ])
    def test_an_exact_assertion_matches(self, obs_type, value, pattern):
        assert pattern_asserts(pattern, obs_type, value)

    def test_aliases_resolve_to_the_same_stix_type(self):
        """ION's own type aliases must verify, or the fix would reject real
        matches arriving from the alert pipeline rather than the UI."""
        pattern = "[ipv4-addr:value = '91.92.242.236']"
        for alias in ("ip", "source_ip", "destination_ip"):
            assert pattern_asserts(pattern, alias, "91.92.242.236"), alias

    def test_hostname_alias_verifies_against_domain_name(self):
        assert pattern_asserts(
            "[domain-name:value = 'evil.test']", "hostname", "evil.test")

    def test_double_quoted_values_are_handled(self):
        """STIX allows either quote style, and feeds are not consistent."""
        assert pattern_asserts(
            '[ipv4-addr:value = "91.92.242.236"]', "ipv4-addr", "91.92.242.236")

    def test_whitespace_around_the_operator_is_irrelevant(self):
        assert pattern_asserts(
            "[ipv4-addr:value='1.2.3.4']", "ipv4-addr", "1.2.3.4")


# -- Compound patterns ---------------------------------------------------


class TestCompoundPatterns:
    def test_an_and_pattern_matches_on_either_side(self):
        pattern = (
            "[domain-name:value = 'evil.test' AND "
            "ipv4-addr:value = '9.9.9.9']"
        )
        assert pattern_asserts(pattern, "domain-name", "evil.test")
        assert pattern_asserts(pattern, "ipv4-addr", "9.9.9.9")

    def test_an_or_of_observations_matches_either(self):
        pattern = "[ipv4-addr:value = '1.1.1.2'] OR [ipv4-addr:value = '1.1.1.3']"
        assert pattern_asserts(pattern, "ipv4-addr", "1.1.1.2")
        assert pattern_asserts(pattern, "ipv4-addr", "1.1.1.3")
        assert not pattern_asserts(pattern, "ipv4-addr", "1.1.1.4")


# -- File hashes ---------------------------------------------------------


class TestFileHashes:
    SHA256 = "a" * 64

    def test_sha256_matches_its_hash_property(self):
        pattern = "[file:hashes.'SHA-256' = '" + self.SHA256 + "']"
        assert pattern_asserts(pattern, "file-sha256", self.SHA256)

    def test_sha256_lookup_does_not_match_an_md5_assertion(self):
        """Different property, different claim. Matching across them would
        report a hash as known-bad on the strength of an unrelated field."""
        pattern = "[file:hashes.MD5 = '" + self.SHA256 + "']"
        assert not pattern_asserts(pattern, "file-sha256", self.SHA256)

    def test_unquoted_hash_key_is_handled(self):
        pattern = "[file:hashes.SHA256 = '" + self.SHA256 + "']"
        assert pattern_asserts(pattern, "file-sha256", self.SHA256)

    def test_a_file_name_assertion_is_not_a_hash_match(self):
        pattern = "[file:name = 'bundle.zip']"
        assert not pattern_asserts(pattern, "file-sha256", self.SHA256)
        assert pattern_asserts(pattern, "file-name", "bundle.zip")


# -- Substring and near-miss rejection -----------------------------------


class TestNoSubstringMatching:
    def test_a_longer_domain_is_not_a_match(self):
        """`evil.test` must not match `notevil.test` or a subdomain of it."""
        assert not pattern_asserts(
            "[domain-name:value = 'notevil.test']", "domain-name", "evil.test")
        assert not pattern_asserts(
            "[domain-name:value = 'evil.test.attacker.cc']",
            "domain-name", "evil.test")

    def test_an_ip_prefix_is_not_a_match(self):
        assert not pattern_asserts(
            "[ipv4-addr:value = '91.92.242.2361']", "ipv4-addr", "91.92.242.236")

    def test_a_value_only_in_the_description_cannot_match(self):
        """The description is not part of the pattern, so a value mentioned
        only there must not verify. This is what made every reporter name
        and reference URL a potential hit."""
        pattern = "[ipv4-addr:value = '9.9.9.9']"
        assert not pattern_asserts(pattern, "ipv4-addr", "abuse_ch")

    def test_case_differences_in_a_domain_still_match(self):
        """DNS is case-insensitive; refusing this would drop true positives."""
        assert pattern_asserts(
            "[domain-name:value = 'Evil.TEST']", "domain-name", "evil.test")

    def test_case_differences_in_a_url_path_do_not_match(self):
        """URL paths are case-sensitive, so this one must stay strict."""
        assert not pattern_asserts(
            "[url:value = 'http://x.test/A']", "url", "http://x.test/a")


# -- Robustness ----------------------------------------------------------


class TestRobustness:
    @pytest.mark.parametrize("pattern", [
        None, "", "   ", "not a pattern at all", "[", "[]",
        "[ipv4-addr:value =]", "[ipv4-addr:value = ']",
    ])
    def test_a_malformed_pattern_is_rejected_not_raised(self, pattern):
        """Patterns come from a third party. A bad one must mean "no match",
        never a 500 on the enrichment endpoint."""
        assert pattern_asserts(pattern, "ipv4-addr", "1.2.3.4") is False

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_an_empty_lookup_value_never_matches(self, value):
        assert pattern_asserts("[ipv4-addr:value = '1.2.3.4']",
                               "ipv4-addr", value) is False

    def test_an_unknown_observable_type_never_matches(self):
        """An unmapped type cannot be verified, so it must not be asserted."""
        assert pattern_asserts(
            "[ipv4-addr:value = '1.2.3.4']", "mystery-type", "1.2.3.4") is False

    def test_the_result_is_a_bool(self):
        """Callers branch on it; a truthy object would hide a mistake."""
        r = pattern_asserts("[ipv4-addr:value = '1.2.3.4']", "ipv4-addr", "1.2.3.4")
        assert r is True
