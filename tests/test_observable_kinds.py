"""Every name ION uses for an observable resolves to one kind.

The OpenCTI lookup, the alert page and the triage enricher each used to hold
their own partial list of these names, and each list was missing different
ones. These tests hold the single table to the whole vocabulary, so a new
extractor type or a new ``ObservableType`` cannot arrive without a kind and
an OpenCTI target.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.models.observable import ObservableType
from ion.services.observable_extractor import ENRICHABLE_TYPES
from ion.services.observable_kinds import observable_kind
from ion.services.observable_service import DISPLAY_ONLY_TYPES
from ion.services.opencti_service import OPENCTI_TARGETS, opencti_target

T = ObservableType


@pytest.mark.parametrize("alias,kind", [
    ("ip", T.IPV4), ("ipv4", T.IPV4), ("ipv4-addr", T.IPV4),
    ("source_ip", T.IPV4), ("destination_ip", T.IPV4), ("host_ip", T.IPV4),
    ("ipv6", T.IPV6), ("ipv6-addr", T.IPV6),
    ("hostname", T.HOSTNAME), ("host", T.HOSTNAME),
    ("source_hostname", T.HOSTNAME), ("destination_hostname", T.HOSTNAME),
    ("user_account", T.USER_ACCOUNT), ("user-account", T.USER_ACCOUNT),
    ("user", T.USER_ACCOUNT), ("subject_user", T.USER_ACCOUNT),
    ("target_user", T.USER_ACCOUNT),
    ("url", T.URL), ("domain", T.DOMAIN), ("domain-name", T.DOMAIN),
    ("sha256", T.FILE_HASH_SHA256), ("file-sha256", T.FILE_HASH_SHA256),
    ("sha1", T.FILE_HASH_SHA1), ("file-sha1", T.FILE_HASH_SHA1),
    ("md5", T.FILE_HASH_MD5), ("file-md5", T.FILE_HASH_MD5),
    ("filename", T.FILE_NAME), ("file_name", T.FILE_NAME), ("file-name", T.FILE_NAME),
    ("email", T.EMAIL), ("email-addr", T.EMAIL),
    ("mac", T.MAC_ADDRESS), ("mac-addr", T.MAC_ADDRESS), ("mac_address", T.MAC_ADDRESS),
    ("cve", T.CVE), ("vulnerability", T.CVE),
])
def test_every_alias_names_its_kind(alias, kind):
    assert observable_kind(alias) is kind


def test_case_and_padding_do_not_change_the_kind():
    assert observable_kind("  Source_IP ") is T.IPV4


@pytest.mark.parametrize("alias", [
    "ip", "ipv4", "ipv4-addr", "source_ip", "destination_ip", "host_ip",
    "ipv6", "ipv6-addr", T.IPV4, T.IPV6,
])
class TestTheValueDecidesTheIpFamily:
    def test_an_ipv6_value_is_ipv6(self, alias):
        assert observable_kind(alias, "2001:db8:85a3::8a2e:370:7334") is T.IPV6

    def test_an_ipv4_value_is_ipv4(self, alias):
        assert observable_kind(alias, " 185.220.101.34 ") is T.IPV4


def test_a_value_that_is_not_an_address_keeps_the_family_the_alias_names():
    assert observable_kind("ipv6-addr", "not-an-address") is T.IPV6
    assert observable_kind("source_ip", "10.0.0.0/8") is T.IPV4


def test_the_value_only_ever_decides_between_the_ip_families():
    """A hash that happens to parse as nothing, or a domain that looks like
    an address, stays the kind its type says."""
    assert observable_kind("domain", "2001:db8::1") is T.DOMAIN
    assert observable_kind("hostname", "10.0.0.1") is T.HOSTNAME


@pytest.mark.parametrize("unknown", ["process_name", "command_line", "", None, "nonsense"])
def test_a_type_with_no_kind_is_none(unknown):
    assert observable_kind(unknown, "x") is None
    assert opencti_target(unknown, "x") is None


@pytest.mark.parametrize("kind", list(ObservableType))
class TestNoKindIsLeftOut:
    def test_its_stored_value_is_an_alias_of_itself(self, kind):
        """The database hands the enum value back, so it has to resolve."""
        assert observable_kind(kind.value) is kind

    def test_it_has_an_opencti_target(self, kind):
        assert kind in OPENCTI_TARGETS


def test_every_type_the_extractor_emits_is_a_kind_or_display_only():
    unaccounted = {
        t for t in ENRICHABLE_TYPES
        if observable_kind(t) is None and t not in DISPLAY_ONLY_TYPES
    }
    assert unaccounted == set()
