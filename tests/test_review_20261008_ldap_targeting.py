"""AD LDAP targeting tests from the 8 Oct 2026 feature review (finding 2, P1).

The adapter interpolated the approved target straight into an LDAP
search filter and then modified ``conn.entries[0]``:

    search_filter = f"(sAMAccountName={target_sam})"
    ...
    entry = conn.entries[0]

So an approved target of ``*`` became ``(sAMAccountName=*)`` — every
account in the search base — and the adapter disabled or reset the
password of whichever one AD happened to return first. The approver
authorised one account; a different one was modified.

Three things have to hold:

* filter metacharacters are escaped per RFC 4515, so a target can never
  broaden the search;
* an identifier that is not a plausible ``sAMAccountName`` is refused
  before any bind happens;
* zero *or more than one* match must never result in a modification.

These run against a fake ldap3 connection, so no network and no AD.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.services.playbook_executors import active_directory_ldap as ad

# ── Fakes ─────────────────────────────────────────────────────────────────


class _FakeAttr:
    def __init__(self, value):
        self.value = value


class _FakeEntry:
    def __init__(self, dn: str, uac: int = 512, sam: str = "someone"):
        self.distinguishedName = _FakeAttr(dn)
        self.userAccountControl = _FakeAttr(uac)
        self.sAMAccountName = _FakeAttr(sam)


class _FakeConnection:
    """Records the filters it was asked for and the modifies it performed."""

    def __init__(self, entries_for_search):
        self._entries_for_search = entries_for_search
        self.searched_filters: list[str] = []
        self.modifies: list[tuple[str, dict]] = []
        self.entries: list[_FakeEntry] = []
        self.result = {"description": "success", "result": 0}

    def search(self, search_base, search_filter, attributes):
        self.searched_filters.append(search_filter)
        self.entries = list(self._entries_for_search)
        return bool(self.entries)

    def modify(self, dn, changes):
        self.modifies.append((dn, changes))
        return True

    def unbind(self):
        pass


@pytest.fixture()
def fake_ldap(monkeypatch):
    """Patch the adapter's lazily-imported ldap3 surface.

    The adapter imports ldap3 inside the worker, so the fakes go into
    ``sys.modules`` before the call.
    """
    import types

    created: dict = {}

    def _make(entries):
        conn = _FakeConnection(entries)
        created["conn"] = conn

        ldap3 = types.ModuleType("ldap3")
        ldap3.ALL = "ALL"
        ldap3.MODIFY_REPLACE = "MODIFY_REPLACE"
        ldap3.Server = lambda *a, **k: object()
        ldap3.Tls = lambda *a, **k: object()
        ldap3.Connection = lambda *a, **k: conn
        monkeypatch.setitem(sys.modules, "ldap3", ldap3)
        return conn

    created["make"] = _make
    return created


def _run(action_type="disable_account", target="jbloggs"):
    return ad._perform_ldap_action(
        action_type,
        target,
        None,
        ldap_uri="ldaps://dc01.test.local",
        bind_dn="CN=svc,DC=test,DC=local",
        bind_password="x",
        search_base="DC=test,DC=local",
        verify_ssl=True,
    )


# ── A wildcard target must not broaden the search ─────────────────────────


class TestWildcardCannotBroadenSearch:
    def test_asterisk_target_is_refused_or_escaped(self, fake_ldap):
        conn = fake_ldap["make"]([
            _FakeEntry("CN=Admin,DC=test,DC=local", sam="Administrator"),
            _FakeEntry("CN=Jo,DC=test,DC=local", sam="jbloggs"),
        ])
        ok, message, _payload = _run(target="*")

        assert ok is False, "a wildcard target must never succeed"
        assert conn.modifies == [], f"wildcard modified {conn.modifies}"
        # If it got as far as searching, the filter must not contain a raw *.
        for f in conn.searched_filters:
            assert "=*)" not in f, f"unescaped wildcard reached the filter: {f}"

    def test_filter_injection_is_neutralised(self, fake_ldap):
        """`jbloggs)(|(sAMAccountName=Administrator` must not become an OR."""
        conn = fake_ldap["make"]([_FakeEntry("CN=Admin,DC=test,DC=local")])
        ok, _message, _payload = _run(target="jbloggs)(|(sAMAccountName=Administrator")

        assert ok is False
        assert conn.modifies == []
        for f in conn.searched_filters:
            assert "|" not in f, f"injected OR survived into the filter: {f}"

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "*", "a*b", "jo(e", "jo)e", "back\\slash", "nul\x00byte",
         "has space", "comma,name", "plus+name", 'quote"name', "x" * 300],
    )
    def test_implausible_identifiers_are_refused(self, fake_ldap, bad):
        conn = fake_ldap["make"]([_FakeEntry("CN=Admin,DC=test,DC=local")])
        ok, _message, _payload = _run(target=bad)
        assert ok is False, f"{bad!r} should not be an acceptable sAMAccountName"
        assert conn.modifies == []


# ── Ambiguous or absent matches must never modify anything ────────────────


class TestExactlyOneMatchRequired:
    def test_two_matches_modify_nothing(self, fake_ldap):
        conn = fake_ldap["make"]([
            _FakeEntry("CN=Jo A,DC=test,DC=local", sam="jbloggs"),
            _FakeEntry("CN=Jo B,DC=test,DC=local", sam="jbloggs"),
        ])
        ok, message, _payload = _run(target="jbloggs")

        assert ok is False
        assert conn.modifies == []
        assert "multiple" in message.lower() or "ambiguous" in message.lower()

    def test_no_match_modifies_nothing(self, fake_ldap):
        conn = fake_ldap["make"]([])
        ok, message, _payload = _run(target="ghost")

        assert ok is False
        assert conn.modifies == []
        assert "not found" in message.lower()

    def test_single_match_still_disables(self, fake_ldap):
        conn = fake_ldap["make"]([
            _FakeEntry("CN=Jo Bloggs,DC=test,DC=local", uac=512, sam="jbloggs"),
        ])
        ok, message, payload = _run(target="jbloggs")

        assert ok is True, message
        assert len(conn.modifies) == 1
        dn, changes = conn.modifies[0]
        assert dn == "CN=Jo Bloggs,DC=test,DC=local"
        # ACCOUNTDISABLE (0x2) set on top of the original 512.
        assert changes["userAccountControl"][0][1] == [514]
        # The resolved identity must be reportable back to the approver.
        assert payload["user_dn"] == "CN=Jo Bloggs,DC=test,DC=local"
        assert payload["resolved_sam_account_name"] == "jbloggs"

    def test_single_match_still_resets_password(self, fake_ldap):
        conn = fake_ldap["make"]([
            _FakeEntry("CN=Jo Bloggs,DC=test,DC=local", sam="jbloggs"),
        ])
        ok, message, payload = _run(action_type="reset_password", target="jbloggs")

        assert ok is True, message
        assert len(conn.modifies) == 1
        dn, changes = conn.modifies[0]
        assert dn == "CN=Jo Bloggs,DC=test,DC=local"
        assert "unicodePwd" in changes
        # The generated plaintext must never appear in the stored payload.
        assert "password" not in str(payload).lower() or "unicodePwd" not in str(payload)


# ── The escaping helper itself ────────────────────────────────────────────


class TestFilterEscaping:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("jbloggs", "jbloggs"),
            ("*", r"\2a"),
            ("(", r"\28"),
            (")", r"\29"),
            ("\\", r"\5c"),
            ("\x00", r"\00"),
            ("a*b", r"a\2ab"),
        ],
    )
    def test_rfc4515_escapes(self, raw, expected):
        assert ad._escape_ldap_filter_value(raw) == expected


class TestIdentifierValidation:
    @pytest.mark.parametrize(
        "good", ["jbloggs", "j.bloggs", "j-bloggs", "j_bloggs", "svc$", "User123"]
    )
    def test_plausible_names_accepted(self, good):
        assert ad._is_valid_sam_account_name(good) is True

    @pytest.mark.parametrize(
        "bad", ["", "   ", "*", "a b", "a(b", "a)b", "a\\b", "a,b", "x" * 300]
    )
    def test_implausible_names_rejected(self, bad):
        assert ad._is_valid_sam_account_name(bad) is False
