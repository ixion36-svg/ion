"""Matching logic for the observable allowlist.

ION already had three per-observable switches -- ``is_whitelisted``,
``is_ignored`` and ``ignore_similarity`` -- but all three are reactive: the
observable has to exist and be wrong before anyone can mark it. On an estate
where a rule fires hundreds of times a day that means marking the same value
over and over, and the record of *why* lives nowhere.

This is the proactive half: values, ranges and domain suffixes that never
become observables in the first place.

Kept free of SQLAlchemy and of ION's services so the matching can be unit
tested on its own and called from inside extraction without dragging a
session in. ``AllowlistRule`` is a plain view over whatever the caller has
-- an ORM row, a dict, a literal -- so the same logic serves the database
list, a test, and any future config-file source.

The design is shaped by how allowlists fail rather than by how they work.
An allowlist stops you seeing something, so the rules here are deliberately
strict: anchored matching, no match across address families, expiry that
actually expires, and a refusal to store a pattern that covers everything.
A too-greedy entry is indistinguishable from a blind spot.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlsplit

__all__ = ["MatchType", "AllowlistRule", "normalise_pattern", "canonical_type"]


class MatchType(str, Enum):
    EXACT = "exact"
    CIDR = "cidr"
    DOMAIN_SUFFIX = "domain_suffix"
    WILDCARD = "wildcard"


#: Context types the extractor emits, mapped to the family an operator
#: thinks in. A rule scoped to "ip" has to cover source_ip, destination_ip
#: and host_ip, or it will look broken to whoever wrote it.
_TYPE_FAMILY = {
    "source_ip": "ip", "destination_ip": "ip", "host_ip": "ip", "ip": "ip",
    "ipv4-addr": "ip", "ipv6-addr": "ip",
    "hostname": "hostname", "source_hostname": "hostname",
    "destination_hostname": "hostname",
    "domain": "domain", "domain-name": "domain",
    "url": "url",
    "target_user": "user", "subject_user": "user", "user_account": "user",
    "user": "user",
    "sha256": "hash", "sha1": "hash", "md5": "hash",
    "file-sha256": "hash", "file-sha1": "hash", "file-md5": "hash",
    "hash": "hash",
    "file_path": "file", "process_path": "file", "file-name": "file",
    "process_name": "process", "parent_process": "process",
    "email": "email", "email-addr": "email",
}


def canonical_type(obs_type: Optional[str]) -> str:
    """Reduce a context type to the family an allowlist rule is scoped by."""
    key = (obs_type or "").strip().lower()
    return _TYPE_FAMILY.get(key, key)


def _host_of(value: str) -> str:
    """The lowercased host of a URL or bare domain, without a trailing dot."""
    v = value.strip()
    if "://" in v:
        host = urlsplit(v).hostname or ""
    else:
        host = v.split("/", 1)[0].split(":", 1)[0]
    return host.lower().rstrip(".")


def _as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Treat a naive datetime as UTC.

    Postgres hands these back naive. Comparing naive to aware raises, and
    an allowlist that raises mid-extraction takes the ingest path with it.
    """
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class AllowlistRule:
    """One allowlist entry, as far as matching is concerned."""

    pattern: str
    match_type: MatchType
    observable_type: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True
    id: Optional[int] = None

    @classmethod
    def from_row(cls, row: Any) -> "AllowlistRule":
        return cls(
            pattern=row.pattern,
            match_type=MatchType(row.match_type),
            observable_type=row.observable_type,
            expires_at=row.expires_at,
            is_active=bool(row.is_active),
            id=getattr(row, "id", None),
        )

    # -- matching --------------------------------------------------------
    def is_live(self, now: Optional[datetime] = None) -> bool:
        if not self.is_active:
            return False
        expires = _as_aware(self.expires_at)
        if expires is None:
            return True
        return (now or datetime.now(timezone.utc)) < expires

    def covers_type(self, obs_type: Optional[str]) -> bool:
        # An unscoped rule covers everything; that is the operator's choice
        # and is visible as such in the list.
        if not self.observable_type:
            return True
        return canonical_type(obs_type) == canonical_type(self.observable_type)

    def matches(self, obs_type: Optional[str], value: Optional[str]) -> bool:
        """Whether this rule suppresses ``value``.

        Never raises. Observable values come from log data and are not all
        well formed; the honest answer for one we cannot parse is "not
        matched", not an exception inside extraction.
        """
        if value is None:
            return False
        text = str(value).strip()
        if not text:
            return False
        if not self.is_live() or not self.covers_type(obs_type):
            return False

        try:
            if self.match_type == MatchType.EXACT:
                return text.lower() == self.pattern.strip().lower()

            if self.match_type == MatchType.CIDR:
                try:
                    addr = ipaddress.ip_address(text)
                    net = ipaddress.ip_network(self.pattern, strict=False)
                except ValueError:
                    # Either the value is not an address or the pattern is
                    # not a network. Both mean "no match" rather than an
                    # error: ip_address also rejects a v4 string against a
                    # v6 network, which is the behaviour we want.
                    return False
                if addr.version != net.version:
                    return False
                return addr in net

            if self.match_type == MatchType.DOMAIN_SUFFIX:
                host = _host_of(text)
                suffix = self.pattern.strip().lower().strip(".")
                if not host or not suffix:
                    return False
                # Label-anchored: corp.example covers mail.corp.example and
                # corp.example itself, never notcorp.example and never
                # corp.example.attacker.test.
                return host == suffix or host.endswith("." + suffix)

            if self.match_type == MatchType.WILDCARD:
                # fnmatch is a glob, so regex metacharacters in the pattern
                # stay literal -- 10.0.0.1 must not match 10x0y0z1 -- and
                # fnmatchcase anchors at both ends, so svc-* does not match
                # nosvc-backup.
                return fnmatch.fnmatch(text.lower(), self.pattern.strip().lower())
        except Exception:  # noqa: BLE001 - matching must never break ingest
            return False
        return False


#: Patterns that would suppress effectively everything. Refused at write
#: time rather than silently accepted: an operator who genuinely wants no
#: observables can turn extraction off, which is at least visible as a
#: setting rather than as one innocuous-looking row in a list.
_CATCH_ALL_WILDCARDS = re.compile(r"^\*+$")


def normalise_pattern(match_type: MatchType, pattern: str) -> str:
    """Validate and canonicalise a pattern, or raise ``ValueError``.

    Canonicalising matters for review as much as for matching: ``10.0.0.5/8``
    is stored as ``10.0.0.0/8`` because the typed form reads as though it
    covers one host when it covers sixteen million.
    """
    text = (pattern or "").strip()
    if not text:
        raise ValueError("A pattern is required")

    if match_type == MatchType.CIDR:
        candidate = text if "/" in text else None
        if candidate is None:
            # A bare address is what operators type; store the /32 or /128
            # so the stored form says exactly what it covers.
            try:
                addr = ipaddress.ip_address(text)
            except ValueError:
                raise ValueError(f"{text!r} is not an IP address or CIDR") from None
            return f"{addr}/{addr.max_prefixlen}"
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            raise ValueError(f"{text!r} is not a valid CIDR") from None
        if net.prefixlen == 0:
            raise ValueError(
                f"{net} covers every address. Turn extraction off instead if "
                f"that is really the intent."
            )
        return str(net)

    if match_type == MatchType.DOMAIN_SUFFIX:
        host = _host_of(text).strip(".")
        if not host:
            raise ValueError(f"{text!r} is not a usable domain suffix")
        return host

    if match_type == MatchType.WILDCARD:
        if _CATCH_ALL_WILDCARDS.match(text):
            raise ValueError(
                "A pattern of only wildcards suppresses every observable. "
                "Turn extraction off instead if that is really the intent."
            )
        return text.lower()

    return text
