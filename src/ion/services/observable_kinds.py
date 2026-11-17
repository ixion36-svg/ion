"""One answer to "what kind of observable is this".

ION names the same thing many ways. The extractor keeps the role
(``source_ip``, ``target_user``), STIX-flavoured callers say ``ipv4-addr`` or
``file-sha256``, and the database stores the ``ObservableType`` value. Every
integration that needs the kind used to carry its own partial copy of that
vocabulary, and each copy was missing different names.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, Optional, Union

from ion.models.observable import ObservableType

#: Every type string ION uses, to the kind it denotes. An IP alias names a
#: default family only: ``observable_kind`` lets the value overrule it.
OBSERVABLE_ALIASES: Dict[str, ObservableType] = {
    # IP addresses (role distinguished by context on the link)
    "ip": ObservableType.IPV4,
    "ipv4": ObservableType.IPV4,
    "ipv4-addr": ObservableType.IPV4,
    "source_ip": ObservableType.IPV4,
    "destination_ip": ObservableType.IPV4,
    "host_ip": ObservableType.IPV4,
    "ipv6": ObservableType.IPV6,
    "ipv6-addr": ObservableType.IPV6,
    # Hostnames
    "hostname": ObservableType.HOSTNAME,
    "host": ObservableType.HOSTNAME,
    "source_hostname": ObservableType.HOSTNAME,
    "destination_hostname": ObservableType.HOSTNAME,
    # User accounts (subject/target role distinguished by context)
    "user_account": ObservableType.USER_ACCOUNT,
    "user-account": ObservableType.USER_ACCOUNT,
    "user": ObservableType.USER_ACCOUNT,
    "subject_user": ObservableType.USER_ACCOUNT,
    "target_user": ObservableType.USER_ACCOUNT,
    # URLs and domains
    "url": ObservableType.URL,
    "domain": ObservableType.DOMAIN,
    "domain-name": ObservableType.DOMAIN,
    # File hashes
    "sha256": ObservableType.FILE_HASH_SHA256,
    "sha1": ObservableType.FILE_HASH_SHA1,
    "md5": ObservableType.FILE_HASH_MD5,
    "file-sha256": ObservableType.FILE_HASH_SHA256,
    "file-sha1": ObservableType.FILE_HASH_SHA1,
    "file-md5": ObservableType.FILE_HASH_MD5,
    # File names
    "filename": ObservableType.FILE_NAME,
    "file_name": ObservableType.FILE_NAME,
    "file-name": ObservableType.FILE_NAME,
    # Email
    "email": ObservableType.EMAIL,
    "email-addr": ObservableType.EMAIL,
    # MAC addresses
    "mac": ObservableType.MAC_ADDRESS,
    "mac-addr": ObservableType.MAC_ADDRESS,
    "mac_address": ObservableType.MAC_ADDRESS,
    # Vulnerabilities
    "cve": ObservableType.CVE,
    "vulnerability": ObservableType.CVE,
}

_IP_KINDS = (ObservableType.IPV4, ObservableType.IPV6)


def observable_kind(
    obs_type: Union[str, ObservableType, None], value: Optional[str] = None
) -> Optional[ObservableType]:
    """The canonical kind for a type string, or None when ION has none.

    None is an answer, not an error: process names, command lines and
    registry keys are extracted for display and are not observables of any
    kind. Callers decide whether that is worth a log line.

    ``value`` settles the IP family. ``source_ip`` says where an address was
    seen, not whether it is v4 or v6, and rows stored before this existed
    carry ``ipv4`` for both. A value that does not parse as an address keeps
    the family the alias names.
    """
    if isinstance(obs_type, ObservableType):
        kind: Optional[ObservableType] = obs_type
    else:
        kind = OBSERVABLE_ALIASES.get(str(obs_type or "").strip().lower())
    if kind in _IP_KINDS and value:
        try:
            version = ipaddress.ip_address(str(value).strip()).version
        except ValueError:
            return kind
        return ObservableType.IPV6 if version == 6 else ObservableType.IPV4
    return kind
