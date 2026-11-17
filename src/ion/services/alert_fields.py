"""Which fields of an alert document are evidence.

A Kibana security alert is three things in one document: the matched event,
the whole definition of the rule that fired, and the detection engine's own
record keeping. Only the first is something the host did.

``ALERT_FIELD_ROLES`` is the one place that says which is which. It names
what is *not* evidence and leaves everything else as evidence, because the
free-text IOC walker has to read fields nobody listed: a vendor's own
``winlog.event_data`` keys, a message, a decoded command line. An allowlist
there would lose real sightings every time a new log source arrived. The
field-map extractor in ``observable_extractor`` is the opposite case: it
names each ECS field it reads, and none of them is listed here.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Tuple

Path = Tuple[str, ...]


class FieldRole(Enum):
    EVIDENCE = "evidence"
    #: Written by the rule author: name, description, investigation guide,
    #: references, false positives, tags, setup, author, licence, query.
    RULE_METADATA = "rule_metadata"
    #: Minted by the detection engine or by ION about the alert itself.
    ALERT_BOOKKEEPING = "alert_bookkeeping"


#: Subtree -> role, matched on the path from the root of the event document.
#:
#: Whole subtrees rather than leaf names: Kibana mirrors the rule under
#: ``.parameters``, so a leaf list lets the same prose back in by another
#: path, and a name match would discard a process called ``rule.exe``.
#:
#: ``kibana.alert`` itself is not listed. ``reason``, ``threshold_result``,
#: ``new_terms``, ``suppression.terms`` and ``original_event`` are generated
#: per alert from the matched events and are evidence.
ALERT_FIELD_ROLES: Dict[Path, FieldRole] = {
    ("kibana", "alert", "rule"): FieldRole.RULE_METADATA,
    ("signal", "rule"): FieldRole.RULE_METADATA,       # the pre-8.x alert format
    ("rule",): FieldRole.RULE_METADATA,                # ECS, and forwarders that flatten to the root
    # Alert and group ids are 64-hex strings, which read as SHA-256 hashes.
    ("_id",): FieldRole.ALERT_BOOKKEEPING,
    ("_index",): FieldRole.ALERT_BOOKKEEPING,
    ("kibana", "alert", "uuid"): FieldRole.ALERT_BOOKKEEPING,
    ("kibana", "alert", "group"): FieldRole.ALERT_BOOKKEEPING,
    ("kibana", "alert", "ancestors"): FieldRole.ALERT_BOOKKEEPING,
    # ION's own verdict and summary, written back by a previous investigation.
    ("ion",): FieldRole.ALERT_BOOKKEEPING,
}


def field_role(path: Path) -> FieldRole:
    """The role of the field at ``path``, by the subtree it sits in."""
    for end in range(1, len(path) + 1):
        role = ALERT_FIELD_ROLES.get(path[:end])
        if role is not None:
            return role
    return FieldRole.EVIDENCE


def event_document(alert: Dict[str, Any]) -> Dict[str, Any]:
    """The Elasticsearch document inside whichever shape a caller holds.

    ``ElasticsearchAlert.to_dict()`` puts the document under ``raw_data``
    and surrounds it with a projection: ``title`` is the rule name, ``tags``
    are the rule's, and ``message`` falls back to the rule description.
    Every projected value that is evidence is also in the document, so the
    document alone is what gets read, from its own root.
    """
    raw = alert.get("raw_data")
    return raw if isinstance(raw, dict) else alert
