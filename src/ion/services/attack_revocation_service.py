"""Resolve retired ATT&CK technique ids to the ids that replaced them.

MITRE revokes technique ids and points them at a replacement. v18/v19 moved
the whole `T1562` *Impair Defenses* sub-tree to `T1685`/`T1686`/`T1688`-`T1690`,
and `T1070.001`/`T1070.002` to `T1685.005`/`T1685.006`.

Two sets of technique ids meet all over ION -- a control's mapped techniques
against the ones TIDE has rules for, an alert's tags against a template's --
and after a catalogue bump the two sides can be written in different ATT&CK
generations. Intersecting them then misses, quietly, and the result reads as
"no coverage" rather than "ids from different versions". Normalising both sides
through this map is what stops that.

Read-only over `data/attack_revocations.json`, written by
`scripts/generate_attack_techniques_json.py`.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set

logger = logging.getLogger(__name__)

_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_revocations.json"

#: A revocation chain longer than this is a cycle in the snapshot, not a
#: history. Bail rather than spin.
_MAX_HOPS = 10

_DATA: Optional[Dict[str, Any]] = None
_LOAD_ERROR: Optional[str] = None


def _load() -> Dict[str, Any]:
    global _DATA, _LOAD_ERROR
    if _DATA is None:
        try:
            with open(_PATH, encoding="utf-8") as fh:
                _DATA = json.load(fh)
            _LOAD_ERROR = None
        except Exception as exc:
            logger.warning("ATT&CK revocation map unreadable at %s: %s", _PATH, exc)
            _DATA = {}
            _LOAD_ERROR = str(exc)
    return _DATA


def reset_cache() -> None:
    """Drop the cached map. For tests pointing at a different file."""
    global _DATA, _LOAD_ERROR
    _DATA = None
    _LOAD_ERROR = None


def status() -> Dict[str, Any]:
    """Whether the map loaded, which ATT&CK version, and how many entries."""
    data = _load()
    return {
        "loaded": bool(data),
        "attack_version": data.get("attack_version"),
        "count": data.get("count", 0),
        "error": _LOAD_ERROR,
    }


def _map() -> Dict[str, Dict[str, str]]:
    return _load().get("revocations", {})


def resolve(technique_id: str) -> str:
    """The current id for a technique, following revocation chains.

    Returns the input unchanged when it is current, unknown, or the map did
    not load -- never None, so callers can resolve unconditionally.
    """
    if not technique_id:
        return technique_id
    current = technique_id.strip().upper()
    mapping = _map()
    seen: Set[str] = {current}
    for _ in range(_MAX_HOPS):
        entry = mapping.get(current)
        if not entry:
            return current
        nxt = entry.get("replacement")
        if not nxt or nxt in seen:
            # A cycle, or a dangling replacement. Stop on the last good id.
            return current
        seen.add(nxt)
        current = nxt
    logger.warning("Revocation chain for %s exceeded %d hops", technique_id, _MAX_HOPS)
    return current


def resolve_all(technique_ids: Iterable[str]) -> Set[str]:
    """Resolve a collection of ids, deduped. Empty input gives an empty set."""
    return {resolve(t) for t in technique_ids if t}


def is_revoked(technique_id: str) -> bool:
    """Whether this id has been retired in favour of another."""
    return bool(technique_id) and technique_id.strip().upper() in _map()


def replacement_name(technique_id: str) -> Optional[str]:
    """The name of the technique that replaced this id, if it was revoked."""
    entry = _map().get((technique_id or "").strip().upper())
    return entry.get("name") if entry else None
