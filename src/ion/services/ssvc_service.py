"""SSVC: turn CVSS, EPSS and KEV into a patching decision.

ION already carries three signals about a vulnerability and none of them is a
decision. CVSS scores severity, EPSS estimates the probability of exploitation
and KEV confirms it, and an analyst still has to say whether this one gets
patched tonight or next cycle. SSVC's deployer tree is that step: four inputs,
one of ``defer`` / ``scheduled`` / ``out-of-cycle`` / ``immediate``.

The table is CERT/CC's, transcribed by
``scripts/generate_ssvc_table_json.py`` and read from
``data/ssvc_deployer_table.json``. Nothing here computes the tree.

**One input is evidence and three are assumptions, and they are never mixed.**
Exploitation is derived from what ION knows -- a KEV entry, an in-the-wild
flag, a published exploit. System exposure, automatability and human impact
are properties of the deployment ION has no way to observe, so they come from
Settings (``ssvc_exposure``, ``ssvc_automatable``, ``ssvc_human_impact``, or
the ``ION_SSVC_*`` variable that overrides each) and every result says which
inputs were assumed. A decision
presented as measured, when three quarters of it was a default nobody set, is
worse than no decision: it is a number an engineer will act on.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_TABLE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "ssvc_deployer_table.json"
)

#: Evidence values for the one input ION can derive.
EXPLOIT_ACTIVE = "active"
EXPLOIT_POC = "public poc"
EXPLOIT_NONE = "none"

#: Defaults for the three ION cannot observe. Deliberately middling rather
#: than safe-looking: a default of "small / no / low" would quietly turn every
#: vulnerability into `defer`, which is the one outcome nobody reviews.
_DEFAULTS = {
    "exposure": "controlled",
    "automatable": "no",
    "human_impact": "medium",
}
_ENV = {
    "exposure": "ION_SSVC_EXPOSURE",
    "automatable": "ION_SSVC_AUTOMATABLE",
    "human_impact": "ION_SSVC_HUMAN_IMPACT",
}
#: Each input's setting. get_config() applies the variable above over it.
_SETTING = {
    "exposure": "ssvc_exposure",
    "automatable": "ssvc_automatable",
    "human_impact": "ssvc_human_impact",
}

_TABLE: Optional[Dict[str, Any]] = None
_LOAD_ERROR: Optional[str] = None


def _load() -> Dict[str, Any]:
    global _TABLE, _LOAD_ERROR
    if _TABLE is None:
        try:
            with open(_TABLE_PATH, encoding="utf-8") as fh:
                _TABLE = json.load(fh)
            _LOAD_ERROR = None
        except Exception as exc:
            logger.warning("SSVC table unreadable at %s: %s", _TABLE_PATH, exc)
            _TABLE = {}
            _LOAD_ERROR = str(exc)
    return _TABLE


def reset_cache() -> None:
    """Drop the cached table. For tests pointing at a different file."""
    global _TABLE, _LOAD_ERROR
    _TABLE = None
    _LOAD_ERROR = None


def status() -> Dict[str, Any]:
    """Whether the table loaded, its version, and the source it came from."""
    table = _load()
    return {
        "loaded": bool(table),
        "table_version": table.get("table_version"),
        "source": table.get("source"),
        "rows": table.get("rows"),
        "outcomes": table.get("outcomes", []),
        "error": _LOAD_ERROR,
    }


def decision_points() -> Dict[str, List[str]]:
    """The legal value of each input, as the published table defines them."""
    return _load().get("decision_points", {})


def configured_inputs() -> Dict[str, Dict[str, Any]]:
    """The three deployment inputs, their value, and where it came from.

    Read from Settings, where the ``ION_SSVC_*`` variable overrides each.
    A value the table does not know is refused rather than passed into a
    lookup that would simply miss. A missing row and a configured row are not
    distinguishable downstream, so the bad value is caught here where it can
    still be named, and reported as ``invalid``.
    """
    from ion.core.config import get_config

    config = get_config()
    points = decision_points()
    out: Dict[str, Dict[str, Any]] = {}
    for key, env_name in _ENV.items():
        setting = _SETTING[key]
        raw = str(getattr(config, setting, "") or "").strip().lower()
        legal = points.get(key, [])
        invalid = None
        if raw and legal and raw not in legal:
            logger.warning("%s=%r is not one of %s; using the default %r",
                           setting, raw, legal, _DEFAULTS[key])
            invalid, raw = raw, ""
        out[key] = {
            "value": raw or _DEFAULTS[key],
            "configured": bool(raw),
            "setting": setting,
            "env": env_name,
            "invalid": invalid,
            "legal": list(legal),
        }
    return out


def exploitation_for(
    vuln: Any, kev_entry: Any = None, kev_age_days: Optional[int] = None
) -> Dict[str, Any]:
    """The one input ION can derive, with the evidence it rests on.

    KEV outranks the local flags: it is somebody else's confirmed observation
    of exploitation, where `exploit_in_the_wild` is whatever an analyst ticked.

    `none` is the weakest claim here and is reported with the catalogue's age,
    because "not in KEV" means "not in a catalogue last refreshed N days ago"
    and an analyst reading `defer` deserves to know which.
    """
    if kev_entry is not None:
        return {"value": EXPLOIT_ACTIVE, "measured": True,
                "basis": "listed in the CISA KEV catalogue"}
    if getattr(vuln, "exploit_in_the_wild", False):
        return {"value": EXPLOIT_ACTIVE, "measured": True,
                "basis": "flagged exploited in the wild"}
    if getattr(vuln, "exploit_available", False):
        return {"value": EXPLOIT_POC, "measured": True,
                "basis": "a public exploit is recorded"}
    stale = ""
    if kev_age_days is not None:
        stale = f", against a KEV catalogue {kev_age_days} days old"
    return {"value": EXPLOIT_NONE, "measured": True,
            "basis": f"no exploit recorded and not in KEV{stale}"}


def decide(exploitation: str, exposure: str, automatable: str,
           human_impact: str) -> Optional[str]:
    """Look the four inputs up in the published tree.

    Returns None when the table did not load or the combination is absent --
    never a default outcome. Every outcome in this tree is an instruction to
    do something at a particular speed, so inventing one is worse than
    declining to answer.
    """
    table = _load().get("table", {})
    key = "|".join(str(v).strip().lower() for v in
                   (exploitation, exposure, automatable, human_impact))
    return table.get(key)


def assess(vuln: Any, kev_entry: Any = None,
           kev_age_days: Optional[int] = None) -> Dict[str, Any]:
    """The decision for one vulnerability, and what it rests on."""
    table_status = status()
    exploitation = exploitation_for(vuln, kev_entry, kev_age_days)
    assumed = configured_inputs()
    unset = [a["env"] for a in assumed.values() if not a["configured"]]
    unset_settings = [a["setting"] for a in assumed.values() if not a["configured"]]

    if not table_status["loaded"]:
        return {
            "decision": None,
            "reason": "the SSVC table could not be read",
            "exploitation": exploitation,
            "assumed": assumed,
            "assumed_count": len(unset),
            "unset_env": unset,
            "unset_settings": unset_settings,
            "table": table_status,
        }

    decision = decide(
        exploitation["value"],
        assumed["exposure"]["value"],
        assumed["automatable"]["value"],
        assumed["human_impact"]["value"],
    )
    return {
        "decision": decision,
        "reason": None if decision else
                  "no row in the published tree for this combination",
        "exploitation": exploitation,
        "assumed": assumed,
        # Surfaced as a count so a caller cannot render the decision without
        # having had the chance to say how much of it was assumed.
        "assumed_count": sum(1 for a in assumed.values() if not a["configured"]),
        "unset_env": unset,
        "unset_settings": unset_settings,
        "table": table_status,
    }
