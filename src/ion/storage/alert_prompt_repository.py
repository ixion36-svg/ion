"""Repository for AlertPromptTemplate operations."""

from __future__ import annotations

import json
import logging
import re
from typing import Optional, List

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.alert_prompt import AlertPromptTemplate

logger = logging.getLogger(__name__)


def _dumps(values: Optional[list]) -> Optional[str]:
    if values is None:
        return None
    if not isinstance(values, list):
        values = list(values)
    return json.dumps(values)


def _loads(raw: Optional[str]) -> list:
    if not raw:
        return []
    try:
        val = json.loads(raw)
        return val if isinstance(val, list) else []
    except Exception:
        return []


class AlertPromptRepository:
    """CRUD + matching for AlertPromptTemplate rows."""

    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------ CRUD

    def create(
        self,
        name: str,
        prompt_text: str,
        description: Optional[str] = None,
        enabled: bool = True,
        rule_ids: Optional[List[str]] = None,
        rule_groups: Optional[List[str]] = None,
        rule_id_pattern: Optional[str] = None,
        mitre_techniques: Optional[List[str]] = None,
        mitre_tactics: Optional[List[str]] = None,
        priority: int = 100,
        investigation_checklist_text: Optional[str] = None,
        severity_hint: Optional[str] = None,
        expected_outputs: Optional[List[str]] = None,
        created_by_id: Optional[int] = None,
    ) -> AlertPromptTemplate:
        tmpl = AlertPromptTemplate(
            name=name,
            description=description,
            enabled=enabled,
            rule_ids_json=_dumps(rule_ids),
            rule_groups_json=_dumps(rule_groups),
            rule_id_pattern=rule_id_pattern,
            mitre_techniques_json=_dumps(mitre_techniques),
            mitre_tactics_json=_dumps(mitre_tactics),
            priority=priority,
            prompt_text=prompt_text,
            investigation_checklist_text=investigation_checklist_text,
            severity_hint=severity_hint,
            expected_outputs_json=_dumps(expected_outputs),
            created_by_id=created_by_id,
        )
        self.session.add(tmpl)
        self.session.flush()
        return tmpl

    def get_by_id(self, template_id: int) -> Optional[AlertPromptTemplate]:
        return self.session.get(AlertPromptTemplate, template_id)

    def get_by_name(self, name: str) -> Optional[AlertPromptTemplate]:
        stmt = select(AlertPromptTemplate).where(AlertPromptTemplate.name == name)
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(self, enabled_only: bool = False) -> List[AlertPromptTemplate]:
        stmt = select(AlertPromptTemplate)
        if enabled_only:
            stmt = stmt.where(AlertPromptTemplate.enabled == True)  # noqa: E712
        stmt = stmt.order_by(
            AlertPromptTemplate.priority.asc(),
            AlertPromptTemplate.updated_at.desc(),
        )
        return list(self.session.execute(stmt).scalars().all())

    def update(
        self,
        tmpl: AlertPromptTemplate,
        **fields,
    ) -> AlertPromptTemplate:
        """Update arbitrary fields. List fields are JSON-encoded transparently."""
        list_fields = {
            "rule_ids",
            "rule_groups",
            "expected_outputs",
            "mitre_techniques",
            "mitre_tactics",
        }
        for key, value in fields.items():
            if value is None and key not in list_fields:
                # Preserve None-means-no-change for scalar fields
                continue
            if key in list_fields:
                setattr(tmpl, f"{key}_json", _dumps(value))
            elif hasattr(tmpl, key):
                setattr(tmpl, key, value)
        self.session.flush()
        return tmpl

    def delete(self, tmpl: AlertPromptTemplate) -> None:
        self.session.delete(tmpl)
        self.session.flush()

    def count(self) -> int:
        from sqlalchemy import func
        return self.session.execute(
            select(func.count(AlertPromptTemplate.id))
        ).scalar() or 0

    # -------------------------------------------------------------- matching

    @staticmethod
    def _extract_rule_id(alert: dict) -> Optional[str]:
        """Pull the rule id out of an alert dict across known shapes."""
        if not alert:
            return None
        # Flat shapes
        for key in ("rule_id", "ruleId"):
            val = alert.get(key)
            if val:
                return str(val)
        # Nested rule dict (ES/Elastic SIEM style)
        rule = alert.get("rule")
        if isinstance(rule, dict):
            for key in ("id", "rule_id", "ruleId"):
                val = rule.get(key)
                if val:
                    return str(val)
        # Elastic Security "kibana.alert.rule.rule_id" flattened key
        flat = alert.get("kibana.alert.rule.rule_id") or alert.get(
            "kibana.alert.rule.uuid"
        )
        if flat:
            return str(flat)
        # raw_data fallback
        raw = alert.get("raw_data")
        if isinstance(raw, dict):
            nested_rule = raw.get("rule")
            if isinstance(nested_rule, dict):
                for key in ("id", "rule_id", "ruleId"):
                    val = nested_rule.get(key)
                    if val:
                        return str(val)
            flat = raw.get("kibana.alert.rule.rule_id") or raw.get(
                "kibana.alert.rule.uuid"
            )
            if flat:
                return str(flat)
        return None

    @staticmethod
    def _extract_mitre_techniques(alert: dict) -> List[str]:
        """Pull MITRE ATT&CK technique IDs from an alert dict across known shapes.

        Returns a de-duplicated, order-preserving list of uppercase technique
        IDs (e.g. ``["T1059", "T1059.001"]``). Handles:

        - Elastic Security: ``kibana.alert.rule.threat[].technique[].id``
          (and nested under ``technique[].subtechnique[].id`` when present).
        - Wazuh/Sigma: ``rule.mitre.id`` (list), or the string form ``rule.mitre``.
        - Flat keys: ``mitre_techniques``, ``techniques``.
        - ``raw_data`` fallbacks for all of the above.
        """
        if not alert:
            return []
        out: list[str] = []

        def _add_many(values) -> None:
            if not values:
                return
            if isinstance(values, str):
                values = [values]
            for v in values:
                if not v:
                    continue
                s = str(v).strip().upper()
                # Defensively ignore tactic IDs accidentally placed in a
                # techniques list (tactics start with TA, techniques with T
                # followed by a digit).
                if s.startswith("TA"):
                    continue
                if s.startswith("T") and len(s) > 1 and s[1].isdigit():
                    out.append(s)

        def _from_elastic_threat(threat_list) -> None:
            if not isinstance(threat_list, list):
                return
            for entry in threat_list:
                if not isinstance(entry, dict):
                    continue
                tech = entry.get("technique")
                if isinstance(tech, list):
                    for t in tech:
                        if isinstance(t, dict):
                            _add_many([t.get("id")])
                            sub = t.get("subtechnique")
                            if isinstance(sub, list):
                                _add_many([s.get("id") for s in sub if isinstance(s, dict)])

        # Elastic shape
        flat = alert.get("kibana.alert.rule.threat")
        _from_elastic_threat(flat)

        # Wazuh/Sigma shape: rule.mitre.id
        rule = alert.get("rule")
        if isinstance(rule, dict):
            mitre = rule.get("mitre")
            if isinstance(mitre, dict):
                _add_many(mitre.get("id") or mitre.get("technique"))
            elif isinstance(mitre, list):
                _add_many(mitre)

        # Flat convenience keys
        _add_many(alert.get("mitre_techniques"))
        _add_many(alert.get("techniques"))

        # raw_data fallback
        raw = alert.get("raw_data")
        if isinstance(raw, dict):
            _from_elastic_threat(raw.get("kibana.alert.rule.threat"))
            r = raw.get("rule")
            if isinstance(r, dict):
                m = r.get("mitre")
                if isinstance(m, dict):
                    _add_many(m.get("id") or m.get("technique"))
                elif isinstance(m, list):
                    _add_many(m)
            _add_many(raw.get("mitre_techniques"))

        # De-dup preserving order
        seen, dedup = set(), []
        for t in out:
            if t not in seen:
                seen.add(t)
                dedup.append(t)
        return dedup

    @staticmethod
    def _extract_mitre_tactics(alert: dict) -> List[str]:
        """Pull MITRE ATT&CK tactic IDs or names from an alert dict.

        Returns a de-duplicated list. Values may be either TAXXXX IDs
        (preferred, e.g. ``"TA0002"``) or lowercase tactic names
        (e.g. ``"execution"``). Matching against templates is case- and
        form-insensitive (see :meth:`find_matching`).
        """
        if not alert:
            return []
        out: list[str] = []

        def _add_many(values) -> None:
            if not values:
                return
            if isinstance(values, str):
                values = [values]
            for v in values:
                if not v:
                    continue
                out.append(str(v).strip())

        # Elastic shape
        flat = alert.get("kibana.alert.rule.threat")
        if isinstance(flat, list):
            for entry in flat:
                if isinstance(entry, dict):
                    tac = entry.get("tactic")
                    if isinstance(tac, dict):
                        _add_many([tac.get("id"), tac.get("name")])

        # Wazuh/Sigma
        rule = alert.get("rule")
        if isinstance(rule, dict):
            mitre = rule.get("mitre")
            if isinstance(mitre, dict):
                _add_many(mitre.get("tactic") or mitre.get("tactics"))

        # Flat
        _add_many(alert.get("mitre_tactics"))
        _add_many(alert.get("tactics"))

        # raw_data fallback
        raw = alert.get("raw_data")
        if isinstance(raw, dict):
            f = raw.get("kibana.alert.rule.threat")
            if isinstance(f, list):
                for entry in f:
                    if isinstance(entry, dict):
                        tac = entry.get("tactic")
                        if isinstance(tac, dict):
                            _add_many([tac.get("id"), tac.get("name")])
            r = raw.get("rule")
            if isinstance(r, dict):
                m = r.get("mitre")
                if isinstance(m, dict):
                    _add_many(m.get("tactic") or m.get("tactics"))
            _add_many(raw.get("mitre_tactics"))

        seen, dedup = set(), []
        for t in out:
            key = t.lower()
            if key and key not in seen:
                seen.add(key)
                dedup.append(t)
        return dedup

    @staticmethod
    def _extract_rule_groups(alert: dict) -> List[str]:
        """Pull rule.groups list out of an alert dict."""
        if not alert:
            return []
        groups: list = []
        rule = alert.get("rule")
        if isinstance(rule, dict):
            g = rule.get("groups")
            if isinstance(g, list):
                groups.extend(str(x) for x in g)
        g = alert.get("rule_groups") or alert.get("groups")
        if isinstance(g, list):
            groups.extend(str(x) for x in g)
        raw = alert.get("raw_data")
        if isinstance(raw, dict):
            nested_rule = raw.get("rule")
            if isinstance(nested_rule, dict):
                g = nested_rule.get("groups")
                if isinstance(g, list):
                    groups.extend(str(x) for x in g)
            g = raw.get("rule_groups")
            if isinstance(g, list):
                groups.extend(str(x) for x in g)
        # De-dup preserving order
        seen, out = set(), []
        for g in groups:
            if g and g not in seen:
                seen.add(g)
                out.append(g)
        return out

    def find_matching(self, alert: dict) -> Optional[AlertPromptTemplate]:
        """Return the best-matching enabled template for the given alert.

        Match priority (first non-empty tier wins; within a tier the templates
        are already globally sorted by priority asc, updated_at desc):

          1. explicit rule_id in ``rule_ids_json``
          2. regex match on ``rule_id_pattern``
          3. MITRE technique overlap — **parent→sub tolerant**: a template
             listing ``T1059`` matches an alert tagged ``T1059.001``. The
             opposite direction (template ``T1059.001``, alert ``T1059``) is
             also tolerated because parent-only tagging is common on Wazuh.
          4. MITRE tactic overlap (TAxxxx id OR lowercase name)
          5. ``rule.groups`` overlap with ``rule_groups_json``
        """
        if not alert:
            return None

        rule_id = self._extract_rule_id(alert)
        alert_groups = set(self._extract_rule_groups(alert))
        alert_techniques = [t.upper() for t in self._extract_mitre_techniques(alert)]
        alert_tactics = {t.lower() for t in self._extract_mitre_tactics(alert)}

        candidates = self.list_all(enabled_only=True)

        # Bucket by match tier so tier-N always beats tier-(N+1) regardless of priority
        tier1: list[AlertPromptTemplate] = []  # exact rule_id
        tier2: list[AlertPromptTemplate] = []  # regex rule_id
        tier3: list[AlertPromptTemplate] = []  # MITRE technique overlap
        tier4: list[AlertPromptTemplate] = []  # MITRE tactic overlap
        tier5: list[AlertPromptTemplate] = []  # rule.groups overlap

        for tmpl in candidates:
            rule_ids = _loads(tmpl.rule_ids_json)
            if rule_id and rule_ids and rule_id in rule_ids:
                tier1.append(tmpl)
                continue
            if rule_id and tmpl.rule_id_pattern:
                try:
                    if re.search(tmpl.rule_id_pattern, rule_id):
                        tier2.append(tmpl)
                        continue
                except re.error:
                    logger.debug(
                        "Invalid regex on AlertPromptTemplate id=%s: %r",
                        tmpl.id,
                        tmpl.rule_id_pattern,
                    )

            tmpl_techs = [str(t).upper() for t in _loads(tmpl.mitre_techniques_json)]
            if alert_techniques and tmpl_techs:
                if _techniques_overlap(alert_techniques, tmpl_techs):
                    tier3.append(tmpl)
                    continue

            tmpl_tactics_raw = _loads(tmpl.mitre_tactics_json)
            if alert_tactics and tmpl_tactics_raw:
                tmpl_tactics = {str(t).lower() for t in tmpl_tactics_raw}
                if alert_tactics.intersection(tmpl_tactics):
                    tier4.append(tmpl)
                    continue

            rule_groups = _loads(tmpl.rule_groups_json)
            if alert_groups and rule_groups:
                if alert_groups.intersection(rule_groups):
                    tier5.append(tmpl)

        for bucket in (tier1, tier2, tier3, tier4, tier5):
            if bucket:
                # Already globally sorted by priority asc, updated_at desc
                return bucket[0]
        return None


def _techniques_overlap(alert_techs: List[str], tmpl_techs: List[str]) -> bool:
    """Parent→sub tolerant MITRE technique overlap check.

    Returns True if any alert technique matches any template technique, where
    "matches" means: identical, or one is a sub-technique of the other
    (e.g. ``T1059`` ↔ ``T1059.001``). Both inputs are expected uppercase.
    """
    if not alert_techs or not tmpl_techs:
        return False
    a_set = set(alert_techs)
    t_set = set(tmpl_techs)
    if a_set & t_set:
        return True
    # Reduce each to its parent (before the dot) and check again
    a_parents = {t.split(".", 1)[0] for t in a_set}
    t_parents = {t.split(".", 1)[0] for t in t_set}
    if a_parents & t_parents:
        return True
    return False
