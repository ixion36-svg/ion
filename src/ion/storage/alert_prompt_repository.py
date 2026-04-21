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
        list_fields = {"rule_ids", "rule_groups", "expected_outputs"}
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

        Match priority (first hit wins per-template, then sorted across
        templates by priority asc, updated_at desc):
          1. explicit rule_id in rule_ids_json
          2. regex match on rule_id_pattern
          3. any of alert's rule.groups present in rule_groups_json
        """
        if not alert:
            return None

        rule_id = self._extract_rule_id(alert)
        alert_groups = set(self._extract_rule_groups(alert))

        candidates = self.list_all(enabled_only=True)

        # Bucket by match tier so tier-1 always beats tier-2/3 regardless of priority
        tier1: list[AlertPromptTemplate] = []  # exact rule_id
        tier2: list[AlertPromptTemplate] = []  # regex rule_id
        tier3: list[AlertPromptTemplate] = []  # rule.groups overlap

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
            rule_groups = _loads(tmpl.rule_groups_json)
            if alert_groups and rule_groups:
                if alert_groups.intersection(rule_groups):
                    tier3.append(tmpl)

        for bucket in (tier1, tier2, tier3):
            if bucket:
                # Already globally sorted by priority asc, updated_at desc
                return bucket[0]
        return None
