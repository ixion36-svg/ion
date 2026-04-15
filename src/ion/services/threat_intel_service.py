"""Threat Intel service for managing watched entities and match alerting."""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from ion.models.threat_intel import ThreatIntelWatch
from ion.models.observable import (
    Observable,
    ObservableEnrichment,
    WatchlistAlert,
    WatchlistAlertType,
)

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Service for managing threat intel watches and enrichment matching."""

    def __init__(self, session: Session):
        self.session = session

    # =========================================================================
    # Watch CRUD
    # =========================================================================

    def add_watch(
        self,
        entity_type: str,
        opencti_id: str,
        name: str,
        watched_by: str,
        description: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        labels: Optional[List[str]] = None,
        reason: Optional[str] = None,
    ) -> ThreatIntelWatch:
        """Add a new watch for a threat actor or campaign.

        Returns:
            The created (or existing active) ThreatIntelWatch record.
        """
        existing = (
            self.session.query(ThreatIntelWatch)
            .filter(ThreatIntelWatch.opencti_id == opencti_id)
            .first()
        )
        if existing:
            if not existing.is_active:
                existing.is_active = True
                existing.watched_by = watched_by
                existing.watch_reason = reason
                existing.updated_at = datetime.utcnow()
            return existing

        watch = ThreatIntelWatch(
            entity_type=entity_type,
            opencti_id=opencti_id,
            name=name,
            description=description,
            aliases=json.dumps(aliases) if aliases else None,
            labels=json.dumps(labels) if labels else None,
            watched_by=watched_by,
            watch_reason=reason,
        )
        self.session.add(watch)
        self.session.flush()
        return watch

    def remove_watch(self, watch_id: int) -> bool:
        """Soft-disable a watch. Returns True if found."""
        watch = self.session.query(ThreatIntelWatch).get(watch_id)
        if not watch:
            return False
        watch.is_active = False
        watch.updated_at = datetime.utcnow()
        return True

    def get_watches(
        self,
        entity_type: Optional[str] = None,
        is_active: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[ThreatIntelWatch], int]:
        """List watches with optional filtering."""
        q = self.session.query(ThreatIntelWatch)
        if entity_type:
            q = q.filter(ThreatIntelWatch.entity_type == entity_type)
        if is_active is not None:
            q = q.filter(ThreatIntelWatch.is_active == is_active)
        total = q.count()
        items = q.order_by(desc(ThreatIntelWatch.created_at)).offset(offset).limit(limit).all()
        return items, total

    def get_watch_by_opencti_id(self, opencti_id: str) -> Optional[ThreatIntelWatch]:
        """Find a watch by OpenCTI entity ID."""
        return (
            self.session.query(ThreatIntelWatch)
            .filter(ThreatIntelWatch.opencti_id == opencti_id)
            .first()
        )

    # =========================================================================
    # Enrichment Match Checking
    # =========================================================================

    def check_enrichment_for_watched_actors(
        self,
        enrichment: ObservableEnrichment,
        observable: Observable,
    ) -> List[WatchlistAlert]:
        """Check if enrichment result contains any watched threat actors.

        Matches by opencti_id or by name/aliases. Creates a WatchlistAlert
        per match and bumps the watch's `match_count` / `last_seen_at`.

        Returns:
            List of created WatchlistAlert records.
        """
        threat_actors = enrichment.threat_actors
        if not threat_actors:
            return []

        # Load active watches
        watches, _ = self.get_watches(is_active=True, limit=1000)
        if not watches:
            return []

        # Build lookup structures
        id_map: Dict[str, ThreatIntelWatch] = {}
        name_map: Dict[str, ThreatIntelWatch] = {}
        for w in watches:
            id_map[w.opencti_id] = w
            name_map[w.name.lower()] = w
            if w.aliases:
                try:
                    alias_list = json.loads(w.aliases)
                    for alias in alias_list:
                        if alias:
                            name_map[alias.lower()] = w
                except (json.JSONDecodeError, TypeError):
                    pass

        alerts: List[WatchlistAlert] = []
        matched_watch_ids: set = set()

        # Dedup: find recent unread alerts for this observable to avoid duplicates
        day_ago = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = (
            self.session.query(WatchlistAlert)
            .filter(
                WatchlistAlert.observable_id == observable.id,
                WatchlistAlert.alert_type == WatchlistAlertType.THREAT_ACTOR_MATCH,
                WatchlistAlert.created_at >= day_ago,
            )
            .all()
        )
        recent_watch_ids = set()
        for ra in recent_alerts:
            if ra.details and isinstance(ra.details, dict):
                wid = ra.details.get("watch_id")
                if wid:
                    recent_watch_ids.add(wid)

        for ta in threat_actors:
            if not isinstance(ta, dict):
                continue

            watch = None
            ta_id = ta.get("id", "")
            ta_name = ta.get("name", "")

            # Match by OpenCTI ID first
            if ta_id and ta_id in id_map:
                watch = id_map[ta_id]
            # Fallback: match by name
            elif ta_name and ta_name.lower() in name_map:
                watch = name_map[ta_name.lower()]

            if watch and watch.id not in matched_watch_ids and watch.id not in recent_watch_ids:
                matched_watch_ids.add(watch.id)

                # Create WatchlistAlert on the observable
                alert = WatchlistAlert(
                    observable_id=observable.id,
                    alert_type=WatchlistAlertType.THREAT_ACTOR_MATCH,
                    message=f"Observable '{observable.value}' linked to watched {watch.entity_type.replace('_', ' ')} '{watch.name}'",
                    details={
                        "watch_id": watch.id,
                        "watch_name": watch.name,
                        "entity_type": watch.entity_type,
                        "opencti_id": watch.opencti_id,
                        "matched_actor_id": ta_id,
                        "matched_actor_name": ta_name,
                    },
                )
                self.session.add(alert)
                alerts.append(alert)

                # Update watch stats
                watch.match_count = (watch.match_count or 0) + 1
                watch.last_seen_at = datetime.utcnow()

        return alerts

    # =========================================================================
    # Match Queries
    # =========================================================================

    def get_matches(
        self,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[WatchlistAlert], int]:
        """Get threat actor match alerts."""
        q = (
            self.session.query(WatchlistAlert)
            .filter(WatchlistAlert.alert_type == WatchlistAlertType.THREAT_ACTOR_MATCH)
        )
        if unread_only:
            q = q.filter(WatchlistAlert.is_read == False)
        total = q.count()
        items = q.order_by(desc(WatchlistAlert.created_at)).offset(offset).limit(limit).all()
        return items, total

    def mark_match_read(self, match_id: int, username: str) -> bool:
        """Mark a match alert as read."""
        alert = self.session.query(WatchlistAlert).get(match_id)
        if not alert or alert.alert_type != WatchlistAlertType.THREAT_ACTOR_MATCH:
            return False
        alert.is_read = True
        alert.read_by = username
        alert.read_at = datetime.utcnow()
        return True

    # =========================================================================
    # Overview Stats
    # =========================================================================

    def get_overview_stats(self) -> Dict[str, Any]:
        """Get dashboard stats for the threat intel overview."""
        actor_count = (
            self.session.query(func.count(ThreatIntelWatch.id))
            .filter(
                ThreatIntelWatch.is_active == True,
                ThreatIntelWatch.entity_type == "threat_actor",
            )
            .scalar()
        ) or 0

        campaign_count = (
            self.session.query(func.count(ThreatIntelWatch.id))
            .filter(
                ThreatIntelWatch.is_active == True,
                ThreatIntelWatch.entity_type == "campaign",
            )
            .scalar()
        ) or 0

        week_ago = datetime.utcnow() - timedelta(days=7)
        matches_7d = (
            self.session.query(func.count(WatchlistAlert.id))
            .filter(
                WatchlistAlert.alert_type == WatchlistAlertType.THREAT_ACTOR_MATCH,
                WatchlistAlert.created_at >= week_ago,
            )
            .scalar()
        ) or 0

        unread_alerts = (
            self.session.query(func.count(WatchlistAlert.id))
            .filter(
                WatchlistAlert.alert_type == WatchlistAlertType.THREAT_ACTOR_MATCH,
                WatchlistAlert.is_read == False,
            )
            .scalar()
        ) or 0

        return {
            "watched_actors": actor_count,
            "watched_campaigns": campaign_count,
            "matches_7d": matches_7d,
            "unread_alerts": unread_alerts,
        }
