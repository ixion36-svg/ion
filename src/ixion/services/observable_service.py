"""Observable service for centralized IOC tracking and enrichment.

Provides CRUD operations, linking to alerts/cases, correlation queries,
enrichment via OpenCTI, and migration from legacy JSON observables.
"""

import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import func, and_, or_, desc
from sqlalchemy.orm import Session

from ixion.models.observable import (
    Observable,
    ObservableEnrichment,
    ObservableLink,
    ObservableLinkType,
    ObservableType,
    ThreatLevel,
    WatchlistAlert,
    WatchlistAlertType,
)
from ixion.models.alert_triage import AlertTriage, AlertCase
from ixion.services.opencti_service import get_opencti_service, OpenCTIError

logger = logging.getLogger(__name__)

# Map legacy observable types to new enum values
LEGACY_TYPE_MAP = {
    "hostname": ObservableType.HOSTNAME,
    "source_ip": ObservableType.IPV4,
    "destination_ip": ObservableType.IPV4,
    "url": ObservableType.URL,
    "domain": ObservableType.DOMAIN,
    "user_account": ObservableType.USER_ACCOUNT,
    "ipv4-addr": ObservableType.IPV4,
    "ipv6-addr": ObservableType.IPV6,
    "domain-name": ObservableType.DOMAIN,
    "file-sha256": ObservableType.FILE_HASH_SHA256,
    "file-sha1": ObservableType.FILE_HASH_SHA1,
    "file-md5": ObservableType.FILE_HASH_MD5,
    "email-addr": ObservableType.EMAIL,
    "ip": ObservableType.IPV4,
}


class ObservableService:
    """Service for managing observables with enrichment and correlation."""

    def __init__(self, session: Session):
        self.session = session

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def get_or_create(
        self,
        obs_type: ObservableType | str,
        value: str,
    ) -> Tuple[Observable, bool]:
        """Get existing observable or create a new one.

        Args:
            obs_type: Observable type (enum or string)
            value: Observable value

        Returns:
            Tuple of (Observable, created) where created is True if new
        """
        # Convert string type to enum if needed
        if isinstance(obs_type, str):
            obs_type = self._resolve_type(obs_type)

        normalized = Observable.normalize_value(obs_type, value)

        existing = (
            self.session.query(Observable)
            .filter(
                Observable.type == obs_type,
                Observable.normalized_value == normalized,
            )
            .first()
        )

        if existing:
            # Update sighting count and last_seen
            existing.sighting_count += 1
            existing.last_seen = datetime.utcnow()
            return existing, False

        # Create new observable
        observable = Observable(
            type=obs_type,
            value=value,
            normalized_value=normalized,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            sighting_count=1,
        )
        self.session.add(observable)
        self.session.flush()
        return observable, True

    def get_by_id(self, observable_id: int) -> Optional[Observable]:
        """Get observable by ID."""
        return self.session.query(Observable).filter(Observable.id == observable_id).first()

    def get_by_value(
        self,
        value: str,
        obs_type: Optional[ObservableType | str] = None,
    ) -> List[Observable]:
        """Find observables by value, optionally filtered by type.

        Args:
            value: Value to search for (will be normalized)
            obs_type: Optional type filter

        Returns:
            List of matching observables
        """
        # Try to normalize with each potential type if not specified
        if obs_type:
            if isinstance(obs_type, str):
                obs_type = self._resolve_type(obs_type)
            normalized = Observable.normalize_value(obs_type, value)
            return (
                self.session.query(Observable)
                .filter(
                    Observable.type == obs_type,
                    Observable.normalized_value == normalized,
                )
                .all()
            )

        # Search across all types with normalized value
        normalized_lower = value.strip().lower()
        return (
            self.session.query(Observable)
            .filter(Observable.normalized_value == normalized_lower)
            .all()
        )

    def search(
        self,
        query: Optional[str] = None,
        types: Optional[List[ObservableType | str]] = None,
        threat_level: Optional[ThreatLevel | str] = None,
        is_whitelisted: Optional[bool] = None,
        is_enriched: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Observable], int]:
        """Search observables with filters.

        Args:
            query: Text search in value/notes
            types: Filter by observable types
            threat_level: Filter by threat level
            is_whitelisted: Filter by whitelist status
            is_enriched: Filter by enrichment status
            tags: Filter by tags (any match)
            limit: Max results
            offset: Pagination offset

        Returns:
            Tuple of (results, total_count)
        """
        q = self.session.query(Observable)

        if query:
            search_term = f"%{query.lower()}%"
            q = q.filter(
                or_(
                    Observable.normalized_value.ilike(search_term),
                    Observable.value.ilike(search_term),
                    Observable.notes.ilike(search_term),
                )
            )

        if types:
            resolved_types = [
                self._resolve_type(t) if isinstance(t, str) else t
                for t in types
            ]
            q = q.filter(Observable.type.in_(resolved_types))

        if threat_level:
            if isinstance(threat_level, str):
                threat_level = ThreatLevel(threat_level)
            q = q.filter(Observable.threat_level == threat_level)

        if is_whitelisted is not None:
            q = q.filter(Observable.is_whitelisted == is_whitelisted)

        if is_enriched is not None:
            # Subquery to find observables with enrichments
            enriched_ids = (
                self.session.query(ObservableEnrichment.observable_id)
                .distinct()
                .subquery()
            )
            if is_enriched:
                q = q.filter(Observable.id.in_(enriched_ids))
            else:
                q = q.filter(~Observable.id.in_(enriched_ids))

        if tags:
            # JSON array contains any of the tags
            for tag in tags:
                q = q.filter(Observable.tags.contains([tag]))

        total = q.count()
        results = (
            q.order_by(desc(Observable.last_seen))
            .offset(offset)
            .limit(limit)
            .all()
        )

        return results, total

    def update(
        self,
        observable_id: int,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
        is_whitelisted: Optional[bool] = None,
        threat_level: Optional[ThreatLevel | str] = None,
    ) -> Optional[Observable]:
        """Update observable metadata.

        Args:
            observable_id: ID of observable to update
            tags: New tags (replaces existing)
            notes: New notes (replaces existing)
            is_whitelisted: Whitelist flag
            threat_level: Manual threat level override

        Returns:
            Updated observable or None if not found
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return None

        if tags is not None:
            observable.tags = tags
        if notes is not None:
            observable.notes = notes
        if is_whitelisted is not None:
            observable.is_whitelisted = is_whitelisted
        if threat_level is not None:
            if isinstance(threat_level, str):
                threat_level = ThreatLevel(threat_level)
            observable.threat_level = threat_level

        return observable

    def delete(self, observable_id: int) -> bool:
        """Delete an observable and all its links.

        Args:
            observable_id: ID of observable to delete

        Returns:
            True if deleted, False if not found
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return False

        self.session.delete(observable)
        return True

    # =========================================================================
    # Linking Operations
    # =========================================================================

    def link_to_alert(
        self,
        observable_id: int,
        alert_triage_id: int,
        context: str,
        extracted_from: str = "auto",
    ) -> Optional[ObservableLink]:
        """Link an observable to an alert triage record.

        Args:
            observable_id: Observable ID
            alert_triage_id: AlertTriage ID
            context: Context of the observable (e.g., "source_ip")
            extracted_from: How it was extracted ("auto" or "manual")

        Returns:
            Link record or None if observable/alert not found
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return None

        # Check if link already exists
        existing = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.ALERT,
                ObservableLink.entity_id == alert_triage_id,
                ObservableLink.context == context,
            )
            .first()
        )
        if existing:
            return existing

        link = ObservableLink(
            observable_id=observable_id,
            link_type=ObservableLinkType.ALERT,
            entity_id=alert_triage_id,
            context=context,
            extracted_from=extracted_from,
        )
        self.session.add(link)
        self.session.flush()
        return link

    def link_to_case(
        self,
        observable_id: int,
        case_id: int,
        context: str,
    ) -> Optional[ObservableLink]:
        """Link an observable to a case.

        Args:
            observable_id: Observable ID
            case_id: AlertCase ID
            context: Context of the observable

        Returns:
            Link record or None if observable/case not found
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return None

        # Check if link already exists
        existing = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.CASE,
                ObservableLink.entity_id == case_id,
                ObservableLink.context == context,
            )
            .first()
        )
        if existing:
            return existing

        link = ObservableLink(
            observable_id=observable_id,
            link_type=ObservableLinkType.CASE,
            entity_id=case_id,
            context=context,
            extracted_from="manual",
        )
        self.session.add(link)
        self.session.flush()
        return link

    def unlink_from_alert(
        self,
        observable_id: int,
        alert_triage_id: int,
    ) -> bool:
        """Remove all links between an observable and an alert.

        Returns:
            True if any links were removed
        """
        result = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.ALERT,
                ObservableLink.entity_id == alert_triage_id,
            )
            .delete()
        )
        return result > 0

    def unlink_from_case(
        self,
        observable_id: int,
        case_id: int,
    ) -> bool:
        """Remove all links between an observable and a case.

        Returns:
            True if any links were removed
        """
        result = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.CASE,
                ObservableLink.entity_id == case_id,
            )
            .delete()
        )
        return result > 0

    # =========================================================================
    # Bulk Operations
    # =========================================================================

    def extract_and_link_from_alert(
        self,
        alert_triage_id: int,
    ) -> List[Observable]:
        """Extract observables from alert triage JSON and create links.

        Reads the legacy JSON observables field and creates normalized
        Observable records with links back to the alert.

        Args:
            alert_triage_id: AlertTriage record ID

        Returns:
            List of created/linked observables
        """
        triage = (
            self.session.query(AlertTriage)
            .filter(AlertTriage.id == alert_triage_id)
            .first()
        )
        if not triage or not triage.observables:
            return []

        observables = []
        for obs_data in triage.observables:
            obs_type_str = obs_data.get("type", "")
            obs_value = obs_data.get("value", "")
            if not obs_type_str or not obs_value:
                continue

            try:
                obs_type = self._resolve_type(obs_type_str)
            except ValueError:
                logger.warning("Unknown observable type: %s", obs_type_str)
                continue

            observable, created = self.get_or_create(obs_type, obs_value)
            self.link_to_alert(
                observable.id,
                alert_triage_id,
                context=obs_type_str,
                extracted_from="auto",
            )

            # Record sighting for timeline
            self.record_sighting(
                observable_id=observable.id,
                source_type="alert",
                source_id=alert_triage_id,
                context=obs_type_str,
            )

            # Check watchlist and create alert if watched
            self.check_and_alert_watched(observable, triggered_by_alert_id=alert_triage_id)

            # Auto-enrich new observables if enabled
            if created and observable.auto_enrich:
                try:
                    self.auto_enrich_new_observable(observable)
                except Exception as e:
                    logger.warning(f"Auto-enrichment failed for {observable.id}: {e}")

            observables.append(observable)

        return observables

    def extract_and_link_from_case(
        self,
        case_id: int,
    ) -> List[Observable]:
        """Extract observables from all alerts linked to a case.

        Args:
            case_id: AlertCase ID

        Returns:
            List of all observables linked to the case
        """
        case = (
            self.session.query(AlertCase)
            .filter(AlertCase.id == case_id)
            .first()
        )
        if not case:
            return []

        observables = []
        seen_observable_ids = set()

        # Process all triage entries linked to this case
        for triage in case.triage_entries:
            alert_observables = self.extract_and_link_from_alert(triage.id)
            for obs in alert_observables:
                if obs.id not in seen_observable_ids:
                    # Also link to the case
                    self.link_to_case(obs.id, case_id, context="from_alert")
                    observables.append(obs)
                    seen_observable_ids.add(obs.id)

        return observables

    def migrate_json_observables(self) -> Dict[str, int]:
        """One-time migration of all JSON observables to normalized table.

        Returns:
            Dict with migration statistics
        """
        stats = {
            "alerts_processed": 0,
            "observables_created": 0,
            "observables_existing": 0,
            "links_created": 0,
            "errors": 0,
        }

        triages = (
            self.session.query(AlertTriage)
            .filter(AlertTriage.observables.isnot(None))
            .all()
        )

        for triage in triages:
            stats["alerts_processed"] += 1
            try:
                for obs_data in triage.observables or []:
                    obs_type_str = obs_data.get("type", "")
                    obs_value = obs_data.get("value", "")
                    if not obs_type_str or not obs_value:
                        continue

                    try:
                        obs_type = self._resolve_type(obs_type_str)
                    except ValueError:
                        logger.warning("Migration: unknown type %s", obs_type_str)
                        stats["errors"] += 1
                        continue

                    observable, created = self.get_or_create(obs_type, obs_value)
                    if created:
                        stats["observables_created"] += 1
                    else:
                        stats["observables_existing"] += 1

                    link = self.link_to_alert(
                        observable.id,
                        triage.id,
                        context=obs_type_str,
                        extracted_from="migration",
                    )
                    if link:
                        stats["links_created"] += 1
            except Exception as e:
                logger.error("Migration error for triage %s: %s", triage.id, e)
                stats["errors"] += 1

        logger.info("Migration complete: %s", stats)
        return stats

    # =========================================================================
    # Correlation Queries
    # =========================================================================

    def get_related_alerts(
        self,
        observable_id: int,
        limit: int = 50,
    ) -> List[AlertTriage]:
        """Get all alerts containing this observable.

        Args:
            observable_id: Observable ID
            limit: Max results

        Returns:
            List of AlertTriage records
        """
        links = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.ALERT,
            )
            .order_by(desc(ObservableLink.created_at))
            .limit(limit)
            .all()
        )
        alert_ids = [link.entity_id for link in links]
        if not alert_ids:
            return []
        return self.session.query(AlertTriage).filter(AlertTriage.id.in_(alert_ids)).all()

    def get_related_cases(
        self,
        observable_id: int,
        limit: int = 50,
    ) -> List[AlertCase]:
        """Get all cases containing this observable.

        Args:
            observable_id: Observable ID
            limit: Max results

        Returns:
            List of AlertCase records
        """
        links = (
            self.session.query(ObservableLink)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.CASE,
            )
            .order_by(desc(ObservableLink.created_at))
            .limit(limit)
            .all()
        )
        case_ids = [link.entity_id for link in links]
        if not case_ids:
            return []
        return self.session.query(AlertCase).filter(AlertCase.id.in_(case_ids)).all()

    def get_co_occurring_observables(
        self,
        observable_id: int,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Get observables that frequently appear alongside this one.

        Args:
            observable_id: Observable ID
            limit: Max results

        Returns:
            List of dicts with observable info and co-occurrence count
        """
        # Find all alerts containing this observable
        alert_ids_subq = (
            self.session.query(ObservableLink.entity_id)
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.link_type == ObservableLinkType.ALERT,
            )
            .subquery()
        )

        # Find other observables in those alerts, count occurrences
        co_occurring = (
            self.session.query(
                Observable,
                func.count(ObservableLink.id).label("count"),
            )
            .join(ObservableLink)
            .filter(
                ObservableLink.link_type == ObservableLinkType.ALERT,
                ObservableLink.entity_id.in_(alert_ids_subq),
                Observable.id != observable_id,
            )
            .group_by(Observable.id)
            .order_by(desc("count"))
            .limit(limit)
            .all()
        )

        return [
            {
                "observable": obs,
                "co_occurrence_count": count,
            }
            for obs, count in co_occurring
        ]

    # =========================================================================
    # Enrichment
    # =========================================================================

    async def enrich(
        self,
        observable_id: int,
        source: str = "opencti",
    ) -> Optional[ObservableEnrichment]:
        """Enrich an observable using external threat intelligence.

        Args:
            observable_id: Observable ID
            source: Enrichment source (currently only "opencti")

        Returns:
            Enrichment record or None if failed
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return None

        if source == "opencti":
            return await self._enrich_from_opencti(observable)

        logger.warning("Unknown enrichment source: %s", source)
        return None

    async def enrich_batch(
        self,
        observable_ids: List[int],
        source: str = "opencti",
    ) -> List[ObservableEnrichment]:
        """Enrich multiple observables.

        Args:
            observable_ids: List of observable IDs
            source: Enrichment source

        Returns:
            List of enrichment records (may be shorter than input if errors)
        """
        results = []
        for obs_id in observable_ids:
            enrichment = await self.enrich(obs_id, source)
            if enrichment:
                results.append(enrichment)
        return results

    async def _enrich_from_opencti(
        self,
        observable: Observable,
    ) -> Optional[ObservableEnrichment]:
        """Enrich observable using OpenCTI.

        Args:
            observable: Observable to enrich

        Returns:
            Enrichment record or None if failed
        """
        service = get_opencti_service()
        if not service.is_configured:
            logger.warning("OpenCTI not configured, skipping enrichment")
            return None

        # Map our type to OpenCTI type
        opencti_type = self._to_opencti_type(observable.type)

        try:
            result = await service.enrich_observable(opencti_type, observable.value)
        except OpenCTIError as e:
            logger.error("OpenCTI enrichment failed: %s", e)
            return None

        # Handle case where OpenCTI returns None or invalid response
        if not result or not isinstance(result, dict):
            logger.warning("OpenCTI returned no/invalid result for observable %s: %s", observable.value, type(result))
            return None

        try:
            # Calculate score and malicious flag
            is_malicious = bool(
                result.get("found", False) and (
                    result.get("indicators") or result.get("threat_actors")
                )
            )
            score = None
            obs_data = result.get("observable") or {}
            if isinstance(obs_data, dict) and obs_data.get("score") is not None:
                score = obs_data["score"]
            elif result.get("indicators"):
                # Average score from indicators
                scores = [
                    i.get("score")
                    for i in result.get("indicators", [])
                    if isinstance(i, dict) and i.get("score") is not None
                ]
                if scores:
                    score = sum(scores) // len(scores)

            # Extract and clean data for JSON storage
            labels_data = [l.get("value") for l in result.get("labels", []) if isinstance(l, dict) and l.get("value")]
            threat_actors_data = [
                {"name": ta.get("name"), "id": ta.get("id")}
                for ta in result.get("threat_actors", [])
                if isinstance(ta, dict) and ta.get("name")
            ]
            indicators_data = [
                {
                    "name": i.get("name"),
                    "id": i.get("id"),
                    "pattern": i.get("pattern"),
                }
                for i in result.get("indicators", [])
                if isinstance(i, dict) and (i.get("name") or i.get("id"))
            ]
            reports_data = [
                {"name": r.get("name"), "id": r.get("id")}
                for r in result.get("reports", [])
                if isinstance(r, dict) and r.get("name")
            ]
        except (AttributeError, TypeError, KeyError) as e:
            logger.error("Error processing OpenCTI result for %s: %s", observable.value, e)
            return None

        # Create enrichment record with no_autoflush to prevent premature flush
        with self.session.no_autoflush:
            enrichment = ObservableEnrichment(
                observable_id=observable.id,
                source="opencti",
                enriched_at=datetime.utcnow(),
                raw_response=result,
                is_malicious=is_malicious,
                score=score,
                labels=labels_data if labels_data else None,
                threat_actors=threat_actors_data if threat_actors_data else None,
                indicators=indicators_data if indicators_data else None,
                reports=reports_data if reports_data else None,
            )
            self.session.add(enrichment)
            self.session.flush()

            # Update observable threat level based on enrichment
            self._update_threat_level(observable, enrichment)

        return enrichment

    def get_enrichment_history(
        self,
        observable_id: int,
    ) -> List[ObservableEnrichment]:
        """Get all enrichment records for an observable.

        Args:
            observable_id: Observable ID

        Returns:
            List of enrichment records, newest first
        """
        return (
            self.session.query(ObservableEnrichment)
            .filter(ObservableEnrichment.observable_id == observable_id)
            .order_by(desc(ObservableEnrichment.enriched_at))
            .all()
        )

    def calculate_threat_level(
        self,
        observable_id: int,
    ) -> ThreatLevel:
        """Calculate threat level from latest enrichment data.

        Args:
            observable_id: Observable ID

        Returns:
            Calculated threat level
        """
        observable = self.get_by_id(observable_id)
        if not observable:
            return ThreatLevel.UNKNOWN

        if observable.is_whitelisted:
            return ThreatLevel.BENIGN

        enrichment = observable.latest_enrichment
        if not enrichment:
            return ThreatLevel.UNKNOWN

        if not enrichment.is_malicious:
            return ThreatLevel.BENIGN

        score = enrichment.score
        if score is None:
            # Has indicators but no score
            if enrichment.threat_actors:
                return ThreatLevel.HIGH
            if enrichment.indicators:
                return ThreatLevel.MEDIUM
            return ThreatLevel.LOW

        # Score-based levels
        if score >= 80:
            return ThreatLevel.CRITICAL
        if score >= 60:
            return ThreatLevel.HIGH
        if score >= 40:
            return ThreatLevel.MEDIUM
        if score >= 20:
            return ThreatLevel.LOW
        return ThreatLevel.BENIGN

    def _update_threat_level(
        self,
        observable: Observable,
        enrichment: ObservableEnrichment,
    ) -> None:
        """Update observable threat level based on enrichment."""
        if observable.is_whitelisted:
            observable.threat_level = ThreatLevel.BENIGN
            return

        new_level = self.calculate_threat_level(observable.id)
        observable.threat_level = new_level

    # =========================================================================
    # Graph & Pattern Detection
    # =========================================================================

    def get_relationship_graph(
        self,
        observable_id: Optional[int] = None,
        limit: int = 100,
        min_co_occurrence: int = 2,
    ) -> Dict[str, Any]:
        """Build a relationship graph of observables.

        Args:
            observable_id: Optional center node (if None, uses top observables)
            limit: Max nodes to include
            min_co_occurrence: Minimum times observables must appear together

        Returns:
            Dict with 'nodes' and 'edges' for visualization
        """
        nodes = []
        edges = []
        node_ids = set()

        if observable_id:
            # Start from a specific observable
            center = self.get_by_id(observable_id)
            if not center:
                return {"nodes": [], "edges": []}

            nodes.append(self._observable_to_node(center, is_center=True))
            node_ids.add(center.id)

            # Get co-occurring observables
            co_occurring = self.get_co_occurring_observables(observable_id, limit=limit)
            for item in co_occurring:
                obs = item["observable"]
                count = item["co_occurrence_count"]
                if count >= min_co_occurrence and obs.id not in node_ids:
                    nodes.append(self._observable_to_node(obs))
                    node_ids.add(obs.id)
                    edges.append({
                        "from": center.id,
                        "to": obs.id,
                        "weight": count,
                        "label": str(count),
                    })
        else:
            # Build graph from top observables and their relationships
            top_obs = self.get_top_observables(limit=min(limit, 30))
            for obs in top_obs:
                if obs.id not in node_ids:
                    nodes.append(self._observable_to_node(obs))
                    node_ids.add(obs.id)

            # Find edges between these nodes
            for obs in top_obs:
                co_occurring = self.get_co_occurring_observables(obs.id, limit=20)
                for item in co_occurring:
                    other = item["observable"]
                    count = item["co_occurrence_count"]
                    if other.id in node_ids and count >= min_co_occurrence:
                        # Avoid duplicate edges
                        edge_key = tuple(sorted([obs.id, other.id]))
                        existing = any(
                            tuple(sorted([e["from"], e["to"]])) == edge_key
                            for e in edges
                        )
                        if not existing:
                            edges.append({
                                "from": obs.id,
                                "to": other.id,
                                "weight": count,
                                "label": str(count),
                            })

        return {"nodes": nodes, "edges": edges}

    def _observable_to_node(
        self,
        obs: Observable,
        is_center: bool = False,
    ) -> Dict[str, Any]:
        """Convert observable to graph node."""
        # Color by type
        type_colors = {
            ObservableType.IPV4: "#ef4444",
            ObservableType.IPV6: "#ef4444",
            ObservableType.DOMAIN: "#8b5cf6",
            ObservableType.HOSTNAME: "#3b82f6",
            ObservableType.URL: "#22c55e",
            ObservableType.EMAIL: "#f59e0b",
            ObservableType.USER_ACCOUNT: "#06b6d4",
        }
        color = type_colors.get(obs.type, "#6b7280")

        # Size by sighting count (log scale)
        import math
        size = 15 + min(35, int(math.log(obs.sighting_count + 1) * 10))

        # Border by threat level
        threat_borders = {
            ThreatLevel.CRITICAL: "#ff0000",
            ThreatLevel.HIGH: "#ff6600",
            ThreatLevel.MEDIUM: "#ffcc00",
        }
        border = threat_borders.get(obs.threat_level, None)

        # Type icons/prefixes
        type_prefix = {
            ObservableType.IPV4: "IP:",
            ObservableType.IPV6: "IPv6:",
            ObservableType.DOMAIN: "DOM:",
            ObservableType.HOSTNAME: "HOST:",
            ObservableType.URL: "URL:",
            ObservableType.EMAIL: "EMAIL:",
            ObservableType.USER_ACCOUNT: "USER:",
            ObservableType.FILE_HASH_MD5: "MD5:",
            ObservableType.FILE_HASH_SHA1: "SHA1:",
            ObservableType.FILE_HASH_SHA256: "SHA256:",
        }
        prefix = type_prefix.get(obs.type, "")

        # Truncate value for label
        max_len = 25
        display_value = obs.value
        if len(display_value) > max_len:
            display_value = display_value[:max_len] + "..."

        # Multi-line label with type and value
        label = f"{prefix}\n{display_value}"

        return {
            "id": obs.id,
            "label": label,
            "title": f"Type: {obs.type.value.upper()}\nValue: {obs.value}\nSightings: {obs.sighting_count}\nThreat Level: {obs.threat_level.value.upper()}",
            "value": obs.value,
            "type": obs.type.value,
            "threat_level": obs.threat_level.value,
            "sighting_count": obs.sighting_count,
            "color": {
                "background": color,
                "border": border or color,
                "highlight": {"background": color, "border": "#ffffff"},
            },
            "size": size,
            "font": {"color": "#ffffff", "size": 11, "multi": True},
            "shape": "box",
            "borderWidth": 3 if is_center else 1,
            "is_center": is_center,
        }

    def detect_patterns(
        self,
        time_window_minutes: int = 60,
        min_occurrences: int = 3,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Detect patterns of observables that appear together.

        Args:
            time_window_minutes: Time window for clustering
            min_occurrences: Minimum times pattern must occur
            limit: Max patterns to return

        Returns:
            List of pattern dicts with observables and occurrence info
        """
        from collections import defaultdict
        from sqlalchemy import text

        # Find alert pairs within time window that share observables
        # This query finds observables that appear in alerts close in time
        patterns = defaultdict(lambda: {"count": 0, "alerts": set(), "times": []})

        # Get all alert links with timestamps
        links = (
            self.session.query(
                ObservableLink.observable_id,
                ObservableLink.entity_id,
                ObservableLink.created_at,
            )
            .filter(ObservableLink.link_type == ObservableLinkType.ALERT)
            .order_by(ObservableLink.created_at)
            .all()
        )

        # Group by alert
        alert_observables = defaultdict(set)
        alert_times = {}
        for obs_id, alert_id, created_at in links:
            alert_observables[alert_id].add(obs_id)
            alert_times[alert_id] = created_at

        # Find observable sets that appear together
        observable_sets = defaultdict(lambda: {"alerts": [], "times": []})
        for alert_id, obs_ids in alert_observables.items():
            if len(obs_ids) >= 2:
                # Create a frozen set key of observable IDs
                key = frozenset(obs_ids)
                observable_sets[key]["alerts"].append(alert_id)
                observable_sets[key]["times"].append(alert_times.get(alert_id))

        # Filter to patterns with enough occurrences
        results = []
        for obs_set, data in observable_sets.items():
            if len(data["alerts"]) >= min_occurrences:
                # Get observable details
                observables = (
                    self.session.query(Observable)
                    .filter(Observable.id.in_(obs_set))
                    .all()
                )
                results.append({
                    "observables": [
                        {
                            "id": o.id,
                            "type": o.type.value,
                            "value": o.value,
                            "threat_level": o.threat_level.value,
                        }
                        for o in observables
                    ],
                    "occurrence_count": len(data["alerts"]),
                    "alert_ids": data["alerts"][:10],  # Limit for response size
                    "first_seen": min(data["times"]).isoformat() if data["times"] else None,
                    "last_seen": max(data["times"]).isoformat() if data["times"] else None,
                })

        # Sort by occurrence count
        results.sort(key=lambda x: x["occurrence_count"], reverse=True)
        return results[:limit]

    def get_time_clusters(
        self,
        hours: int = 24,
        interval_minutes: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get observable activity clusters over time.

        Args:
            hours: How far back to look
            interval_minutes: Time bucket size

        Returns:
            List of time buckets with observable counts
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=hours)

        # Get all observables seen since cutoff
        observables = (
            self.session.query(Observable)
            .filter(Observable.last_seen >= cutoff)
            .order_by(Observable.last_seen)
            .all()
        )

        # Bucket by time interval
        buckets = defaultdict(lambda: {"count": 0, "types": defaultdict(int), "threat_levels": defaultdict(int)})

        for obs in observables:
            # Round to interval
            bucket_time = obs.last_seen.replace(
                minute=(obs.last_seen.minute // interval_minutes) * interval_minutes,
                second=0,
                microsecond=0,
            )
            bucket_key = bucket_time.isoformat()
            buckets[bucket_key]["count"] += 1
            buckets[bucket_key]["types"][obs.type.value] += 1
            buckets[bucket_key]["threat_levels"][obs.threat_level.value] += 1

        # Convert to list
        result = [
            {
                "time": k,
                "count": v["count"],
                "types": dict(v["types"]),
                "threat_levels": dict(v["threat_levels"]),
            }
            for k, v in sorted(buckets.items())
        ]

        return result

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get observable statistics for dashboard.

        Returns:
            Dict with various counts and breakdowns
        """
        total = self.session.query(Observable).count()

        # Count by type
        type_counts = dict(
            self.session.query(
                Observable.type,
                func.count(Observable.id),
            )
            .group_by(Observable.type)
            .all()
        )

        # Count by threat level
        threat_counts = dict(
            self.session.query(
                Observable.threat_level,
                func.count(Observable.id),
            )
            .group_by(Observable.threat_level)
            .all()
        )

        # Count enriched
        enriched_count = (
            self.session.query(func.count(func.distinct(ObservableEnrichment.observable_id)))
            .scalar()
        )

        # Count whitelisted
        whitelisted_count = (
            self.session.query(Observable)
            .filter(Observable.is_whitelisted == True)
            .count()
        )

        return {
            "total": total,
            "by_type": {k.value if hasattr(k, 'value') else k: v for k, v in type_counts.items()},
            "by_threat_level": {k.value if hasattr(k, 'value') else k: v for k, v in threat_counts.items()},
            "enriched": enriched_count,
            "whitelisted": whitelisted_count,
        }

    def get_top_observables(
        self,
        obs_type: Optional[ObservableType | str] = None,
        limit: int = 10,
    ) -> List[Observable]:
        """Get most frequently seen observables.

        Args:
            obs_type: Optional type filter
            limit: Max results

        Returns:
            List of observables sorted by sighting count
        """
        q = self.session.query(Observable)

        if obs_type:
            if isinstance(obs_type, str):
                obs_type = self._resolve_type(obs_type)
            q = q.filter(Observable.type == obs_type)

        return (
            q.order_by(desc(Observable.sighting_count))
            .limit(limit)
            .all()
        )

    # =========================================================================
    # Watchlist Functionality
    # =========================================================================

    def add_to_watchlist(
        self,
        observable_id: int,
        reason: Optional[str] = None,
        watched_by: Optional[str] = None,
    ) -> Observable:
        """Add an observable to the watchlist.

        Args:
            observable_id: Observable ID
            reason: Why this observable is being watched
            watched_by: Username of who added it

        Returns:
            Updated observable
        """
        obs = self.get_by_id(observable_id)
        if not obs:
            raise ValueError(f"Observable {observable_id} not found")

        obs.is_watched = True
        obs.watch_reason = reason
        obs.watched_by = watched_by
        obs.watched_at = datetime.utcnow()
        self.session.flush()

        logger.info(f"Added observable {observable_id} to watchlist: {obs.value}")
        return obs

    def remove_from_watchlist(self, observable_id: int) -> Observable:
        """Remove an observable from the watchlist.

        Args:
            observable_id: Observable ID

        Returns:
            Updated observable
        """
        obs = self.get_by_id(observable_id)
        if not obs:
            raise ValueError(f"Observable {observable_id} not found")

        obs.is_watched = False
        obs.watch_reason = None
        obs.watched_by = None
        obs.watched_at = None
        self.session.flush()

        logger.info(f"Removed observable {observable_id} from watchlist")
        return obs

    def get_watched_observables(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Observable], int]:
        """Get all watched observables.

        Args:
            limit: Max results
            offset: Pagination offset

        Returns:
            Tuple of (observables, total_count)
        """
        q = self.session.query(Observable).filter(Observable.is_watched == True)
        total = q.count()
        results = (
            q.order_by(desc(Observable.watched_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return results, total

    def create_watchlist_alert(
        self,
        observable_id: int,
        alert_type: WatchlistAlertType,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        triggered_by_alert_id: Optional[int] = None,
    ) -> WatchlistAlert:
        """Create a watchlist alert for a watched observable.

        Args:
            observable_id: Observable ID
            alert_type: Type of alert
            message: Alert message
            details: Additional details
            triggered_by_alert_id: Alert that triggered this watchlist alert

        Returns:
            Created WatchlistAlert
        """
        alert = WatchlistAlert(
            observable_id=observable_id,
            alert_type=alert_type,
            message=message,
            details=details,
            triggered_by_alert_id=triggered_by_alert_id,
        )
        self.session.add(alert)
        self.session.flush()

        logger.info(f"Created watchlist alert for observable {observable_id}: {alert_type}")
        return alert

    def get_watchlist_alerts(
        self,
        observable_id: Optional[int] = None,
        is_read: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[WatchlistAlert], int]:
        """Get watchlist alerts.

        Args:
            observable_id: Filter by observable
            is_read: Filter by read status
            limit: Max results
            offset: Pagination offset

        Returns:
            Tuple of (alerts, total_count)
        """
        q = self.session.query(WatchlistAlert)

        if observable_id is not None:
            q = q.filter(WatchlistAlert.observable_id == observable_id)

        if is_read is not None:
            q = q.filter(WatchlistAlert.is_read == is_read)

        total = q.count()
        results = (
            q.order_by(desc(WatchlistAlert.created_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return results, total

    def mark_watchlist_alert_read(
        self,
        alert_id: int,
        read_by: Optional[str] = None,
    ) -> WatchlistAlert:
        """Mark a watchlist alert as read.

        Args:
            alert_id: Alert ID
            read_by: Username of who read it

        Returns:
            Updated alert
        """
        alert = self.session.query(WatchlistAlert).filter(WatchlistAlert.id == alert_id).first()
        if not alert:
            raise ValueError(f"Watchlist alert {alert_id} not found")

        alert.is_read = True
        alert.read_by = read_by
        alert.read_at = datetime.utcnow()
        self.session.flush()
        return alert

    def check_and_alert_watched(
        self,
        observable: Observable,
        triggered_by_alert_id: Optional[int] = None,
    ) -> Optional[WatchlistAlert]:
        """Check if observable is watched and create alert if so.

        Args:
            observable: The observable that was seen
            triggered_by_alert_id: Alert that triggered this sighting

        Returns:
            WatchlistAlert if created, None otherwise
        """
        if not observable.is_watched:
            return None

        # Don't alert if we just added it to watchlist (within 1 minute)
        if observable.watched_at:
            since_watched = (datetime.utcnow() - observable.watched_at).total_seconds()
            if since_watched < 60:
                return None

        return self.create_watchlist_alert(
            observable_id=observable.id,
            alert_type=WatchlistAlertType.NEW_SIGHTING,
            message=f"Watched observable '{observable.value}' seen in new alert",
            details={
                "observable_type": observable.type.value,
                "observable_value": observable.value,
                "sighting_count": observable.sighting_count,
            },
            triggered_by_alert_id=triggered_by_alert_id,
        )

    # =========================================================================
    # Timeline/Sighting History
    # =========================================================================

    def record_sighting(
        self,
        observable_id: int,
        source_type: str,
        source_id: Optional[int] = None,
        context: Optional[str] = None,
        seen_at: Optional[datetime] = None,
    ) -> ObservableLink:
        """Record a sighting of an observable for timeline tracking.

        Args:
            observable_id: Observable ID
            source_type: Type of source ("alert", "case", "manual", "import")
            source_id: ID of the source (alert_id or case_id)
            context: Context of the sighting (e.g., "source_ip")
            seen_at: When it was seen (defaults to now)

        Returns:
            Created sighting record (as ObservableLink)
        """
        # Map source_type to ObservableLinkType
        link_type_map = {
            "alert": ObservableLinkType.ALERT,
            "case": ObservableLinkType.CASE,
        }
        link_type = link_type_map.get(source_type, ObservableLinkType.MANUAL)

        sighting = ObservableLink(
            observable_id=observable_id,
            link_type=link_type,
            entity_id=source_id or 0,
            context=context or source_type,
            extracted_from="sighting",
        )
        self.session.add(sighting)
        self.session.flush()
        return sighting

    def get_timeline(
        self,
        observable_id: int,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get timeline of sightings for an observable.

        Args:
            observable_id: Observable ID
            limit: Max results

        Returns:
            List of timeline events
        """
        # Get all links (sightings) for this observable
        links = (
            self.session.query(ObservableLink)
            .filter(ObservableLink.observable_id == observable_id)
            .order_by(desc(ObservableLink.created_at))
            .limit(limit)
            .all()
        )

        # Also include enrichments in timeline
        enrichments = (
            self.session.query(ObservableEnrichment)
            .filter(ObservableEnrichment.observable_id == observable_id)
            .order_by(desc(ObservableEnrichment.enriched_at))
            .limit(limit)
            .all()
        )

        events = []

        for link in links:
            events.append({
                "type": "sighting",
                "timestamp": link.created_at.isoformat(),
                "source_type": link.link_type.value,
                "source_id": link.entity_id,
                "context": link.context,
            })

        for e in enrichments:
            events.append({
                "type": "enrichment",
                "timestamp": e.enriched_at.isoformat(),
                "source": e.source,
                "is_malicious": e.is_malicious,
                "score": e.score,
            })

        # Sort by timestamp descending
        events.sort(key=lambda x: x["timestamp"], reverse=True)
        return events[:limit]

    def get_activity_heatmap(
        self,
        observable_id: int,
        days: int = 30,
    ) -> Dict[str, int]:
        """Get activity heatmap data for an observable.

        Args:
            observable_id: Observable ID
            days: Number of days to include

        Returns:
            Dict mapping date strings to sighting counts
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=days)

        sightings = (
            self.session.query(
                func.date(ObservableLink.created_at).label("date"),
                func.count(ObservableLink.id).label("count"),
            )
            .filter(
                ObservableLink.observable_id == observable_id,
                ObservableLink.created_at >= cutoff,
            )
            .group_by(func.date(ObservableLink.created_at))
            .all()
        )

        return {str(s.date): s.count for s in sightings}

    # =========================================================================
    # Bulk Import (CSV/STIX)
    # =========================================================================

    def import_from_csv(
        self,
        csv_data: str,
        default_type: Optional[str] = None,
        auto_enrich: bool = False,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Import observables from CSV data.

        Expected CSV format:
        type,value,tags,notes
        ipv4,192.168.1.1,"malware,apt","Suspicious IP"
        domain,evil.com,,

        Args:
            csv_data: CSV string data
            default_type: Default type if not specified in CSV
            auto_enrich: Whether to auto-enrich imported observables
            tags: Additional tags to apply to all imports

        Returns:
            Import summary with counts
        """
        import csv
        from io import StringIO

        reader = csv.DictReader(StringIO(csv_data))

        created = 0
        updated = 0
        errors = []
        imported_ids = []

        for row_num, row in enumerate(reader, start=2):
            try:
                obs_type = row.get("type", default_type)
                value = row.get("value", "").strip()

                if not value:
                    errors.append({"row": row_num, "error": "Missing value"})
                    continue

                if not obs_type:
                    errors.append({"row": row_num, "error": "Missing type"})
                    continue

                # Parse tags
                row_tags = []
                if row.get("tags"):
                    row_tags = [t.strip() for t in row["tags"].split(",") if t.strip()]
                if tags:
                    row_tags.extend(tags)

                # Get or create observable
                obs, is_new = self.get_or_create(obs_type, value)
                imported_ids.append(obs.id)

                # Update fields
                if row_tags:
                    existing_tags = obs.tags or []
                    obs.tags = list(set(existing_tags + row_tags))

                if row.get("notes"):
                    if obs.notes:
                        obs.notes += f"\n{row['notes']}"
                    else:
                        obs.notes = row["notes"]

                if is_new:
                    created += 1
                else:
                    updated += 1

                # Record sighting
                self.record_sighting(
                    observable_id=obs.id,
                    source_type="import",
                    context="csv_import",
                )

            except Exception as e:
                errors.append({"row": row_num, "error": str(e)})

        self.session.flush()

        # Auto-enrich if requested
        enriched = 0
        if auto_enrich and imported_ids:
            for obs_id in imported_ids[:50]:  # Limit to 50 for performance
                try:
                    self.enrich(obs_id)
                    enriched += 1
                except Exception as e:
                    logger.warning(f"Failed to enrich observable {obs_id}: {e}")

        return {
            "created": created,
            "updated": updated,
            "enriched": enriched,
            "errors": errors,
            "total_processed": created + updated,
        }

    def import_from_stix(
        self,
        stix_bundle: Dict[str, Any],
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Import observables from STIX 2.1 bundle.

        Args:
            stix_bundle: STIX 2.1 bundle dict
            tags: Additional tags to apply

        Returns:
            Import summary
        """
        created = 0
        updated = 0
        errors = []
        imported_ids = []

        # STIX type to our type mapping
        stix_type_map = {
            "ipv4-addr": ObservableType.IPV4,
            "ipv6-addr": ObservableType.IPV6,
            "domain-name": ObservableType.DOMAIN,
            "url": ObservableType.URL,
            "email-addr": ObservableType.EMAIL,
            "file": None,  # Will check hashes
            "user-account": ObservableType.USER_ACCOUNT,
            "mac-addr": ObservableType.MAC_ADDRESS,
            "vulnerability": ObservableType.CVE,
        }

        objects = stix_bundle.get("objects", [])

        for obj in objects:
            obj_type = obj.get("type", "")

            # Skip non-observable types
            if not obj_type.endswith("-addr") and obj_type not in stix_type_map:
                continue

            try:
                our_type = stix_type_map.get(obj_type)
                value = None

                if obj_type == "file":
                    # Extract hash
                    hashes = obj.get("hashes", {})
                    if "SHA-256" in hashes:
                        our_type = ObservableType.FILE_HASH_SHA256
                        value = hashes["SHA-256"]
                    elif "SHA-1" in hashes:
                        our_type = ObservableType.FILE_HASH_SHA1
                        value = hashes["SHA-1"]
                    elif "MD5" in hashes:
                        our_type = ObservableType.FILE_HASH_MD5
                        value = hashes["MD5"]
                elif obj_type == "ipv4-addr" or obj_type == "ipv6-addr":
                    value = obj.get("value")
                elif obj_type == "domain-name":
                    value = obj.get("value")
                elif obj_type == "url":
                    value = obj.get("value")
                elif obj_type == "email-addr":
                    value = obj.get("value")
                elif obj_type == "user-account":
                    value = obj.get("account_login") or obj.get("user_id")
                elif obj_type == "mac-addr":
                    value = obj.get("value")
                elif obj_type == "vulnerability":
                    value = obj.get("name")

                if not our_type or not value:
                    continue

                obs, is_new = self.get_or_create(our_type, value)
                imported_ids.append(obs.id)

                # Apply tags
                if tags:
                    existing_tags = obs.tags or []
                    obs.tags = list(set(existing_tags + tags))

                # Store STIX ID reference
                stix_id = obj.get("id")
                if stix_id:
                    stix_tags = obs.tags or []
                    stix_tags.append(f"stix:{stix_id}")
                    obs.tags = stix_tags

                if is_new:
                    created += 1
                else:
                    updated += 1

                # Record sighting
                self.record_sighting(
                    observable_id=obs.id,
                    source_type="import",
                    context="stix_import",
                )

            except Exception as e:
                errors.append({"stix_id": obj.get("id"), "error": str(e)})

        self.session.flush()

        return {
            "created": created,
            "updated": updated,
            "errors": errors,
            "total_processed": created + updated,
        }

    def export_to_csv(
        self,
        observable_ids: Optional[List[int]] = None,
        types: Optional[List[ObservableType]] = None,
    ) -> str:
        """Export observables to CSV format.

        Args:
            observable_ids: Specific IDs to export (None = all)
            types: Filter by types

        Returns:
            CSV string
        """
        import csv
        from io import StringIO

        q = self.session.query(Observable)

        if observable_ids:
            q = q.filter(Observable.id.in_(observable_ids))

        if types:
            q = q.filter(Observable.type.in_(types))

        observables = q.order_by(Observable.type, Observable.value).all()

        output = StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "type", "value", "threat_level", "sighting_count",
            "first_seen", "last_seen", "is_whitelisted", "is_watched", "tags", "notes"
        ])

        for obs in observables:
            writer.writerow([
                obs.type.value,
                obs.value,
                obs.threat_level.value,
                obs.sighting_count,
                obs.first_seen.isoformat() if obs.first_seen else "",
                obs.last_seen.isoformat() if obs.last_seen else "",
                obs.is_whitelisted,
                obs.is_watched,
                ",".join(obs.tags) if obs.tags else "",
                obs.notes or "",
            ])

        return output.getvalue()

    # =========================================================================
    # Auto-Enrichment
    # =========================================================================

    def auto_enrich_new_observable(
        self,
        observable: Observable,
    ) -> Optional[ObservableEnrichment]:
        """Auto-enrich a new observable if enabled.

        Args:
            observable: The new observable

        Returns:
            Enrichment record if performed, None otherwise
        """
        if not observable.auto_enrich:
            return None

        # Skip if already enriched recently (within 24 hours)
        if observable.last_auto_enriched:
            from datetime import timedelta
            hours_since = (datetime.utcnow() - observable.last_auto_enriched).total_seconds() / 3600
            if hours_since < 24:
                return None

        try:
            enrichment = self.enrich(observable.id)
            observable.last_auto_enriched = datetime.utcnow()
            self.session.flush()
            return enrichment
        except Exception as e:
            logger.warning(f"Auto-enrichment failed for observable {observable.id}: {e}")
            return None

    def enable_auto_enrich(self, observable_id: int) -> Observable:
        """Enable auto-enrichment for an observable."""
        obs = self.get_by_id(observable_id)
        if not obs:
            raise ValueError(f"Observable {observable_id} not found")
        obs.auto_enrich = True
        self.session.flush()
        return obs

    def disable_auto_enrich(self, observable_id: int) -> Observable:
        """Disable auto-enrichment for an observable."""
        obs = self.get_by_id(observable_id)
        if not obs:
            raise ValueError(f"Observable {observable_id} not found")
        obs.auto_enrich = False
        self.session.flush()
        return obs

    def run_scheduled_enrichment(
        self,
        max_age_hours: int = 168,  # 7 days
        limit: int = 100,
    ) -> Dict[str, int]:
        """Run scheduled enrichment for observables that need updating.

        Args:
            max_age_hours: Re-enrich if last enrichment older than this
            limit: Max observables to process

        Returns:
            Summary of enrichment run
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)

        # Find observables that need enrichment
        # (auto_enrich enabled and either never enriched or stale)
        observables = (
            self.session.query(Observable)
            .filter(
                Observable.auto_enrich == True,
                or_(
                    Observable.last_auto_enriched.is_(None),
                    Observable.last_auto_enriched < cutoff,
                ),
            )
            .order_by(Observable.last_auto_enriched.asc().nullsfirst())
            .limit(limit)
            .all()
        )

        enriched = 0
        failed = 0

        for obs in observables:
            result = self.auto_enrich_new_observable(obs)
            if result:
                enriched += 1
            else:
                failed += 1

        return {
            "processed": len(observables),
            "enriched": enriched,
            "failed": failed,
        }

    # =========================================================================
    # Retention Policies
    # =========================================================================

    def apply_retention_policy(
        self,
        max_age_days: int = 365,
        min_sighting_count: int = 1,
        preserve_watched: bool = True,
        preserve_enriched: bool = True,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Apply retention policy to clean up old observables.

        Args:
            max_age_days: Delete observables not seen in this many days
            min_sighting_count: Only delete if sighting count is at or below this
            preserve_watched: Don't delete watched observables
            preserve_enriched: Don't delete observables with enrichment data
            dry_run: If True, only report what would be deleted

        Returns:
            Summary of what was (or would be) deleted
        """
        from datetime import timedelta

        cutoff = datetime.utcnow() - timedelta(days=max_age_days)

        q = self.session.query(Observable).filter(
            Observable.last_seen < cutoff,
            Observable.sighting_count <= min_sighting_count,
        )

        if preserve_watched:
            q = q.filter(Observable.is_watched == False)

        if preserve_enriched:
            # Subquery to find observables with enrichments
            enriched_ids = (
                self.session.query(ObservableEnrichment.observable_id)
                .distinct()
                .subquery()
            )
            q = q.filter(~Observable.id.in_(enriched_ids))

        candidates = q.all()

        summary = {
            "dry_run": dry_run,
            "candidates": len(candidates),
            "by_type": {},
            "deleted_ids": [],
        }

        # Count by type
        for obs in candidates:
            type_key = obs.type.value
            summary["by_type"][type_key] = summary["by_type"].get(type_key, 0) + 1

        if not dry_run and candidates:
            # Delete related records first
            obs_ids = [obs.id for obs in candidates]

            # Delete links (formerly sightings)
            self.session.query(ObservableLink).filter(
                ObservableLink.observable_id.in_(obs_ids)
            ).delete(synchronize_session=False)

            # Delete watchlist alerts
            self.session.query(WatchlistAlert).filter(
                WatchlistAlert.observable_id.in_(obs_ids)
            ).delete(synchronize_session=False)

            # Delete the observables (cascade will handle remaining links)
            for obs in candidates:
                summary["deleted_ids"].append(obs.id)
                self.session.delete(obs)

            self.session.flush()
            logger.info(f"Retention policy deleted {len(candidates)} observables")

        return summary

    def get_retention_preview(
        self,
        max_age_days: int = 365,
        min_sighting_count: int = 1,
    ) -> Dict[str, Any]:
        """Preview what would be deleted by retention policy.

        Args:
            max_age_days: Delete observables not seen in this many days
            min_sighting_count: Only delete if sighting count at or below this

        Returns:
            Preview of what would be deleted
        """
        return self.apply_retention_policy(
            max_age_days=max_age_days,
            min_sighting_count=min_sighting_count,
            dry_run=True,
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _resolve_type(self, type_str: str) -> ObservableType:
        """Resolve a string type to ObservableType enum.

        Args:
            type_str: Type string (may be legacy format)

        Returns:
            ObservableType enum value

        Raises:
            ValueError if type is unknown
        """
        type_str = type_str.lower().strip()

        # Check legacy map first
        if type_str in LEGACY_TYPE_MAP:
            return LEGACY_TYPE_MAP[type_str]

        # Try direct enum lookup
        try:
            return ObservableType(type_str)
        except ValueError:
            pass

        # Try by name
        try:
            return ObservableType[type_str.upper()]
        except KeyError:
            raise ValueError(f"Unknown observable type: {type_str}")

    def _to_opencti_type(self, obs_type: ObservableType) -> str:
        """Convert ObservableType to OpenCTI STIX type.

        Args:
            obs_type: Our observable type

        Returns:
            OpenCTI type string
        """
        mapping = {
            ObservableType.IPV4: "ipv4-addr",
            ObservableType.IPV6: "ipv6-addr",
            ObservableType.DOMAIN: "domain-name",
            ObservableType.HOSTNAME: "hostname",
            ObservableType.URL: "url",
            ObservableType.EMAIL: "email-addr",
            ObservableType.FILE_HASH_MD5: "file-md5",
            ObservableType.FILE_HASH_SHA1: "file-sha1",
            ObservableType.FILE_HASH_SHA256: "file-sha256",
            ObservableType.USER_ACCOUNT: "user_account",
            ObservableType.MAC_ADDRESS: "mac-addr",
            ObservableType.CVE: "vulnerability",
        }
        return mapping.get(obs_type, obs_type.value)


# Convenience function for getting service with session
def get_observable_service(session: Session) -> ObservableService:
    """Get an ObservableService instance.

    Args:
        session: SQLAlchemy session

    Returns:
        ObservableService instance
    """
    return ObservableService(session)
