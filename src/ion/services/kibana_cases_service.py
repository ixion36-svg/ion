"""Kibana Cases API integration service."""

import httpx
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime

from ion.core.config import get_kibana_config

logger = logging.getLogger(__name__)


class KibanaCasesService:
    """Service for interacting with Kibana Cases API."""

    def __init__(self):
        self.config = get_kibana_config()
        self._client: Optional[httpx.Client] = None

    @property
    def enabled(self) -> bool:
        """Check if Kibana Cases integration is enabled."""
        return self.config.get("enabled", False) and bool(self.config.get("url"))

    @property
    def client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            auth = None
            if self.config.get("username") and self.config.get("password"):
                auth = (self.config["username"], self.config["password"])

            from ion.core.config import get_ssl_verify
            self._client = httpx.Client(
                base_url=self.config["url"],
                auth=auth,
                verify=get_ssl_verify(self.config.get("verify_ssl", True)),
                headers={
                    "kbn-xsrf": "true",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def _get_api_path(self, path: str) -> str:
        """Get the full API path including space ID."""
        space_id = self.config.get("space_id", "default")
        if space_id and space_id != "default":
            return f"/s/{space_id}{path}"
        return path

    def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to Kibana."""
        if not self.enabled:
            return {"success": False, "error": "Kibana Cases integration not enabled"}

        try:
            response = self.client.get("/api/status")
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "version": data.get("version", {}).get("number", "unknown"),
                    "status": data.get("status", {}).get("overall", {}).get("level", "unknown"),
                }
            return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Kibana connection test failed: {e}")
            return {"success": False, "error": str(e)}

    def list_cases(
        self,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
        sort_field: str = "createdAt",
        sort_order: str = "desc",
    ) -> Dict[str, Any]:
        """List cases from Kibana.

        Args:
            status: Filter by status (open, in-progress, closed)
            page: Page number (1-indexed)
            per_page: Items per page
            sort_field: Field to sort by
            sort_order: Sort direction (asc/desc)
        """
        if not self.enabled:
            return {"cases": [], "total": 0, "error": "Kibana Cases not enabled"}

        try:
            params = {
                "page": page,
                "perPage": per_page,
                "sortField": sort_field,
                "sortOrder": sort_order,
            }
            if status:
                params["status"] = status

            path = self._get_api_path("/api/cases/_find")
            response = self.client.get(path, params=params)

            if response.status_code == 200:
                data = response.json()
                return {
                    "cases": data.get("cases", []),
                    "total": data.get("total", 0),
                    "page": data.get("page", page),
                    "per_page": data.get("perPage", per_page),
                }
            else:
                logger.error(f"Failed to list cases: {response.status_code} - {response.text}")
                return {"cases": [], "total": 0, "error": response.text}
        except Exception as e:
            logger.error(f"Error listing Kibana cases: {e}")
            return {"cases": [], "total": 0, "error": str(e)}

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific case by ID."""
        if not self.enabled:
            return None

        try:
            path = self._get_api_path(f"/api/cases/{case_id}")
            response = self.client.get(path)

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get case {case_id}: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting Kibana case {case_id}: {e}")
            return None

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "low",
        tags: Optional[List[str]] = None,
        connector: Optional[Dict] = None,
        settings: Optional[Dict] = None,
        assignees: Optional[List[Dict]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Create a new case in Kibana.

        Args:
            title: Case title
            description: Case description
            severity: Severity level (low, medium, high, critical)
            tags: List of tags
            connector: External connector config
            assignees: List of assignees (each with 'uid')
        """
        if not self.enabled:
            return None

        try:
            owner = self.config.get("case_owner", "securitySolution")

            payload = {
                "title": title,
                "description": description or "",
                "tags": tags or [],
                "severity": severity,
                "owner": owner,
                "connector": connector or {
                    "id": "none",
                    "name": "none",
                    "type": ".none",
                    "fields": None,
                },
                "settings": settings or {"syncAlerts": True},
            }

            if assignees:
                payload["assignees"] = assignees

            path = self._get_api_path("/api/cases")
            response = self.client.post(path, json=payload)

            if response.status_code in (200, 201):
                return response.json()
            else:
                logger.error(f"Failed to create case: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating Kibana case: {e}")
            return None

    def update_case(
        self,
        case_id: str,
        version: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        assignees: Optional[List[Dict]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Update an existing case.

        Handles two recurring failure modes:

        1. **Version conflict** (HTTP 500 with `version_conflict_engine_exception`,
           or HTTP 409). The Kibana cases API uses optimistic concurrency: every
           case carries a `version` field, and the PATCH must include the
           current version. If anyone else (the Kibana UI, another ION user,
           an alert closure) updates the case between us reading it and us
           writing, the version is stale and the PATCH fails. Recovery: re-read
           the case to get the latest version + current field values, then
           retry once.

        2. **No-op update** (HTTP 406 with "all update fields are identical to
           current version"). Kibana refuses PATCH requests where every field
           in the payload already matches the current state. Recovery: before
           sending, compare the desired payload to the current case and drop
           any field that's already at the target value. If everything matches,
           skip the network call entirely and return the current case as-is.

        Args:
            case_id: Case ID to update
            version: Current case version (used as a starting hint; we re-fetch
                     to make sure we have the freshest value)
            title / description / status / severity / tags / assignees: only
                pass values you actually want to change; ``None`` means "leave
                this field alone".
        """
        if not self.enabled:
            return None

        # Build the dict of fields the caller actually wants to change.
        desired: Dict[str, Any] = {}
        if title is not None:
            desired["title"] = title
        if description is not None:
            desired["description"] = description
        if status is not None:
            desired["status"] = status
        if severity is not None:
            desired["severity"] = severity
        if tags is not None:
            desired["tags"] = tags
        if assignees is not None:
            desired["assignees"] = assignees

        if not desired:
            # Nothing to do. Return the current case so callers can keep their
            # version pointer accurate.
            current = self.get_case(case_id)
            return current

        # Two attempts: first uses the version the caller passed in (cheap),
        # second re-fetches after a conflict (correct).
        for attempt in (0, 1):
            try:
                # On retry, always start from a fresh fetch.
                if attempt == 1 or not version:
                    current = self.get_case(case_id)
                    if not current:
                        logger.warning("update_case: case %s not found in Kibana", case_id)
                        return None
                    version = current.get("version")
                else:
                    current = None  # we'll fetch lazily if we need to filter

                # Filter out fields that are already at the target value to
                # avoid the 406 "all update fields are identical" error.
                if current is None:
                    current = self.get_case(case_id)
                    if not current:
                        return None

                changed = self._filter_unchanged_fields(desired, current)
                if not changed:
                    logger.debug("update_case: no field changes for %s, skipping PATCH", case_id)
                    return current

                payload = {
                    "cases": [
                        {
                            "id": case_id,
                            "version": version,
                            **changed,
                        }
                    ]
                }
                path = self._get_api_path("/api/cases")
                response = self.client.patch(path, json=payload)

                if response.status_code == 200:
                    cases = response.json()
                    return cases[0] if cases else current

                body_text = (response.text or "")[:500]
                lower_body = body_text.lower()

                # Detect version conflict — Kibana surfaces ES's
                # version_conflict_engine_exception either as a 500 with that
                # phrase in the body, or sometimes as a plain 409.
                is_version_conflict = (
                    response.status_code == 409
                    or "version_conflict" in lower_body
                    or "version conflict" in lower_body
                )
                # Detect "no-op already-applied" — Kibana returns 406 with
                # "all update fields are identical to current version".
                is_no_op = (
                    response.status_code == 406
                    or "identical to current version" in lower_body
                )

                if is_no_op:
                    logger.info(
                        "update_case: Kibana reports case %s already at target state",
                        case_id,
                    )
                    return current

                if is_version_conflict and attempt == 0:
                    logger.info(
                        "update_case: version conflict on %s, re-fetching and retrying",
                        case_id,
                    )
                    version = None  # force re-fetch on next loop
                    continue

                logger.warning(
                    "update_case failed for %s: HTTP %s — %s",
                    case_id, response.status_code, body_text,
                )
                return None

            except Exception as e:
                logger.warning("update_case error for %s: %s", case_id, type(e).__name__)
                return None

        # Out of retries
        return None

    @staticmethod
    def _filter_unchanged_fields(desired: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Drop any desired field whose value already matches the current case.

        Returns the subset of ``desired`` that actually represents a change.
        Used to avoid Kibana's 406 "all update fields are identical" error
        and to send the smallest possible patch.
        """
        out: Dict[str, Any] = {}
        for k, v in desired.items():
            cur = current.get(k)
            if k == "assignees":
                # Compare as sorted UID lists so reordering is not treated as a change.
                cur_uids = sorted(((a or {}).get("uid") or "") for a in (cur or []))
                new_uids = sorted(((a or {}).get("uid") or "") for a in (v or []))
                if cur_uids != new_uids:
                    out[k] = v
            elif k == "tags":
                cur_tags = sorted(cur or [])
                new_tags = sorted(v or [])
                if cur_tags != new_tags:
                    out[k] = v
            else:
                if cur != v:
                    out[k] = v
        return out

    def add_comment(
        self,
        case_id: str,
        comment: str,
        comment_type: str = "user",
    ) -> Optional[Dict[str, Any]]:
        """Add a comment to a case.

        Args:
            case_id: Case ID
            comment: Comment text
            comment_type: Type of comment (user, alert, actions)
        """
        if not self.enabled:
            return None

        try:
            owner = self.config.get("case_owner", "securitySolution")

            payload = {
                "comment": comment,
                "type": comment_type,
                "owner": owner,
            }

            path = self._get_api_path(f"/api/cases/{case_id}/comments")
            response = self.client.post(path, json=payload)

            if response.status_code in (200, 201):
                return response.json()
            else:
                logger.error(f"Failed to add comment: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error adding comment to Kibana case: {e}")
            return None

    def get_case_comments(self, case_id: str) -> List[Dict[str, Any]]:
        """Get all comments for a case."""
        if not self.enabled:
            return []

        try:
            path = self._get_api_path(f"/api/cases/{case_id}/comments/_find")
            response = self.client.get(path, params={"perPage": 100})

            if response.status_code == 200:
                data = response.json()
                return data.get("comments", [])
            else:
                logger.error(f"Failed to get comments: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error getting Kibana case comments: {e}")
            return []

    def get_case_alerts(self, case_id: str) -> List[Dict[str, Any]]:
        """Get all alerts attached to a case.

        Returns a list of alert references with 'id' and 'index' fields.
        Supports both Kibana 9.x (dedicated alerts endpoint) and 8.x (comment-based).
        """
        if not self.enabled:
            return []

        try:
            # Kibana 9.x: dedicated alerts endpoint
            alerts_path = self._get_api_path(f"/api/cases/{case_id}/alerts")
            alerts_response = self.client.get(alerts_path)
            if alerts_response.status_code == 200:
                alerts_data = alerts_response.json()
                if isinstance(alerts_data, list) and alerts_data:
                    return [
                        {"id": a["id"], "index": a.get("index", ".alerts-security.alerts-default")}
                        for a in alerts_data
                    ]

            # Kibana 8.x fallback: alerts stored as comment type "alert"
            path = self._get_api_path(f"/api/cases/{case_id}/comments/_find")
            response = self.client.get(path, params={"perPage": 100})

            comments = []
            if response.status_code == 200:
                comments = response.json().get("comments", [])

            if not comments:
                case_data = self.get_case(case_id)
                if case_data:
                    comments = case_data.get("comments", [])

            alerts = []
            for comment in comments:
                if comment.get("type") == "alert":
                    alert_ids = comment.get("alertId", [])
                    index = comment.get("index", ".alerts-security.alerts-default")

                    if isinstance(alert_ids, str):
                        alert_ids = [alert_ids]
                    if isinstance(index, str):
                        index = [index] * len(alert_ids)

                    for i, alert_id in enumerate(alert_ids):
                        alerts.append({
                            "id": alert_id,
                            "index": index[i] if i < len(index) else index[0],
                        })

            return alerts
        except Exception as e:
            logger.error(f"Error getting Kibana case alerts: {e}")
            return []

    def attach_alerts_to_case(
        self,
        case_id: str,
        alert_ids: List[str],
        alert_index: str = ".alerts-security.alerts-default",
    ) -> Optional[Dict[str, Any]]:
        """Attach alerts to a case.

        Args:
            case_id: Case ID
            alert_ids: List of alert IDs to attach
            alert_index: Elasticsearch index containing the alerts
        """
        if not self.enabled:
            return None

        if not alert_ids:
            return None

        owner = self.config.get("case_owner", "securitySolution")
        path = self._get_api_path(f"/api/cases/{case_id}/comments")
        last_response = None

        # Attach alerts one at a time to avoid ES version_conflict_engine_exception
        # when Kibana's syncAlerts updates alert documents concurrently.
        for aid in alert_ids:
            try:
                payload = {
                    "type": "alert",
                    "alertId": [aid],
                    "index": [alert_index],
                    "owner": owner,
                    "rule": {
                        "id": "manual-attachment",
                        "name": "Manual Alert Attachment",
                    },
                }

                response = self.client.post(path, json=payload)

                if response.status_code in (200, 201):
                    last_response = response.json()
                else:
                    logger.error(
                        "Failed to attach alert %s to case %s: %s - %s",
                        aid, case_id, response.status_code, response.text,
                    )
            except Exception as e:
                logger.error("Error attaching alert %s to Kibana case %s: %s", aid, case_id, e)

        return last_response

    def delete_case(self, case_id: str) -> bool:
        """Delete a case."""
        if not self.enabled:
            return False

        try:
            path = self._get_api_path("/api/cases")
            response = self.client.delete(path, params={"ids": case_id})

            if response.status_code in (200, 204):
                return True
            else:
                logger.error(f"Failed to delete case: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error deleting Kibana case: {e}")
            return False

    def suggest_user_profiles(self, name: str) -> List[Dict[str, Any]]:
        """Look up Kibana/Elastic user profile UIDs by username.

        Uses the Kibana internal security API to find user profiles.
        Returns list of profiles with 'uid', 'user.username', etc.
        """
        if not self.enabled:
            return []

        try:
            # Try Kibana's internal suggest endpoint (works on 8.x and 9.x)
            response = self.client.post(
                "/internal/security/user_profile/_suggest",
                json={"name": name, "size": 5},
            )
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, list) else data.get("profiles", [])

            # Fallback: try the public suggest endpoint (Kibana 9.x)
            response = self.client.post(
                "/api/security/user_profile/_suggest",
                json={"name": name, "size": 5},
            )
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, list) else data.get("profiles", [])

            logger.debug("Kibana user profile suggest returned %d", response.status_code)
            return []
        except Exception as e:
            logger.debug("Failed to suggest Kibana user profiles: %s", e)
            return []

    def resolve_user_uid(self, username: str) -> Optional[str]:
        """Resolve an ION username to a Kibana/Elastic user profile UID.

        Returns the profile UID string, or None if not found.
        """
        profiles = self.suggest_user_profiles(username)
        for profile in profiles:
            # Match exact username
            profile_user = profile.get("user", {})
            if isinstance(profile_user, dict) and profile_user.get("username") == username:
                return profile.get("uid")
        return None

    def get_case_url(self, case_id: str) -> str:
        """Get the Kibana UI URL for a case."""
        base_url = self.config.get("url", "").rstrip("/")
        space_id = self.config.get("space_id", "default")

        if space_id and space_id != "default":
            return f"{base_url}/s/{space_id}/app/security/cases/{case_id}"
        return f"{base_url}/app/security/cases/{case_id}"

    def close(self):
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None


# Singleton instance
_kibana_service: Optional[KibanaCasesService] = None


def get_kibana_cases_service() -> KibanaCasesService:
    """Get the singleton Kibana Cases service instance."""
    global _kibana_service
    if _kibana_service is None:
        _kibana_service = KibanaCasesService()
    return _kibana_service


def reset_kibana_cases_service():
    """Reset the singleton Kibana Cases service instance."""
    global _kibana_service
    if _kibana_service is not None:
        _kibana_service.close()
        _kibana_service = None
