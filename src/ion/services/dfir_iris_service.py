"""DFIR-IRIS API integration service."""

import httpx
import logging
from typing import Optional, Dict, Any, List

from ion.core.config import get_dfir_iris_config, get_ssl_verify

logger = logging.getLogger(__name__)

# Map ION observable type to DFIR-IRIS ioc_type_id (integer)
IOC_TYPE_MAP = {
    "ip": 77,           # ip-dst
    "ip-src": 79,       # ip-src
    "domain": 20,       # domain
    "url": 141,         # url
    "uri": 140,         # uri
    "hash": 90,         # md5 (fallback)
    "sha256": 113,      # sha256
    "sha1": 111,        # sha1
    "md5": 90,          # md5
    "email": 25,        # email-dst
    "file": 37,         # filename
    "filename": 37,     # filename
    "user_account": 133,  # target-user
    "hostname": 69,     # hostname
    "mac": 86,          # mac-address
    "registry": 109,    # regkey
}

# Map ION severity to DFIR-IRIS severity_id
SEVERITY_MAP = {
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# Map MITRE ATT&CK tactic names to DFIR-IRIS event_category_id
TACTIC_CATEGORY_MAP = {
    "initial access": 4,
    "execution": 5,
    "persistence": 6,
    "privilege escalation": 7,
    "defense evasion": 8,
    "credential access": 9,
    "discovery": 10,
    "lateral movement": 11,
    "collection": 12,
    "command and control": 13,
    "exfiltration": 14,
    "impact": 15,
    "remediation": 3,
}


class DFIRIRISService:
    """Service for interacting with DFIR-IRIS API (v2.4.x)."""

    def __init__(self):
        self.config = get_dfir_iris_config()
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def enabled(self) -> bool:
        return self.config.get("enabled", False) and self.is_configured

    @property
    def is_configured(self) -> bool:
        return bool(self.config.get("url")) and bool(self.config.get("api_key"))

    @property
    def url(self) -> str:
        return (self.config.get("url") or "").rstrip("/")

    @property
    def api_key(self) -> str:
        return self.config.get("api_key", "")

    def _get_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.url,
                headers=self._get_headers(),
                verify=get_ssl_verify(self.config.get("verify_ssl", True)),
                timeout=httpx.Timeout(30.0, connect=10.0),
            )
        return self._client

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> Dict[str, Any]:
        """Make an HTTP request to the DFIR-IRIS API.

        Returns the response JSON data dict. Raises on HTTP errors.
        IRIS wraps responses in {"status": "success", "data": {...}}.
        """
        client = await self._get_client()
        response = await client.request(method, path, **kwargs)
        response.raise_for_status()
        body = response.json()
        if isinstance(body, dict) and "data" in body:
            return body["data"]
        return body

    async def test_connection(self) -> Dict[str, Any]:
        """Test connectivity to DFIR-IRIS by listing cases."""
        try:
            client = await self._get_client()
            response = await client.get("/manage/cases/list")
            if response.status_code == 200:
                body = response.json()
                return {
                    "success": True,
                    "details": {
                        "status": body.get("status", "unknown"),
                        "message": "Connected to DFIR-IRIS",
                    },
                }
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
            }
        except httpx.ConnectError as e:
            return {"success": False, "error": f"Connection failed: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "medium",
        soc_id: str = "",
        customer_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Create a new case in DFIR-IRIS."""
        payload = {
            "case_name": title,
            "case_description": description,
            "case_customer": customer_id or self.config.get("default_customer", 1),
            "case_soc_id": soc_id,
        }
        return await self._request("POST", "/manage/cases/add", json=payload)

    async def add_ioc(
        self,
        case_id: int,
        value: str,
        ioc_type_id: int = 77,
        description: str = "",
        tlp_id: int = 2,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add an IOC to a DFIR-IRIS case.

        Args:
            case_id: IRIS case ID
            value: IOC value
            ioc_type_id: IRIS IOC type ID (integer, e.g., 77 for ip-dst)
            description: IOC description
            tlp_id: TLP level (1=white, 2=green, 3=amber, 4=red)
            tags: List of tags
        """
        payload = {
            "ioc_value": value,
            "ioc_type_id": ioc_type_id,
            "ioc_description": description,
            "ioc_tlp_id": tlp_id,
            "ioc_tags": ",".join(tags) if tags else "",
            "cid": case_id,
        }
        return await self._request("POST", "/case/ioc/add", json=payload)

    async def add_note(
        self,
        case_id: int,
        title: str,
        content: str,
        directory_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Add a note to a DFIR-IRIS case.

        Args:
            case_id: IRIS case ID
            title: Note title
            content: Note content (markdown supported)
            directory_id: Notes directory ID (creates one if None)
        """
        if directory_id is None:
            directory_id = await self._get_or_create_notes_directory(case_id)

        payload = {
            "note_title": title,
            "note_content": content,
            "directory_id": directory_id,
            "cid": case_id,
        }
        return await self._request("POST", "/case/notes/add", json=payload)

    async def _get_or_create_notes_directory(self, case_id: int) -> int:
        """Get or create an ION notes directory for a case."""
        try:
            data = await self._request(
                "GET", "/case/notes/directories/filter",
                params={"cid": case_id},
            )
            dirs = data if isinstance(data, list) else []
            for d in dirs:
                if d.get("name") == "ION Escalation Notes":
                    return d["id"]
            if dirs:
                return dirs[0]["id"]
        except Exception:
            pass

        # Create a new directory
        try:
            result = await self._request(
                "POST", "/case/notes/directories/add",
                json={"name": "ION Escalation Notes", "cid": case_id},
            )
            return result.get("id", 1)
        except Exception:
            return 1

    async def add_event(
        self,
        case_id: int,
        title: str,
        date: str,
        content: str = "",
        source: str = "ION",
        tags: Optional[List[str]] = None,
        category_id: int = 1,
    ) -> Dict[str, Any]:
        """Add a timeline event to a DFIR-IRIS case."""
        # IRIS requires microsecond format without tz suffix, plus empty arrays
        if "+" in date or date.endswith("Z"):
            date = date.split("+")[0].replace("Z", "")
        if "." not in date:
            date += ".000000"
        payload = {
            "event_title": title,
            "event_date": date,
            "event_content": content,
            "event_source": source,
            "event_tags": ",".join(tags) if tags else "",
            "event_tz": "+00:00",
            "event_category_id": category_id,
            "event_assets": [],
            "event_iocs": [],
            "cid": case_id,
        }
        return await self._request(
            "POST", "/case/timeline/events/add", json=payload
        )

    def map_tactic_to_category(self, tactic_name: str) -> int:
        """Map a MITRE tactic name to an IRIS event category ID."""
        if not tactic_name:
            return 1  # Unspecified
        return TACTIC_CATEGORY_MAP.get(tactic_name.lower(), 1)

    async def get_case(self, case_id: int) -> Dict[str, Any]:
        """Get a case by ID."""
        return await self._request(
            "GET", f"/manage/cases/{case_id}",
        )

    def get_case_url(self, case_id: int) -> str:
        """Get the browser URL for a DFIR-IRIS case."""
        return f"{self.url}/case?cid={case_id}"

    def map_ioc_type(self, observable_type: str) -> int:
        """Map an ION observable type to a DFIR-IRIS IOC type ID."""
        return IOC_TYPE_MAP.get(observable_type, 96)  # 96 = "other"

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


# Singleton instance
_dfir_iris_service: Optional[DFIRIRISService] = None


def get_dfir_iris_service() -> DFIRIRISService:
    """Get the DFIR-IRIS service instance. Re-creates if config changed."""
    global _dfir_iris_service
    if _dfir_iris_service is None:
        _dfir_iris_service = DFIRIRISService()
    else:
        # Re-read config in case it was updated via the admin wizard
        fresh_config = get_dfir_iris_config()
        if fresh_config != _dfir_iris_service.config:
            _dfir_iris_service = DFIRIRISService()
    return _dfir_iris_service
