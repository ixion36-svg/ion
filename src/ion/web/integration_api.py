"""Integration management API endpoints.

Provides endpoints for the integration dashboard, webhooks, and integration logs.
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_db_session, require_admin, get_current_user, get_client_ip, require_permission
from ion.models.user import User


def require_integration_access(user: User = Depends(require_permission("integration:read"))) -> User:
    """Require user to have integration:read permission."""
    return user
from ion.models.integration import (
    IntegrationType,
    IntegrationStatus,
    LogLevel,
    WebhookStatus,
)
from ion.services.connectors import get_connector_registry, ConnectorStatus
from ion.services.webhook_service import get_webhook_service
from ion.web.api import limiter
from ion.services.integration_log_service import get_integration_log_service

router = APIRouter(tags=["integrations"])


# =============================================================================
# Request/Response Models
# =============================================================================

class WebhookCreate(BaseModel):
    """Request model for creating a webhook."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    source_type: str = Field(default="custom")
    secret: Optional[str] = Field(default=None, description="HMAC secret for signature verification")
    event_types: Optional[List[str]] = Field(default=None, description="List of allowed event types")


class WebhookUpdate(BaseModel):
    """Request model for updating a webhook."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    secret: Optional[str] = None
    event_types: Optional[List[str]] = None
    is_active: Optional[bool] = None


class WebhookResponse(BaseModel):
    """Response model for a webhook."""
    id: int
    name: str
    description: Optional[str]
    source_type: str
    event_types: Optional[List[str]]
    is_active: bool
    created_by_id: Optional[int]
    last_triggered_at: Optional[str]
    trigger_count: int
    created_at: Optional[str]
    updated_at: Optional[str]
    has_secret: bool
    token: Optional[str] = None  # Only included when specifically requested

    class Config:
        from_attributes = True


class WebhookLogResponse(BaseModel):
    """Response model for a webhook log entry."""
    id: int
    webhook_id: int
    event_type: Optional[str]
    payload: Optional[dict]
    headers: Optional[dict]
    source_ip: Optional[str]
    status: str
    error_message: Optional[str]
    processing_time_ms: Optional[float]
    created_at: Optional[str]

    class Config:
        from_attributes = True


class IntegrationStatusResponse(BaseModel):
    """Response model for integration status."""
    type: str
    display_name: str
    is_configured: bool
    is_enabled: bool
    status: Optional[str] = None
    response_time_ms: Optional[float] = None
    last_check: Optional[str] = None
    error: Optional[str] = None
    metadata: Optional[dict] = None


class IntegrationLogResponse(BaseModel):
    """Response model for an integration log entry."""
    id: int
    integration_type: str
    level: str
    action: str
    message: str
    details: Optional[dict]
    user_id: Optional[int]
    timestamp: Optional[str]

    class Config:
        from_attributes = True


class HealthCheckResponse(BaseModel):
    """Response model for health check results."""
    integration_type: str
    status: str
    response_time_ms: float
    error: Optional[str] = None
    metadata: Optional[dict] = None


# =============================================================================
# Integration Dashboard Endpoints
# =============================================================================

@router.get("/status", response_model=List[IntegrationStatusResponse])
async def get_integration_status(
    current_user: User = Depends(require_integration_access),
):
    """Get status of all integrations."""
    registry = get_connector_registry()
    log_service = get_integration_log_service()

    # Get latest health checks
    latest_checks = log_service.get_latest_health_checks()

    results = []
    for connector in registry.get_all():
        status_info = connector.get_status_info()

        # Get latest health check for this integration
        latest_check = latest_checks.get(connector.CONNECTOR_TYPE)

        response = IntegrationStatusResponse(
            type=connector.CONNECTOR_TYPE,
            display_name=connector.DISPLAY_NAME,
            is_configured=status_info.get("is_configured", False),
            is_enabled=status_info.get("is_enabled", False),
            metadata=status_info,
        )

        if latest_check:
            response.status = latest_check.health_status.value if hasattr(latest_check.health_status, 'value') else str(latest_check.health_status)
            response.response_time_ms = latest_check.response_time_ms
            response.last_check = latest_check.checked_at.isoformat() if latest_check.checked_at else None
            response.error = latest_check.error_message
            # Merge health check metadata (includes version_compatibility) into response
            if latest_check.check_metadata:
                response.metadata = {**(response.metadata or {}), **latest_check.check_metadata}

        results.append(response)

    return results


@router.post("/healthcheck", response_model=List[HealthCheckResponse])
async def run_health_checks(
    current_user: User = Depends(require_integration_access),
):
    """Run health checks on all integrations."""
    registry = get_connector_registry()
    log_service = get_integration_log_service()

    # Run health checks
    check_results = await registry.healthcheck_all()

    results = []
    for integration_type, result in check_results.items():
        # Record the health check
        status = IntegrationStatus.HEALTHY
        if result.status == ConnectorStatus.ERROR:
            status = IntegrationStatus.ERROR
        elif result.status == ConnectorStatus.DEGRADED:
            status = IntegrationStatus.DEGRADED
        elif result.status == ConnectorStatus.NOT_CONFIGURED:
            status = IntegrationStatus.DISABLED

        # Map integration type string to enum
        try:
            int_type_enum = IntegrationType(integration_type)
        except ValueError:
            int_type_enum = IntegrationType.CUSTOM

        log_service.record_health_check(
            integration_type=int_type_enum,
            status=status,
            response_time_ms=result.response_time_ms,
            error_message=result.error,
            metadata=result.metadata,
        )

        # Log the health check
        log_service.log_info(
            integration_type=int_type_enum,
            action="healthcheck",
            message=f"Health check: {result.status.value}",
            details=result.to_dict(),
            user_id=current_user.id,
        )

        results.append(HealthCheckResponse(
            integration_type=integration_type,
            status=result.status.value,
            response_time_ms=result.response_time_ms,
            error=result.error,
            metadata=result.metadata,
        ))

    return results


@router.get("/{integration_type}/config-schema")
async def get_config_schema(
    integration_type: str,
    current_user: User = Depends(require_integration_access),
):
    """Get configuration schema for an integration."""
    registry = get_connector_registry()
    connector = registry.get(integration_type)

    if not connector:
        raise HTTPException(status_code=404, detail=f"Integration type '{integration_type}' not found")

    return connector.get_config_schema()


# =============================================================================
# Webhook Endpoints
# =============================================================================

@router.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """List all webhooks."""
    webhook_service = get_webhook_service()

    source_type_enum = None
    if source_type:
        try:
            source_type_enum = IntegrationType(source_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid source type: {source_type}")

    webhooks = webhook_service.list_webhooks(
        source_type=source_type_enum,
        is_active=is_active,
        session=session,
    )

    return [WebhookResponse(**w.to_dict(include_token=False)) for w in webhooks]


@router.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(
    data: WebhookCreate,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Create a new webhook."""
    webhook_service = get_webhook_service()

    try:
        source_type_enum = IntegrationType(data.source_type)
    except ValueError:
        source_type_enum = IntegrationType.CUSTOM

    webhook = webhook_service.create_webhook(
        name=data.name,
        description=data.description,
        source_type=source_type_enum,
        secret=data.secret,
        event_types=data.event_types,
        created_by_id=current_user.id,
        session=session,
    )

    # Log the creation
    log_service = get_integration_log_service()
    log_service.log_info(
        integration_type=source_type_enum,
        action="webhook_create",
        message=f"Created webhook: {webhook.name}",
        details={"webhook_id": webhook.id},
        user_id=current_user.id,
    )

    # Return with token for initial creation
    return WebhookResponse(**webhook.to_dict(include_token=True))


@router.get("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: int,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get a webhook by ID."""
    webhook_service = get_webhook_service()
    webhook = webhook_service.get_webhook(webhook_id, session=session)

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(**webhook.to_dict(include_token=False))


@router.put("/webhooks/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: int,
    data: WebhookUpdate,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Update a webhook."""
    webhook_service = get_webhook_service()

    webhook = webhook_service.update_webhook(
        webhook_id=webhook_id,
        name=data.name,
        description=data.description,
        secret=data.secret,
        event_types=data.event_types,
        is_active=data.is_active,
        session=session,
    )

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return WebhookResponse(**webhook.to_dict(include_token=False))


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Delete a webhook."""
    webhook_service = get_webhook_service()

    if not webhook_service.delete_webhook(webhook_id, session=session):
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"success": True, "message": "Webhook deleted"}


@router.post("/webhooks/{webhook_id}/regenerate-token")
@limiter.limit("3/minute")
async def regenerate_webhook_token(
    request: Request,
    webhook_id: int,
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Regenerate the token for a webhook."""
    webhook_service = get_webhook_service()

    new_token = webhook_service.regenerate_token(webhook_id, session=session)

    if not new_token:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"success": True, "token": new_token}


@router.post("/webhooks/receive/{token}")
async def receive_webhook(
    token: str,
    request: Request,
):
    """Receive a webhook event (public endpoint).

    This endpoint does not require authentication - it uses the token
    for identification and optional HMAC signature for verification.
    """
    webhook_service = get_webhook_service()

    # Get raw body for signature verification
    raw_body = await request.body()

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        return {"success": False, "error": "Invalid JSON payload"}

    # Extract event type from headers or payload
    event_type = (
        request.headers.get("X-Event-Type") or
        request.headers.get("X-GitLab-Event") or
        request.headers.get("X-GitHub-Event") or
        payload.get("event_type") or
        payload.get("object_kind") or
        "unknown"
    )

    # Extract signature from headers
    signature = (
        request.headers.get("X-Hub-Signature-256") or
        request.headers.get("X-GitLab-Token") or
        request.headers.get("X-Signature")
    )

    # Get client IP
    source_ip = get_client_ip(request)

    # Convert headers to dict
    headers = dict(request.headers)

    # Process the webhook
    result = await webhook_service.process_webhook(
        token=token,
        event_type=event_type,
        payload=payload,
        headers=headers,
        source_ip=source_ip,
        signature=signature,
        raw_payload=raw_body,
    )

    if not result.get("success"):
        status_code = 400
        if result.get("status") == "not_found":
            status_code = 404
        elif result.get("status") == "invalid_signature":
            status_code = 401
        raise HTTPException(status_code=status_code, detail=result.get("error"))

    return {"success": True, "message": "Webhook processed"}


@router.get("/webhooks/{webhook_id}/logs", response_model=List[WebhookLogResponse])
async def get_webhook_logs(
    webhook_id: int,
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get logs for a webhook."""
    webhook_service = get_webhook_service()

    # Verify webhook exists
    webhook = webhook_service.get_webhook(webhook_id, session=session)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    status_enum = None
    if status:
        try:
            status_enum = WebhookStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    logs = webhook_service.get_webhook_logs(
        webhook_id=webhook_id,
        status=status_enum,
        limit=limit,
        offset=offset,
        session=session,
    )

    return [WebhookLogResponse(**log.to_dict()) for log in logs]


# =============================================================================
# Integration Log Endpoints
# =============================================================================

@router.get("/logs", response_model=List[IntegrationLogResponse])
async def get_integration_logs(
    integration_type: Optional[str] = Query(None, description="Filter by integration type"),
    level: Optional[str] = Query(None, description="Filter by log level"),
    action: Optional[str] = Query(None, description="Filter by action"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get integration activity logs."""
    log_service = get_integration_log_service()

    integration_type_enum = None
    if integration_type:
        try:
            integration_type_enum = IntegrationType(integration_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid integration type: {integration_type}")

    level_enum = None
    if level:
        try:
            level_enum = LogLevel(level)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid log level: {level}")

    logs = log_service.get_logs(
        integration_type=integration_type_enum,
        level=level_enum,
        action=action,
        hours=hours,
        limit=limit,
        offset=offset,
        session=session,
    )

    return [IntegrationLogResponse(**log.to_dict()) for log in logs]


@router.get("/logs/stats")
async def get_log_stats(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get integration log statistics."""
    log_service = get_integration_log_service()
    return log_service.get_log_stats(hours=hours, session=session)


@router.get("/health-history")
async def get_health_history(
    integration_type: Optional[str] = Query(None, description="Filter by integration type"),
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    limit: int = Query(100, ge=1, le=500),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get health check history."""
    log_service = get_integration_log_service()

    integration_type_enum = None
    if integration_type:
        try:
            integration_type_enum = IntegrationType(integration_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid integration type: {integration_type}")

    history = log_service.get_health_history(
        integration_type=integration_type_enum,
        hours=hours,
        limit=limit,
        session=session,
    )

    return [h.to_dict() for h in history]


# =============================================================================
# Metrics Endpoints
# =============================================================================

@router.get("/metrics/elasticsearch")
async def get_elasticsearch_metrics(
    current_user: User = Depends(require_integration_access),
):
    """Get Elasticsearch cluster health and ingestion metrics."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es_service = ElasticsearchService()

    if not es_service.is_configured:
        return {
            "configured": False,
            "error": "Elasticsearch is not configured",
        }

    # Gather all metrics in parallel
    cluster_health = await es_service.get_cluster_health()
    index_stats = await es_service.get_index_stats()
    ingest_stats = await es_service.get_ingest_stats()

    return {
        "configured": True,
        "cluster": cluster_health,
        "indices": index_stats,
        "ingest": ingest_stats,
    }


@router.get("/metrics/server")
async def get_server_metrics(
    current_user: User = Depends(require_integration_access),
):
    """Get server health metrics."""
    import psutil
    import os
    from datetime import datetime

    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=0.1)

        # Memory usage
        memory = psutil.virtual_memory()

        # Disk usage for current directory
        disk = psutil.disk_usage(os.getcwd())

        # Process info
        process = psutil.Process()
        process_memory = process.memory_info()

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "cpu": {
                "percent": cpu_percent,
                "count": psutil.cpu_count(),
            },
            "memory": {
                "total_gb": round(memory.total / 1024 / 1024 / 1024, 2),
                "available_gb": round(memory.available / 1024 / 1024 / 1024, 2),
                "used_percent": memory.percent,
            },
            "disk": {
                "total_gb": round(disk.total / 1024 / 1024 / 1024, 2),
                "free_gb": round(disk.free / 1024 / 1024 / 1024, 2),
                "used_percent": disk.percent,
            },
            "process": {
                "memory_mb": round(process_memory.rss / 1024 / 1024, 2),
                "threads": process.num_threads(),
            },
        }
    except Exception as e:
        return {"error": str(e)}


@router.get("/metrics/server-logs")
async def get_server_log_metrics(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    current_user: User = Depends(require_integration_access),
):
    """Get server log metrics from Elasticsearch."""
    from ion.services.elasticsearch_service import ElasticsearchService

    es_service = ElasticsearchService()

    if not es_service.is_configured:
        return {"configured": False, "error": "Elasticsearch is not configured"}

    try:
        # Query ion-logs index for stats
        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "by_level": {
                    "terms": {"field": "log.level.keyword", "size": 10}
                },
                "by_logger": {
                    "terms": {"field": "log.logger.keyword", "size": 10}
                },
                "by_status": {
                    "terms": {"field": "http.response.status_code", "size": 10}
                },
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        "min_doc_count": 0
                    }
                }
            }
        }

        import httpx
        from ion.core.config import get_elasticsearch_config
        config = get_elasticsearch_config()

        # Use the ES service's credentials - it already loaded them correctly
        auth = None
        headers = {"Content-Type": "application/json"}
        if es_service.api_key:
            headers["Authorization"] = f"ApiKey {es_service.api_key}"
        elif es_service.username and es_service.password:
            auth = (es_service.username, es_service.password)

        verify_ssl = es_service.verify_ssl
        # For localhost HTTP, disable SSL verification
        if es_service.url.startswith("http://"):
            verify_ssl = False

        url = f"{es_service.url}/ion-logs-*/_search"

        from ion.core.config import get_ssl_verify
        async with httpx.AsyncClient(verify=get_ssl_verify(verify_ssl), timeout=10.0) as client:
            response = await client.post(
                url,
                headers=headers,
                auth=auth,
                json=query,
            )

            data = response.json()

            # Check for various error conditions
            if response.status_code == 404:
                return {
                    "configured": True,
                    "total": 0,
                    "by_level": {},
                    "by_logger": {},
                    "by_status": {},
                    "over_time": [],
                    "note": "Log index not found - logs will appear after server activity",
                }

            if "error" in data:
                return {
                    "configured": True,
                    "error": data.get("error", {}).get("reason", str(data["error"])),
                }

            if response.status_code >= 400:
                return {
                    "configured": True,
                    "error": f"Elasticsearch returned status {response.status_code}",
                }

        # Get total
        total_data = data.get("hits", {}).get("total", {})
        total = total_data.get("value", 0) if isinstance(total_data, dict) else total_data

        # Parse aggregations
        by_level = {}
        for bucket in data.get("aggregations", {}).get("by_level", {}).get("buckets", []):
            by_level[bucket["key"]] = bucket["doc_count"]

        by_logger = {}
        for bucket in data.get("aggregations", {}).get("by_logger", {}).get("buckets", []):
            by_logger[bucket["key"]] = bucket["doc_count"]

        by_status = {}
        for bucket in data.get("aggregations", {}).get("by_status", {}).get("buckets", []):
            by_status[str(bucket["key"])] = bucket["doc_count"]

        over_time = []
        for bucket in data.get("aggregations", {}).get("over_time", {}).get("buckets", []):
            over_time.append({
                "time": bucket["key_as_string"],
                "count": bucket["doc_count"],
            })

        return {
            "configured": True,
            "total": total,
            "by_level": by_level,
            "by_logger": by_logger,
            "by_status": by_status,
            "over_time": over_time[-24:],  # Last 24 data points
            "hours": hours,
        }

    except Exception as e:
        return {"configured": True, "error": str(e)}


@router.get("/metrics/data-flows")
async def get_data_flow_metrics(
    hours: int = Query(24, ge=1, le=168, description="Time window in hours"),
    session: Session = Depends(get_db_session),
    current_user: User = Depends(require_integration_access),
):
    """Get data flow metrics between integrations."""
    from ion.services.elasticsearch_service import ElasticsearchService

    log_service = get_integration_log_service()

    # Get log stats for each integration
    log_stats = log_service.get_log_stats(hours=hours, session=session)

    # Get webhook stats
    webhook_service = get_webhook_service()
    webhooks = webhook_service.list_webhooks(session=session)

    webhook_stats = {
        "total_webhooks": len(webhooks),
        "active_webhooks": sum(1 for w in webhooks if w.is_active),
        "total_triggers": sum(w.trigger_count for w in webhooks),
    }

    # Get Elasticsearch document flow
    es_service = ElasticsearchService()
    es_flow = {}
    if es_service.is_configured:
        try:
            index_stats = await es_service.get_index_stats()
            es_flow = {
                "documents_indexed": index_stats.get("index_total", 0),
                "searches_performed": index_stats.get("search_total", 0),
                "current_docs": index_stats.get("total_docs", 0),
            }
        except Exception:
            es_flow = {"error": "Failed to get ES stats"}

    return {
        "time_window_hours": hours,
        "integration_activity": log_stats,
        "webhooks": webhook_stats,
        "elasticsearch": es_flow,
    }
