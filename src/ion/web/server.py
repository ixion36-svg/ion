"""FastAPI web server for ION - Intelligent Operating Network."""

import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request, Depends
from ion.models.user import User
from ion.auth.dependencies import require_page_auth, require_page_permission
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse

# Use orjson for JSON serialisation if available (5-10x faster than stdlib).
try:
    import orjson

    class ORJSONResponse(JSONResponse):
        media_type = "application/json"
        def render(self, content) -> bytes:
            return orjson.dumps(content, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY)

    _default_response_class = ORJSONResponse
except ImportError:
    _default_response_class = JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import ion
from ion.web.api import router as api_router, limiter
from ion.core.config import get_config as get_app_config
from ion.web.security_api import router as security_router
from ion.web.integration_api import router as integration_router
from ion.web.admin_api import router as admin_router
from ion.web.observable_api import router as observable_router
from ion.web.ai_api import router as ai_router
from ion.web.kibana_api import router as kibana_router
from ion.web.skills_api import router as skills_router
from ion.web.notes_api import router as notes_router
from ion.web.pcap_api import router as pcap_router
from ion.web.forensics_api import router as forensics_router
from ion.web.threat_intel_api import router as threat_intel_router
from ion.web.threat_watch_gap_api import router as threat_watch_gap_router
from ion.web.notification_api import router as notification_router
from ion.web.cyab_api import router as cyab_router
from ion.web.social_api import router as social_router
from ion.web.analytics_api import router as analytics_router
from ion.web.engineering_analytics_api import router as engineering_analytics_router
from ion.web.shift_handover_api import router as shift_handover_router
from ion.web.rule_tuning_api import router as rule_tuning_router
from ion.web.entity_timeline_api import router as entity_timeline_router
from ion.web.analyst_efficiency_api import router as analyst_efficiency_router
from ion.web.soc_health_api import router as soc_health_router
from ion.web.attack_story_api import router as attack_story_router
from ion.web.case_similarity_api import router as case_similarity_router
from ion.web.triage_suggestion_api import router as triage_suggestion_router
from ion.web.mitre_navigator_api import router as mitre_navigator_router
from ion.web.playbook_analytics_api import router as playbook_analytics_router
from ion.web.alert_pattern_api import router as alert_pattern_router
from ion.web.d3fend_api import router as d3fend_router
from ion.web.canary_api import router as canary_router
from ion.web.log_source_api import router as log_source_router
from ion.web.briefing_api import router as briefing_router
from ion.web.knowledge_graph_api import router as knowledge_graph_router
from ion.web.pir_api import router as pir_router
from ion.web.emulation_api import router as emulation_router
from ion.web.vulnerability_api import router as vulnerability_router
from ion.web.maturity_api import router as maturity_router
from ion.web.executive_report_api import router as executive_report_router
from ion.web.ioc_staleness_api import router as ioc_staleness_router
from ion.web.training_sim_api import router as training_sim_router
from ion.web.service_account_api import router as service_account_router
from ion.web.incident_cost_api import router as incident_cost_router
from ion.web.compliance_api import router as compliance_router
from ion.web.comm_template_api import router as comm_template_router
from ion.web.change_log_api import router as change_log_router
from ion.web.saved_search_api import router as saved_search_router
from ion.web.oncall_api import router as oncall_router
from ion.web.sla_api import router as sla_router
from ion.web.bulk_ops_api import router as bulk_ops_router
from ion.web.threat_hunt_api import router as threat_hunt_router
from ion.web.dashboard_layout_api import router as dashboard_layout_router
from ion.web.report_scheduler_api import router as report_scheduler_router
from ion.web.playbook_action_api import router as playbook_action_router
from ion.web.cyber_range_api import router as cyber_range_router
from ion.core.config import get_config, get_elasticsearch_config
from ion.core.logging import setup_logging, get_logger
from ion.storage.database import init_db
from ion.web.logging_middleware import RequestLoggingMiddleware
from ion.web.security_middleware import SecurityMonitoringMiddleware, RateLimitSecurityMiddleware

# Initialize logging with Elasticsearch if configured
import os
es_config = get_elasticsearch_config()
if es_config.get("url"):
    os.environ.setdefault("ION_ES_LOG_URL", es_config.get("url", ""))
    if es_config.get("api_key"):
        os.environ.setdefault("ION_ES_API_KEY", es_config.get("api_key", ""))
    if es_config.get("username"):
        os.environ.setdefault("ION_ES_USERNAME", es_config.get("username", ""))
    if es_config.get("password"):
        os.environ.setdefault("ION_ES_PASSWORD", es_config.get("password", ""))

es_log_url = es_config.get("url") if es_config.get("url") else None
setup_logging(elasticsearch_url=es_log_url)
logger = get_logger(__name__)

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Check if debug mode is enabled for API docs
_app_config = get_app_config()
_debug_mode = _app_config.debug_mode

if _debug_mode:
    logger.warning(
        "SECURITY: Debug mode is ON — /docs, /redoc, and /openapi.json are publicly "
        "accessible. Set ION_DEBUG_MODE=false for production deployments."
    )

if not _app_config.cookie_secure:
    logger.warning(
        "SECURITY: cookie_secure is OFF — session cookies will not have the Secure "
        "flag unless HTTPS is auto-detected. Set ION_COOKIE_SECURE=true behind a "
        "TLS terminator or reverse proxy."
    )

app = FastAPI(
    title="ION",
    description="Intelligent Operating Network - Security Operations Portal for Guarded Glass",
    version=ion.__version__,
    # Use orjson for ~5x faster JSON serialisation on all API responses.
    default_response_class=_default_response_class,
    # Disable API docs in production (when debug_mode is False)
    docs_url="/docs" if _debug_mode else None,
    redoc_url="/redoc" if _debug_mode else None,
    openapi_url="/openapi.json" if _debug_mode else None,
)


# =============================================================================
# Security Headers Middleware
# =============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # XSS protection (legacy, but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # HTTP Strict Transport Security (HSTS)
        # Only set when request is HTTPS to avoid issues during development
        if request.url.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy
        # NOTE: 'unsafe-inline' in script-src is required because the app uses
        # onclick handlers extensively.  DOMPurify sanitises all dynamic HTML so
        # the practical XSS risk is mitigated.  object-src and base-uri are
        # locked down to block plugin-based and base-tag attacks.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )

        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        return response


# Add GZip compression — compresses all responses > 500 bytes.
# Typically 60-80% smaller for HTML/JSON/CSS/JS, major bandwidth + perceived speed win.
from starlette.middleware.gzip import GZipMiddleware
app.add_middleware(GZipMiddleware, minimum_size=500)

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Add security monitoring middleware (attack detection)
app.add_middleware(SecurityMonitoringMiddleware)

# Add rate limit security tracking
app.add_middleware(RateLimitSecurityMiddleware)

# Add request logging middleware (ECS-compliant)
app.add_middleware(RequestLoggingMiddleware)

# Configure rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Mount static files with cache-control headers for browser caching.
# CSS/JS/fonts don't change between deploys, so 24h cache is safe.
# Cache is busted by the version in the URL (ion_version in templates).
from starlette.staticfiles import StaticFiles as _StaticFiles
from starlette.responses import Response as _StaticResponse


class CachedStaticFiles(_StaticFiles):
    """StaticFiles with Cache-Control headers for browser caching."""
    async def get_response(self, path: str, scope) -> _StaticResponse:
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            # 24h cache for immutable assets (CSS, JS, fonts, images)
            response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=3600"
        return response


app.mount("/static", CachedStaticFiles(directory=BASE_DIR / "static"), name="static")

# Setup templates
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.globals["ion_version"] = ion.__version__

# Include API routes
app.include_router(api_router, prefix="/api")
app.include_router(security_router, prefix="/api/security")
app.include_router(integration_router, prefix="/api/integrations")
app.include_router(admin_router, prefix="/api/admin")
app.include_router(observable_router, prefix="/api")
app.include_router(ai_router)
app.include_router(kibana_router, prefix="/api/kibana")
app.include_router(skills_router, prefix="/api/skills")
app.include_router(notes_router, prefix="/api/notes")
app.include_router(pcap_router, prefix="/api/pcap")
app.include_router(forensics_router, prefix="/api/forensics")
app.include_router(notification_router, prefix="/api")
app.include_router(social_router, prefix="/api/social")
app.include_router(analytics_router, prefix="/api/analytics")
app.include_router(engineering_analytics_router, prefix="/api/engineering/analytics")
app.include_router(cyab_router, prefix="/api/cyab")
app.include_router(threat_intel_router, prefix="/api/threat-intel")
app.include_router(threat_watch_gap_router, prefix="/api/threat-intel")
app.include_router(shift_handover_router, prefix="/api")
app.include_router(rule_tuning_router, prefix="/api")
app.include_router(entity_timeline_router, prefix="/api")
app.include_router(analyst_efficiency_router, prefix="/api")
app.include_router(soc_health_router, prefix="/api")
app.include_router(attack_story_router, prefix="/api")
app.include_router(case_similarity_router, prefix="/api")
app.include_router(triage_suggestion_router, prefix="/api")
app.include_router(mitre_navigator_router, prefix="/api")
app.include_router(playbook_analytics_router, prefix="/api")
app.include_router(alert_pattern_router, prefix="/api")
app.include_router(d3fend_router, prefix="/api")
app.include_router(canary_router, prefix="/api")
app.include_router(log_source_router, prefix="/api")
app.include_router(briefing_router, prefix="/api")
app.include_router(knowledge_graph_router, prefix="/api")
app.include_router(pir_router, prefix="/api")
app.include_router(emulation_router, prefix="/api")
app.include_router(vulnerability_router, prefix="/api")
app.include_router(maturity_router, prefix="/api")
app.include_router(executive_report_router, prefix="/api")
app.include_router(ioc_staleness_router, prefix="/api")
app.include_router(training_sim_router, prefix="/api")
app.include_router(service_account_router, prefix="/api")
app.include_router(incident_cost_router, prefix="/api")
app.include_router(compliance_router, prefix="/api")
app.include_router(comm_template_router, prefix="/api")
app.include_router(change_log_router, prefix="/api")
app.include_router(saved_search_router, prefix="/api")
app.include_router(oncall_router, prefix="/api")
app.include_router(sla_router, prefix="/api")
app.include_router(bulk_ops_router, prefix="/api")
app.include_router(threat_hunt_router, prefix="/api")
app.include_router(dashboard_layout_router, prefix="/api")
app.include_router(report_scheduler_router, prefix="/api")
app.include_router(playbook_action_router, prefix="/api")
app.include_router(cyber_range_router, prefix="/api")


def _validate_startup_config():
    """Validate critical configuration at startup. Log warnings for optional issues, raise for fatal ones."""
    import os
    warnings = []
    errors = []

    # Database
    db_url = os.environ.get("ION_DATABASE_URL", "")
    if not db_url:
        warnings.append("ION_DATABASE_URL not set — falling back to SQLite (not recommended for production)")

    # Admin password
    admin_pw = os.environ.get("ION_ADMIN_PASSWORD", "changeme")
    if admin_pw in ("changeme", "password", "admin"):
        # Do not echo the actual password value into logs
        warnings.append("ION_ADMIN_PASSWORD is set to a weak default — change it for production")

    # Elasticsearch
    if os.environ.get("ION_ELASTICSEARCH_ENABLED", "").lower() == "true":
        es_url = os.environ.get("ION_ELASTICSEARCH_URL", "")
        if not es_url:
            errors.append("ION_ELASTICSEARCH_ENABLED=true but ION_ELASTICSEARCH_URL is not set")
        elif "REPLACE_WITH" in es_url:
            errors.append(f"ION_ELASTICSEARCH_URL contains placeholder: {es_url}")

    # TIDE
    if os.environ.get("ION_TIDE_ENABLED", "").lower() == "true":
        tide_url = os.environ.get("ION_TIDE_URL", "")
        tide_key = os.environ.get("ION_TIDE_API_KEY", "")
        if not tide_url:
            warnings.append("ION_TIDE_ENABLED=true but ION_TIDE_URL is not set")
        if not tide_key:
            warnings.append("ION_TIDE_ENABLED=true but ION_TIDE_API_KEY is not set")

    # OpenCTI
    if os.environ.get("ION_OPENCTI_ENABLED", "").lower() == "true":
        octi_url = os.environ.get("ION_OPENCTI_URL", "")
        if not octi_url:
            warnings.append("ION_OPENCTI_ENABLED=true but ION_OPENCTI_URL is not set")

    # Security
    if os.environ.get("ION_COOKIE_SECURE", "").lower() != "true":
        warnings.append("ION_COOKIE_SECURE is not true — session cookies won't have Secure flag")
    if os.environ.get("ION_DEBUG_MODE", "").lower() == "true":
        warnings.append("ION_DEBUG_MODE=true — /docs and /redoc are publicly accessible")

    # Log results
    for w in warnings:
        logger.warning("CONFIG: %s", w)
    for e in errors:
        logger.error("CONFIG FATAL: %s", e)

    if errors:
        logger.error("Startup blocked by %d configuration error(s). Fix .env and restart.", len(errors))
        raise SystemExit(1)

    logger.info("Configuration validated: %d warning(s), 0 errors", len(warnings))


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    _validate_startup_config()
    config = get_config()
    if not config.db_path.exists():
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
    # Always run create_all to ensure new tables are created
    init_db(config.db_path)

    # Seed roles, permissions, and ensure admin user has admin role
    try:
        from ion.storage.database import get_engine, get_session_factory
        from ion.auth.service import AuthService
        import os

        engine = get_engine(config.db_path)
        factory = get_session_factory(engine)
        session = factory()
        try:
            auth_service = AuthService(session)
            auth_service.seed_permissions()
            auth_service.seed_roles()
            admin_password = os.environ.get("ION_ADMIN_PASSWORD", "changeme")
            auth_service.seed_admin_user(password=admin_password)
            session.commit()
        finally:
            session.close()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed auth data: {e}")

    # Seed default pattern-based playbooks
    try:
        from ion.services.pattern_detection_service import seed_default_playbooks
        seed_default_playbooks()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed default playbooks: {e}")

    # Seed SOC documentation templates
    try:
        from ion.services.soc_template_service import seed_soc_templates
        seed_soc_templates()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed SOC templates: {e}")

    # Seed built-in Knowledge Base articles (392 articles, idempotent)
    try:
        from ion.services.kb_seed_service import seed_knowledge_base
        seed_knowledge_base()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed Knowledge Base: {e}")

    # Seed built-in Forensic Investigation playbooks (8 playbooks, idempotent)
    try:
        from ion.services.forensic_seed_service import seed_forensic_playbooks
        seed_forensic_playbooks()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed forensic playbooks: {e}")

    # Seed built-in meme pack for team chat (20 SOC-themed memes, idempotent)
    try:
        from ion.services.meme_seed_service import seed_memes
        seed_memes()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed memes: {e}")

    # Seed role-based group chat rooms (idempotent, reconciles memberships)
    try:
        from ion.services.chat_room_seed_service import seed_chat_rooms
        seed_chat_rooms()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed chat rooms: {e}")

    # Start Kibana bidirectional sync if enabled (via connector)
    try:
        from ion.services.connectors import get_connector_registry

        registry = get_connector_registry()
        kibana = registry.get("kibana_cases")
        if kibana and kibana.is_configured:
            kibana.start_background_sync(interval_seconds=60)
            import logging
            logging.getLogger(__name__).info("Kibana bidirectional sync started (60s interval)")
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to start Kibana sync: {e}")

    # Create daily skills assessment snapshot
    try:
        from ion.services.skills_snapshot_service import create_daily_snapshot
        from ion.storage.database import get_engine, get_session_factory

        engine = get_engine(config.db_path)
        factory = get_session_factory(engine)
        session = factory()
        try:
            create_daily_snapshot(session)
        finally:
            session.close()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to create skills snapshot: {e}")

    # Start Analytics Engine background loop
    try:
        from ion.services.analytics_engine import get_analytics_engine, seed_default_jobs

        engine = get_engine(config.db_path)
        factory = get_session_factory(engine)
        session = factory()
        try:
            seed_default_jobs(session)
        finally:
            session.close()

        analytics = get_analytics_engine()
        analytics.start_background_loop()
        logger.info("Analytics Engine background loop started")
    except Exception as e:
        logger.warning(f"Failed to start Analytics Engine: {e}")

    # Start TIDE background sync (pulls data into PostgreSQL snapshots)
    try:
        from ion.services.tide_sync_service import start_background_loop as _tide_bg
        from ion.storage.database import get_engine as _tide_eng
        _tide_bg(_tide_eng())
        logger.info("TIDE background sync started")
    except Exception as e:
        logger.warning(f"Failed to start TIDE background sync: {e}")

    # Check CyAB review reminders and notify leads
    try:
        from ion.web.cyab_api import check_review_reminders as _cyab_check
        from ion.storage.database import get_engine as _ge, get_session_factory as _gsf

        _eng = _ge(config.db_path)
        _fac = _gsf(_eng)
        _sess = _fac()
        try:
            from ion.models.cyab import CyabSystem
            from datetime import date as _date, timedelta as _td
            from sqlalchemy import select as _sel
            due = _sess.execute(
                _sel(CyabSystem).where(CyabSystem.next_review_date <= _date.today() + _td(days=7))
            ).scalars().all()
            if due:
                from ion.models.user import User as _U, Role as _R, user_roles as _ur
                leads = _sess.execute(
                    _sel(_U)
                    .join(_ur, _ur.c.user_id == _U.id)
                    .join(_R, _R.id == _ur.c.role_id)
                    .where(_R.name.in_(["lead", "admin", "principal_analyst"]))
                    .where(_U.is_active == True)
                ).scalars().all()
                sent = 0
                for sys in due:
                    is_overdue = sys.next_review_date < _date.today()
                    label = "OVERDUE" if is_overdue else "Due soon"
                    for u in leads:
                        create_notification(
                            session=_sess, user_id=u.id,
                            source="cyab_review", source_id=str(sys.id),
                            title=f"CyAB Review {label}: {sys.name}",
                            body=f"{sys.department} — {sys.sal_tier}",
                            url=f"/cyab#{sys.id}",
                        )
                        sent += 1
                _sess.commit()
                if sent:
                    logger.info("CyAB review reminders: %d notifications sent for %d systems", sent, len(due))
        finally:
            _sess.close()
    except Exception as e:
        logger.warning(f"CyAB review reminder check failed: {e}")

    # Version compatibility checks for connectors that declare supported ranges
    try:
        from ion.services.connectors import get_connector_registry
        from ion.services.connectors.version_compat import check_version_compatibility

        registry = get_connector_registry()
        for connector in registry.get_all():
            if connector.SUPPORTED_VERSIONS is None:
                continue
            if not connector.is_configured:
                continue
            try:
                result = await connector.test_connection()
                detected = result.get(connector.VERSION_KEY)
                if detected:
                    compat = check_version_compatibility(detected, connector.SUPPORTED_VERSIONS)
                    if compat["in_range"]:
                        logger.info(
                            "%s version %s OK (tested range: %s)",
                            connector.DISPLAY_NAME, detected, compat["tested_range"],
                        )
                    else:
                        logger.warning(
                            "VERSION COMPATIBILITY [%s]: %s",
                            connector.DISPLAY_NAME, compat["message"],
                        )
            except Exception as conn_err:
                logger.warning("Could not check %s version: %s", connector.DISPLAY_NAME, conn_err)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed version compatibility checks: {e}")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: User = Depends(require_page_auth)):
    """Render the main dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request, user: User = Depends(require_page_permission("template:read"))):
    """Render the templates page."""
    return templates.TemplateResponse(request=request, name="templates.html")


@app.get("/templates/new", response_class=HTMLResponse)
async def new_template_page(request: Request, user: User = Depends(require_page_permission("template:read"))):
    """Render the new template page."""
    return templates.TemplateResponse(request=request, name="template_form.html", context={"template": None})


@app.get("/templates/{template_id}", response_class=HTMLResponse)
async def view_template_page(request: Request, template_id: int, user: User = Depends(require_page_permission("template:read"))):
    """Render the template view page."""
    return templates.TemplateResponse(request=request, name="template_view.html", context={"template_id": template_id})


@app.get("/templates/{template_id}/edit", response_class=HTMLResponse)
async def edit_template_page(request: Request, template_id: int, user: User = Depends(require_page_permission("template:read"))):
    """Render the template edit page."""
    return templates.TemplateResponse(request=request, name="template_form.html", context={"template_id": template_id})


@app.get("/templates/{template_id}/render", response_class=HTMLResponse)
async def render_template_page(request: Request, template_id: int, user: User = Depends(require_page_permission("template:read"))):
    """Render the template rendering page."""
    return templates.TemplateResponse(request=request, name="template_render.html", context={"template_id": template_id})


@app.get("/templates/{template_id}/versions", response_class=HTMLResponse)
async def versions_page(request: Request, template_id: int, user: User = Depends(require_page_permission("template:read"))):
    """Render the versions page."""
    return templates.TemplateResponse(request=request, name="versions.html", context={"template_id": template_id})


@app.get("/documents", response_class=HTMLResponse)
async def documents_page(request: Request, user: User = Depends(require_page_permission("document:read"))):
    """Render the documents page."""
    return templates.TemplateResponse(request=request, name="documents.html")



@app.get("/gitlab", response_class=HTMLResponse)
async def gitlab_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the GitLab integration page."""
    return templates.TemplateResponse(request=request, name="gitlab.html")


# Auth page routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login page."""
    return templates.TemplateResponse(request=request, name="login.html")


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the user profile page."""
    return templates.TemplateResponse(request=request, name="profile.html")


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: User = Depends(require_page_permission("user:read"))):
    """Render the user management page (admin only)."""
    return templates.TemplateResponse(request=request, name="users.html")


@app.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request, user: User = Depends(require_page_permission("system:audit_view"))):
    """Render the audit logs page (admin only)."""
    return templates.TemplateResponse(request=request, name="audit_logs.html")


@app.get("/security", response_class=HTMLResponse)
async def security_dashboard_page(request: Request, user: User = Depends(require_page_permission("security:read"))):
    """Render the security dashboard page."""
    return templates.TemplateResponse(request=request, name="security_dashboard.html")


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the alerts investigation page."""
    return templates.TemplateResponse(request=request, name="alerts.html")


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request, user: User = Depends(require_page_permission("case:read"))):
    """Render the cases management page."""
    return templates.TemplateResponse(request=request, name="cases.html")


@app.get("/observables", response_class=HTMLResponse)
async def observables_page(request: Request, user: User = Depends(require_page_permission("observable:read"))):
    """Render the observables tracking page."""
    return templates.TemplateResponse(request=request, name="observables.html")


@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request, user: User = Depends(require_page_permission("observable:read"))):
    """Render the threat intel page."""
    return templates.TemplateResponse(request=request, name="threat_intel.html")


@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the document tools page."""
    return templates.TemplateResponse(request=request, name="tools.html")


@app.get("/cyab", response_class=HTMLResponse)
async def cyab_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the CyAB Ingestion SLA page."""
    return templates.TemplateResponse(request=request, name="cyab.html")


@app.get("/discover", response_class=HTMLResponse)
async def discover_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the discover and hunt page for analysts."""
    return templates.TemplateResponse(request=request, name="discover.html")


@app.get("/analyst", response_class=HTMLResponse)
async def analyst_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the unified analyst workspace page."""
    return templates.TemplateResponse(request=request, name="analyst.html")


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the integrations management page (read-only for analysts, full access for engineers)."""
    return templates.TemplateResponse(request=request, name="integrations.html")


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: User = Depends(require_page_permission("system:settings"))):
    """Render the system settings page."""
    return templates.TemplateResponse(request=request, name="settings.html")


@app.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request, user: User = Depends(require_page_permission("playbook:read"))):
    """Render the playbooks management page."""
    return templates.TemplateResponse(request=request, name="playbooks.html")


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request, user: User = Depends(require_page_permission("ai:chat"))):
    """Render the AI chat page."""
    return templates.TemplateResponse(request=request, name="chat.html")


@app.get("/training", response_class=HTMLResponse)
async def training_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the training pathways page."""
    return templates.TemplateResponse(request=request, name="training.html")


@app.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the full-page notes view."""
    return templates.TemplateResponse(request=request, name="notes.html")


@app.get("/pcap", response_class=HTMLResponse)
async def pcap_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the PCAP analyzer page."""
    return templates.TemplateResponse(request=request, name="pcap.html")


@app.get("/data-flow", response_class=HTMLResponse)
async def data_flow_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the data flow visualization page."""
    return templates.TemplateResponse(request=request, name="data_flow.html")


@app.get("/forensics", response_class=HTMLResponse)
async def forensics_page(request: Request, user: User = Depends(require_page_permission("forensic:read"))):
    """Render the forensic investigations page."""
    return templates.TemplateResponse(request=request, name="forensics.html")


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Analytics Engine dashboard."""
    return templates.TemplateResponse(request=request, name="analytics.html")


@app.get("/social", response_class=HTMLResponse)
async def social_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the Social Hub page."""
    return templates.TemplateResponse(request=request, name="social.html")


@app.get("/engineering-analytics", response_class=HTMLResponse)
async def engineering_analytics_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Engineering System Analytics page."""
    return templates.TemplateResponse(request=request, name="engineering_analytics.html")


@app.get("/detection-engineering", response_class=HTMLResponse)
async def detection_engineering_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Detection Engineering page (TIDE-powered)."""
    return templates.TemplateResponse(request=request, name="detection_engineering.html")


@app.get("/canaries", response_class=HTMLResponse)
async def canaries_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Canary / Deception Tracker page."""
    return templates.TemplateResponse(request=request, name="canaries.html")


@app.get("/log-sources", response_class=HTMLResponse)
async def log_sources_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Log Source Health Monitor page."""
    return templates.TemplateResponse(request=request, name="log_sources.html")


@app.get("/briefing", response_class=HTMLResponse)
async def briefing_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Morning Threat Briefing page."""
    return templates.TemplateResponse(request=request, name="briefing.html")


@app.get("/knowledge-graph", response_class=HTMLResponse)
async def knowledge_graph_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Knowledge Graph page."""
    return templates.TemplateResponse(request=request, name="knowledge_graph.html")


@app.get("/compliance", response_class=HTMLResponse)
async def compliance_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the multi-framework Compliance Posture page."""
    return templates.TemplateResponse(request=request, name="compliance.html")


@app.get("/maturity", response_class=HTMLResponse)
async def maturity_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the SOC Maturity Assessment page."""
    return templates.TemplateResponse(request=request, name="maturity.html")


@app.get("/pir", response_class=HTMLResponse)
async def pir_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Post-Incident Review page."""
    return templates.TemplateResponse(request=request, name="pir.html")




@app.get("/shift-handover", response_class=HTMLResponse)
async def shift_handover_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Shift Handover Report page."""
    return templates.TemplateResponse(request=request, name="shift_handover.html")


@app.get("/rule-tuning", response_class=HTMLResponse)
async def rule_tuning_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Rule Tuning Feedback Loop page."""
    return templates.TemplateResponse(request=request, name="rule_tuning.html")


@app.get("/entity-timeline", response_class=HTMLResponse)
async def entity_timeline_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Entity Timeline page."""
    return templates.TemplateResponse(request=request, name="entity_timeline.html")


@app.get("/analyst-efficiency", response_class=HTMLResponse)
async def analyst_efficiency_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Analyst Efficiency Dashboard page."""
    return templates.TemplateResponse(request=request, name="analyst_efficiency.html")


@app.get("/soc-health", response_class=HTMLResponse)
async def soc_health_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the SOC Health Scorecard page."""
    return templates.TemplateResponse(request=request, name="soc_health.html")


@app.get("/guide", response_class=HTMLResponse)
async def guide_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the interactive training guide."""
    return templates.TemplateResponse(request=request, name="guide.html")


@app.get("/guide/sim", response_class=HTMLResponse)
async def guide_sim_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the interactive training simulator."""
    return templates.TemplateResponse(request=request, name="guide_sim.html")


@app.get("/guide/range", response_class=HTMLResponse)
async def cyber_range_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the Cyber Range training page."""
    return templates.TemplateResponse(request=request, name="cyber_range.html")


@app.get("/attack-stories", response_class=HTMLResponse)
async def attack_stories_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Attack Stories page."""
    return templates.TemplateResponse(request=request, name="attack_stories.html")


@app.get("/executive-report", response_class=HTMLResponse)
async def executive_report_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Executive Report page."""
    return templates.TemplateResponse(request=request, name="executive_report.html")


@app.get("/threat-hunting", response_class=HTMLResponse)
async def threat_hunting_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Threat Hunting Workbench page."""
    return templates.TemplateResponse(request=request, name="threat_hunting.html")


@app.get("/oncall", response_class=HTMLResponse)
async def oncall_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the On-Call / Escalation Manager page."""
    return templates.TemplateResponse(request=request, name="oncall.html")


@app.get("/service-accounts", response_class=HTMLResponse)
async def service_accounts_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Service Account Tracker page."""
    return templates.TemplateResponse(request=request, name="service_accounts.html")


@app.get("/topology", response_class=HTMLResponse)
async def topology_page(request: Request, user: User = Depends(require_page_permission("security:read"))):
    """Render the network topology visualization page."""
    return templates.TemplateResponse(request=request, name="topology.html")


@app.get("/architecture", response_class=HTMLResponse)
async def architecture_page(request: Request, user: User = Depends(require_page_permission("security:read"))):
    """Render the system architecture flow diagram page."""
    return templates.TemplateResponse(request=request, name="architecture.html")


def main():
    """Run the web server."""
    import argparse
    from ion.core.config import get_config

    parser = argparse.ArgumentParser(description="ION Web Server")
    parser.add_argument("--host", default=None, help="Host to bind to")
    parser.add_argument("--port", type=int, default=None, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--ssl-cert", default=None, help="Path to SSL certificate (PEM)")
    parser.add_argument("--ssl-key", default=None, help="Path to SSL private key (PEM)")
    args = parser.parse_args()

    config = get_config()
    ssl_cert = args.ssl_cert or config.ssl_cert or None
    ssl_key = args.ssl_key or config.ssl_key or None
    host = args.host or os.environ.get("ION_HOST", "127.0.0.1")
    port = args.port or int(os.environ.get("ION_PORT", "8000"))

    kwargs = {
        "host": host,
        "port": port,
        "reload": args.reload,
    }

    if ssl_cert and ssl_key:
        kwargs["ssl_certfile"] = ssl_cert
        kwargs["ssl_keyfile"] = ssl_key
        scheme = "https"
    else:
        scheme = "http"

    print(f"Starting ION Web UI at {scheme}://{host}:{port}")
    uvicorn.run("ion.web.server:app", **kwargs)


if __name__ == "__main__":
    main()
