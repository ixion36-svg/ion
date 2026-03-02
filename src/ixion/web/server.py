"""FastAPI web server for IXION - Intelligence eXchange & Integration Operations Network."""

import uvicorn
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

import ixion
from ixion.web.api import router as api_router, limiter
from ixion.core.config import get_config as get_app_config
from ixion.web.security_api import router as security_router
from ixion.web.integration_api import router as integration_router
from ixion.web.admin_api import router as admin_router
from ixion.web.observable_api import router as observable_router
from ixion.web.ai_api import router as ai_router
from ixion.web.kibana_api import router as kibana_router
from ixion.web.skills_api import router as skills_router
from ixion.web.notes_api import router as notes_router
from ixion.core.config import get_config, get_elasticsearch_config
from ixion.core.logging import setup_logging, get_logger
from ixion.storage.database import init_db
from ixion.web.logging_middleware import RequestLoggingMiddleware
from ixion.web.security_middleware import SecurityMonitoringMiddleware, RateLimitSecurityMiddleware

# Initialize logging with Elasticsearch if configured
import os
es_config = get_elasticsearch_config()
if es_config.get("url"):
    os.environ.setdefault("IXION_ES_LOG_URL", es_config.get("url", ""))
    if es_config.get("api_key"):
        os.environ.setdefault("IXION_ES_API_KEY", es_config.get("api_key", ""))
    if es_config.get("username"):
        os.environ.setdefault("IXION_ES_USERNAME", es_config.get("username", ""))
    if es_config.get("password"):
        os.environ.setdefault("IXION_ES_PASSWORD", es_config.get("password", ""))

es_log_url = es_config.get("url") if es_config.get("url") else None
setup_logging(elasticsearch_url=es_log_url)
logger = get_logger(__name__)

# Get the directory containing this file
BASE_DIR = Path(__file__).parent

# Check if debug mode is enabled for API docs
_app_config = get_app_config()
_debug_mode = _app_config.debug_mode

app = FastAPI(
    title="IXION",
    description="Intelligence eXchange & Integration Operations Network - Security Operations Portal for Guarded Glass",
    version=ixion.__version__,
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

        # Content Security Policy (adjust as needed for your app)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'"
        )

        # Permissions Policy (formerly Feature-Policy)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )

        return response


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

# Mount static files
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Setup templates
templates = Jinja2Templates(directory=BASE_DIR / "templates")

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


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    config = get_config()
    if not config.db_path.exists():
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
    # Always run create_all to ensure new tables are created
    init_db(config.db_path)

    # Seed roles, permissions, and ensure admin user has admin role
    try:
        from ixion.storage.database import get_engine, get_session_factory
        from ixion.auth.service import AuthService
        import os

        engine = get_engine(config.db_path)
        factory = get_session_factory(engine)
        session = factory()
        try:
            auth_service = AuthService(session)
            auth_service.seed_permissions()
            auth_service.seed_roles()
            admin_password = os.environ.get("IXION_ADMIN_PASSWORD", "changeme")
            auth_service.seed_admin_user(password=admin_password)
            session.commit()
        finally:
            session.close()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed auth data: {e}")

    # Seed default pattern-based playbooks
    try:
        from ixion.services.pattern_detection_service import seed_default_playbooks
        seed_default_playbooks()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed default playbooks: {e}")

    # Seed SOC documentation templates
    try:
        from ixion.services.soc_template_service import seed_soc_templates
        seed_soc_templates()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to seed SOC templates: {e}")

    # Start Kibana bidirectional sync if enabled (via connector)
    try:
        from ixion.services.connectors import get_connector_registry

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
        from ixion.services.skills_snapshot_service import create_daily_snapshot
        from ixion.storage.database import get_engine, get_session_factory

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

    # Version compatibility checks for connectors that declare supported ranges
    try:
        from ixion.services.connectors import get_connector_registry
        from ixion.services.connectors.version_compat import check_version_compatibility

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
async def index(request: Request):
    """Render the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request):
    """Render the templates page."""
    return templates.TemplateResponse("templates.html", {"request": request})


@app.get("/templates/new", response_class=HTMLResponse)
async def new_template_page(request: Request):
    """Render the new template page."""
    return templates.TemplateResponse("template_form.html", {"request": request, "template": None})


@app.get("/templates/{template_id}", response_class=HTMLResponse)
async def view_template_page(request: Request, template_id: int):
    """Render the template view page."""
    return templates.TemplateResponse("template_view.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/edit", response_class=HTMLResponse)
async def edit_template_page(request: Request, template_id: int):
    """Render the template edit page."""
    return templates.TemplateResponse("template_form.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/render", response_class=HTMLResponse)
async def render_template_page(request: Request, template_id: int):
    """Render the template rendering page."""
    return templates.TemplateResponse("template_render.html", {"request": request, "template_id": template_id})


@app.get("/templates/{template_id}/versions", response_class=HTMLResponse)
async def versions_page(request: Request, template_id: int):
    """Render the versions page."""
    return templates.TemplateResponse("versions.html", {"request": request, "template_id": template_id})


@app.get("/documents", response_class=HTMLResponse)
async def documents_page(request: Request):
    """Render the documents page."""
    return templates.TemplateResponse("documents.html", {"request": request})



@app.get("/gitlab", response_class=HTMLResponse)
async def gitlab_page(request: Request):
    """Render the GitLab integration page."""
    return templates.TemplateResponse("gitlab.html", {"request": request})


# Auth page routes
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render the login page."""
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    """Render the user profile page."""
    return templates.TemplateResponse("profile.html", {"request": request})


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    """Render the user management page (admin only)."""
    return templates.TemplateResponse("users.html", {"request": request})


@app.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request):
    """Render the audit logs page (admin only)."""
    return templates.TemplateResponse("audit_logs.html", {"request": request})


@app.get("/security", response_class=HTMLResponse)
async def security_dashboard_page(request: Request):
    """Render the security dashboard page (admin only)."""
    return templates.TemplateResponse("security_dashboard.html", {"request": request})


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Render the alerts investigation page (admin only)."""
    return templates.TemplateResponse("alerts.html", {"request": request})


@app.get("/observables", response_class=HTMLResponse)
async def observables_page(request: Request):
    """Render the observables tracking page."""
    return templates.TemplateResponse("observables.html", {"request": request})


@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    """Render the document tools page."""
    return templates.TemplateResponse("tools.html", {"request": request})


@app.get("/discover", response_class=HTMLResponse)
async def discover_page(request: Request):
    """Render the discover and hunt page for analysts."""
    return templates.TemplateResponse("discover.html", {"request": request})


@app.get("/analyst", response_class=HTMLResponse)
async def analyst_page(request: Request):
    """Render the unified analyst workspace page."""
    return templates.TemplateResponse("analyst.html", {"request": request})


@app.get("/integrations", response_class=HTMLResponse)
async def integrations_page(request: Request):
    """Render the integrations management page (admin only)."""
    return templates.TemplateResponse("integrations.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Render the system settings page (admin only)."""
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request):
    """Render the playbooks management page (admin only)."""
    return templates.TemplateResponse("playbooks.html", {"request": request})


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    """Render the AI chat page."""
    return templates.TemplateResponse("chat.html", {"request": request})


@app.get("/training", response_class=HTMLResponse)
async def training_page(request: Request):
    """Render the training pathways page."""
    return templates.TemplateResponse("training.html", {"request": request})


@app.get("/notes", response_class=HTMLResponse)
async def notes_page(request: Request):
    """Render the full-page notes view."""
    return templates.TemplateResponse("notes.html", {"request": request})


def main():
    """Run the web server."""
    import argparse
    parser = argparse.ArgumentParser(description="IXION Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    print(f"Starting IXION Web UI at http://{args.host}:{args.port}")
    uvicorn.run(
        "ixion.web.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
