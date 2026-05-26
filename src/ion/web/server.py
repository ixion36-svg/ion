"""FastAPI web server for ION - Intelligent Operating Network."""

from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ion.auth.dependencies import require_page_auth, require_page_permission
from ion.models.user import User

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
# Initialize logging with Elasticsearch if configured
import os

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

import ion
from ion.core.config import get_config, get_elasticsearch_config
from ion.core.config import get_config as get_app_config
from ion.core.logging import get_logger, setup_logging
from ion.storage.database import init_db
from ion.web.admin_api import router as admin_router
from ion.web.ai_api import router as ai_router
from ion.web.alert_pattern_api import router as alert_pattern_router
from ion.web.alert_prompt_api import router as alert_prompt_router
from ion.web.analyst_efficiency_api import router as analyst_efficiency_router
from ion.web.analytics_api import router as analytics_router
from ion.web.api import limiter
from ion.web.api import router as api_router
from ion.web.arkime_api import router as arkime_router
from ion.web.attack_story_api import router as attack_story_router
from ion.web.bob_analysis_api import router as bob_analysis_router
from ion.web.bob_eval_api import router as bob_eval_router
from ion.web.briefing_api import router as briefing_router
from ion.web.bulk_ops_api import router as bulk_ops_router
from ion.web.canary_api import router as canary_router
from ion.web.case_grouper_api import router as case_grouper_router
from ion.web.case_similarity_api import router as case_similarity_router
from ion.web.change_log_api import router as change_log_router
from ion.web.comm_template_api import router as comm_template_router
from ion.web.compliance_api import router as compliance_router
from ion.web.course_api import router as course_router
from ion.web.cyab_api import router as cyab_router
from ion.web.cyber_range_api import router as cyber_range_router
from ion.web.d3fend_api import router as d3fend_router
from ion.web.daily_standup_api import router as daily_standup_router
from ion.web.dashboard_layout_api import router as dashboard_layout_router
from ion.web.emulation_api import router as emulation_router
from ion.web.engineering_analytics_api import router as engineering_analytics_router
from ion.web.enrichment_api import router as enrichment_router
from ion.web.entity_timeline_api import router as entity_timeline_router
from ion.web.executive_report_api import router as executive_report_router
from ion.web.forensic_workbench_api import router as forensic_workbench_router
from ion.web.forensics_api import router as forensics_router
from ion.web.incident_cost_api import router as incident_cost_router
from ion.web.integration_api import router as integration_router
from ion.web.investigation_api import router as investigation_router
from ion.web.investigation_memory_api import router as investigation_memory_router
from ion.web.ioc_staleness_api import router as ioc_staleness_router
from ion.web.kibana_api import router as kibana_router
from ion.web.knowledge_graph_api import router as knowledge_graph_router
from ion.web.labs_api import router as labs_router
from ion.web.log_source_api import router as log_source_router
from ion.web.logging_middleware import RequestLoggingMiddleware
from ion.web.maturity_api import router as maturity_router
from ion.web.mitre_navigator_api import router as mitre_navigator_router
from ion.web.network_map_api import router as network_map_router
from ion.web.notes_api import router as notes_router
from ion.web.observable_api import router as observable_router
from ion.web.pcap_api import router as pcap_router
from ion.web.playbook_action_api import router as playbook_action_router
from ion.web.playbook_analytics_api import router as playbook_analytics_router
from ion.web.report_scheduler_api import router as report_scheduler_router
from ion.web.role_skills_api import router as role_skills_router
from ion.web.scheduler_api import router as scheduler_router
from ion.web.security_api import router as security_router
from ion.web.security_middleware import RateLimitSecurityMiddleware, SecurityMonitoringMiddleware
from ion.web.service_account_api import router as service_account_router
from ion.web.shift_handover_api import router as shift_handover_router
from ion.web.skill_publisher_api import router as skill_publisher_router
from ion.web.skills_api import router as skills_router
from ion.web.sla_api import router as sla_router
from ion.web.smtp_api import router as smtp_router
from ion.web.soc_health_api import router as soc_health_router
from ion.web.social_api import router as social_router
from ion.web.story_api import router as story_router

# v0.27.0: threat_hunt_api removed; see /threat-hunting handler note below.
from ion.web.threat_intel_api import router as threat_intel_router
from ion.web.threat_landscape_api import router as threat_landscape_router
from ion.web.threat_watch_gap_api import router as threat_watch_gap_router

# v0.26.1: ticker service + API removed (was crashing every tick on an
# enum-case mismatch; the auto-flagging design also conflicted with
# investigation queue ownership). Model + table kept dormant for any
# future redesign — see _backlog_v0_27.md.
from ion.web.training_sim_api import router as training_sim_router
from ion.web.translator_api import router as translator_router
from ion.web.triage_suggestion_api import router as triage_suggestion_router
from ion.web.tuning_proposal_api import router as tuning_proposal_router
from ion.web.vulnerability_api import router as vulnerability_router
from ion.web.wallboard_api import router as wallboard_router
from ion.web.webhook_api import router as webhook_router
from ion.web.workbench_api import router as workbench_router

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

# v0.31.3: per-request CSP nonce. The middleware seeds this contextvar at
# request start; templates read it via the `csp_nonce` Jinja global below.
# ContextVar is per-async-task safe — different concurrent requests get
# different nonces without leaking across tasks.
import contextvars as _contextvars
import secrets as _secrets

_csp_nonce_var: _contextvars.ContextVar[str] = _contextvars.ContextVar(
    "csp_nonce", default=""
)


class _CSPNonceProxy:
    """Renders the current request's CSP nonce when interpolated in a template.

    Used as `{{ csp_nonce }}` (no parens) inside `<script nonce="...">` and
    `<style nonce="...">` opening tags. The nonce is base64-url and contains
    no HTML-special characters, so `__html__()` returns it verbatim to avoid
    Jinja's autoescape mangling it.
    """

    def __str__(self) -> str:
        return _csp_nonce_var.get()

    def __html__(self) -> str:
        return _csp_nonce_var.get()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses + seed the per-request CSP nonce."""

    async def dispatch(self, request: Request, call_next):
        # 16 bytes of CSPRNG → base64-url-encoded (≈22 chars). Stored on
        # request.state for direct access and on a ContextVar so the Jinja
        # `{{ csp_nonce }}` global resolves to the right value without each
        # route handler having to thread it through.
        nonce = _secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce
        _token = _csp_nonce_var.set(nonce)
        try:
            response = await call_next(request)
        finally:
            _csp_nonce_var.reset(_token)

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

        # Content Security Policy — CSP3 split-directive policy.
        # Strict-nonce on `<script>` and `<style>` element bodies (the main
        # XSS injection surface). v0.31.20: `script-src-attr 'none'` flipped
        # on after the v0.31.4–v0.31.19 inline-handler migration retired
        # every `onclick=`/`onkeydown=`/etc attribute (~1,150 handlers) in
        # favour of `data-click-action` / `data-keydown-action` + the
        # event-delegation helper at static/js/event-delegation.js.
        # Browsers now block any attempt to add an inline event handler
        # (defence-in-depth against stored-XSS injection of a malicious
        # `onerror=` etc).
        # v0.31.21: `style-src-attr 'none'` flipped on after
        # tools/migrate_inline_styles.py retired every inline `style=""`
        # attribute (1,820 instances → 993 unique hashed CSS classes in
        # static/css/ion-migrated-styles.css, loaded via base.html). With
        # strict `script-src-attr 'none'` (v0.31.20) AND strict
        # `style-src-attr 'none'` (v0.31.21) AND strict nonce on inline
        # `<script>` / `<style>` (v0.31.3), the only CSS that can apply to
        # an ION page is from same-origin stylesheets, nonced `<style>`
        # blocks, and programmatic CSSOM (`el.style.setProperty(...)`).
        # P11 is now fully closed.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "script-src-attr 'none'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            "style-src-attr 'none'; "
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
from starlette.responses import Response as _StaticResponse
from starlette.staticfiles import StaticFiles as _StaticFiles


class CachedStaticFiles(_StaticFiles):
    """StaticFiles with Cache-Control headers for browser caching."""
    async def get_response(self, path: str, scope) -> _StaticResponse:
        response = await super().get_response(path, scope)
        if response.status_code == 200:
            # 24h cache for immutable assets (CSS, JS, fonts, images)
            response.headers["Cache-Control"] = "public, max-age=86400, stale-while-revalidate=3600"
        return response


app.mount("/static", CachedStaticFiles(directory=BASE_DIR / "static"), name="static")

# Setup templates with bytecode cache (compiled once, not per-request)
from jinja2 import FileSystemBytecodeCache as _J2Cache

_bytecode_cache_dir = Path("/tmp/ion-jinja2-cache")
_bytecode_cache_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=BASE_DIR / "templates")
templates.env.bytecode_cache = _J2Cache(str(_bytecode_cache_dir))
templates.env.auto_reload = _debug_mode  # Only reload in debug
templates.env.globals["ion_version"] = ion.__version__
# v0.31.3: CSP nonce as a global proxy. Templates read it as `{{ csp_nonce }}`
# (no parens) inside `<script nonce="...">` and `<style nonce="...">` tags.
# The proxy reads the per-request value from `_csp_nonce_var`; outside a
# request (e.g. CLI template rendering, if any) it resolves to "" which
# produces a benign empty attribute.
templates.env.globals["csp_nonce"] = _CSPNonceProxy()

# Include API routes
app.include_router(api_router, prefix="/api")
app.include_router(security_router, prefix="/api/security")
app.include_router(integration_router, prefix="/api/integrations")
app.include_router(admin_router, prefix="/api/admin")
app.include_router(skill_publisher_router, prefix="/api/admin")
app.include_router(observable_router, prefix="/api")
app.include_router(ai_router)
app.include_router(kibana_router, prefix="/api/kibana")
app.include_router(skills_router, prefix="/api/skills")
# Role-match router has its own /skills/role-match prefix in the router itself
app.include_router(role_skills_router, prefix="/api")
app.include_router(notes_router, prefix="/api/notes")
app.include_router(pcap_router, prefix="/api/pcap")
app.include_router(arkime_router)  # router already has prefix="/api"
app.include_router(forensics_router, prefix="/api/forensics")
# v0.20.1: ForensicCase Workbench — pinned evidence + tamper-evident ledger
app.include_router(forensic_workbench_router, prefix="/api/forensics")
app.include_router(social_router, prefix="/api/social")
app.include_router(analytics_router, prefix="/api/analytics")
app.include_router(engineering_analytics_router, prefix="/api/engineering/analytics")
app.include_router(cyab_router, prefix="/api/cyab")
app.include_router(wallboard_router, prefix="")
# v0.17.0: translator — page route + /api/translator/* routes share the
# same router so it owns its own prefixes internally.
app.include_router(translator_router, prefix="")
app.include_router(threat_intel_router, prefix="/api/threat-intel")
app.include_router(threat_watch_gap_router, prefix="/api/threat-intel")
app.include_router(threat_landscape_router, prefix="/api")
app.include_router(shift_handover_router, prefix="/api")
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
# v0.20.0: Workbench — pinned evidence + tamper-evident ledger
app.include_router(workbench_router, prefix="/api")
app.include_router(log_source_router, prefix="/api")
app.include_router(briefing_router, prefix="/api")
app.include_router(knowledge_graph_router, prefix="/api")
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
app.include_router(sla_router, prefix="/api")
app.include_router(network_map_router, prefix="/api")
app.include_router(bulk_ops_router, prefix="/api")
# v0.27.0: threat_hunt_router removed alongside the half-built page.
app.include_router(dashboard_layout_router, prefix="/api")
app.include_router(report_scheduler_router, prefix="/api")
app.include_router(playbook_action_router, prefix="/api")
app.include_router(cyber_range_router, prefix="/api")
app.include_router(smtp_router, prefix="/api/smtp")
app.include_router(enrichment_router, prefix="/api/enrichment")
app.include_router(alert_prompt_router, prefix="")
# v0.11.0 — JSON-DAG playbook automation (Stories). The router declares
# its own /api/ + page paths internally, so prefix="" here.
app.include_router(story_router, prefix="")
# v0.11.2 — L1/L2/L3 SOC training course subsystem
app.include_router(course_router, prefix="")
# v0.21.0 — Lab fixture launch/complete lifecycle
app.include_router(labs_router, prefix="")
app.include_router(tuning_proposal_router, prefix="")
# v0.26.1: ticker_router removed alongside the service.
app.include_router(investigation_memory_router)
app.include_router(scheduler_router, prefix="")
app.include_router(investigation_router, prefix="")
# v0.23.1 — on-demand Bob case analysis (replaces auto-comment)
app.include_router(bob_analysis_router, prefix="/api")
app.include_router(case_grouper_router, prefix="")
app.include_router(webhook_router, prefix="/api")
app.include_router(daily_standup_router, prefix="/api")
# v0.21.0: Bob Prompt Evaluation Harness — /api/bob-eval/* + /bob-eval page
app.include_router(bob_eval_router, prefix="")


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
    """Initialize database + run seed/background-task starters on startup.

    Every hook below is wrapped in a Postgres advisory lock via run_locked()
    so that uvicorn's N parallel worker processes don't race each other on
    the same tables (which previously caused unique-constraint violations,
    deadlocks, and duplicate background loops). Only one worker per restart
    actually runs each hook; the rest skip cleanly.
    """
    # v0.9.82 — event-loop lag tripwire. Python asyncio will auto-log a
    # warning any time a callback (read: a sync function called from an
    # async handler) blocks the event loop longer than this threshold.
    # 250ms is aggressive enough to surface the real offenders without
    # spamming the log for normal small syncs.
    try:
        import asyncio as _asyncio
        _loop = _asyncio.get_event_loop()
        _loop.slow_callback_duration = 0.25
    except Exception:
        pass

    _validate_startup_config()
    config = get_config()
    if not config.db_path.exists():
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
    # create_all() is concurrent-safe in postgres (CREATE TABLE IF NOT EXISTS)
    # so we don't need to lock it; let every worker run it independently.
    init_db(config.db_path)

    from ion.storage.database import (
        LOCK_ANALYTICS_BG_LOOP,
        LOCK_CASE_GROUPER_BG,
        LOCK_INVESTIGATION_BG,
        LOCK_KIBANA_BG_SYNC,
        LOCK_SCHEDULER_BG,
        LOCK_SEED_ANALYTICS_JOBS,
        LOCK_SEED_CAPABILITY_KB,
        LOCK_SEED_CYAB_SUBPROFILES,
        LOCK_SEED_DEFAULT_PLAYBOOKS,
        LOCK_SEED_FORENSIC_PB,
        LOCK_SEED_KNOWLEDGE_BASE,
        LOCK_SEED_PERMISSIONS,
        LOCK_SEED_SOC_TEMPLATES,
        LOCK_SKILLS_DAILY_SNAPSHOT,
        LOCK_TIDE_BG_SYNC,
        get_engine,
        get_session_factory,
        run_locked,
    )
    engine = get_engine(config.db_path)
    factory = get_session_factory(engine)

    # ---------------------------------------------------------------
    # Seed roles, permissions, admin user
    # ---------------------------------------------------------------
    def _seed_auth():
        import os

        from ion.auth.service import AuthService
        session = factory()
        try:
            auth_service = AuthService(session)
            auth_service.seed_permissions()
            auth_service.seed_roles()
            admin_password = os.environ.get("ION_ADMIN_PASSWORD", "changeme")
            auth_service.seed_admin_user(password=admin_password)
            # Seed Bob — the AI analyst service account. Must run after
            # seed_roles so the ai_analyst role exists for assignment.
            auth_service.seed_bob_user()
            session.commit()
        finally:
            session.close()
    run_locked(engine, LOCK_SEED_PERMISSIONS, "seed_auth", _seed_auth)

    # ---------------------------------------------------------------
    # Seed default pattern-based playbooks
    # ---------------------------------------------------------------
    def _seed_default_playbooks():
        from ion.services.pattern_detection_service import seed_default_playbooks
        seed_default_playbooks()
    run_locked(engine, LOCK_SEED_DEFAULT_PLAYBOOKS, "seed_default_playbooks", _seed_default_playbooks)

    # ---------------------------------------------------------------
    # Seed SOC documentation templates
    # ---------------------------------------------------------------
    def _seed_soc_templates():
        from ion.services.soc_template_service import seed_soc_templates
        seed_soc_templates()
    run_locked(engine, LOCK_SEED_SOC_TEMPLATES, "seed_soc_templates", _seed_soc_templates)

    # ---------------------------------------------------------------
    # Seed built-in Knowledge Base articles (idempotent)
    # ---------------------------------------------------------------
    def _seed_kb():
        from ion.services.kb_seed_service import seed_knowledge_base
        seed_knowledge_base()
    run_locked(engine, LOCK_SEED_KNOWLEDGE_BASE, "seed_knowledge_base", _seed_kb)

    # ---------------------------------------------------------------
    # Seed built-in Forensic Investigation playbooks
    # ---------------------------------------------------------------
    def _seed_forensic():
        from ion.services.forensic_seed_service import seed_forensic_playbooks
        seed_forensic_playbooks()
    run_locked(engine, LOCK_SEED_FORENSIC_PB, "seed_forensic_playbooks", _seed_forensic)

    # ---------------------------------------------------------------
    # Seed default Alert Prompt Templates (per-rule LLM prompts).
    # Idempotent — no-op when any rows already exist, so running
    # without an advisory lock across workers is safe.
    # ---------------------------------------------------------------
    try:
        from ion.services.alert_prompt_service import seed_default_templates
        seed_default_templates()
    except Exception as e:
        logger.warning("seed_default_alert_prompts failed: %s", e)

    # ---------------------------------------------------------------
    # Seed KnowledgeArticle rows for Role Match capability_keys
    # ---------------------------------------------------------------
    def _seed_capability_articles():
        from ion.services.role_skills_service import seed_capability_articles
        session = factory()
        try:
            report = seed_capability_articles(session)
            if report.get("seeded"):
                logger.info(
                    "Seeded %d Role Match capability articles (%d already present)",
                    report["seeded"], report["already_present"],
                )
        finally:
            session.close()
    run_locked(engine, LOCK_SEED_CAPABILITY_KB, "seed_capability_articles", _seed_capability_articles)

    # ---------------------------------------------------------------
    # v0.12.0: Seed CyAB Onboarding Studio catalogue (6 pillars + 14
    # sub-profiles) and backfill cyab_data_sources.subprofile_id from
    # legacy data_source_type. Idempotent — operator-edited
    # sub-profiles (is_custom=true) are preserved.
    # ---------------------------------------------------------------
    def _seed_cyab_subprofiles():
        from ion.services.cyab_subprofile_service import (
            backfill_subprofile_ids,
            seed_catalogue,
        )
        seed_catalogue()
        backfill_subprofile_ids()
    run_locked(
        engine, LOCK_SEED_CYAB_SUBPROFILES,
        "seed_cyab_subprofiles", _seed_cyab_subprofiles,
    )

    # ---------------------------------------------------------------
    # Start Kibana bidirectional sync (hold_until_close: only one worker
    # in the lifetime of this container instance runs the loop)
    # ---------------------------------------------------------------
    def _start_kibana_sync():
        from ion.services.connectors import get_connector_registry
        registry = get_connector_registry()
        kibana = registry.get("kibana_cases")
        if kibana and kibana.is_configured:
            kibana.start_background_sync(interval_seconds=60)
            logger.info("Kibana bidirectional sync started (60s interval)")
    run_locked(engine, LOCK_KIBANA_BG_SYNC, "kibana_bg_sync", _start_kibana_sync,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Daily skills assessment snapshot
    # ---------------------------------------------------------------
    def _skills_snapshot():
        from ion.services.skills_snapshot_service import create_daily_snapshot
        session = factory()
        try:
            create_daily_snapshot(session)
        finally:
            session.close()
    run_locked(engine, LOCK_SKILLS_DAILY_SNAPSHOT, "skills_daily_snapshot", _skills_snapshot)

    # ---------------------------------------------------------------
    # Analytics Engine: seed default jobs + start background loop
    # ---------------------------------------------------------------
    def _seed_analytics_jobs():
        from ion.services.analytics_engine import seed_default_jobs
        session = factory()
        try:
            seed_default_jobs(session)
        finally:
            session.close()
    run_locked(engine, LOCK_SEED_ANALYTICS_JOBS, "seed_analytics_jobs", _seed_analytics_jobs)

    def _start_analytics_loop():
        from ion.services.analytics_engine import get_analytics_engine
        analytics = get_analytics_engine()
        analytics.start_background_loop()
        logger.info("Analytics Engine background loop started")
    run_locked(engine, LOCK_ANALYTICS_BG_LOOP, "analytics_bg_loop", _start_analytics_loop,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # TIDE background sync (single worker — hold_until_close)
    # ---------------------------------------------------------------
    def _start_tide_sync():
        from ion.services.tide_sync_service import start_background_loop as _tide_bg
        _tide_bg(engine)
        logger.info("TIDE background sync started")
    run_locked(engine, LOCK_TIDE_BG_SYNC, "tide_bg_sync", _start_tide_sync,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Network Mapper background sync
    # ---------------------------------------------------------------
    from ion.storage.database import LOCK_NETMAP_BG_SYNC
    def _start_netmap_sync():
        from ion.services.network_mapper_service import start_background_loop as _netmap_bg
        _netmap_bg()
        logger.info("Network Mapper background sync started")
    run_locked(engine, LOCK_NETMAP_BG_SYNC, "netmap_bg_sync", _start_netmap_sync,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Generic job scheduler background loop (single worker —
    # hold_until_close). Honours ION_SCHEDULER_ENABLED / _INTERVAL_S.
    # ---------------------------------------------------------------
    def _start_scheduler():
        if not config.scheduler_enabled:
            logger.info("Generic scheduler disabled (config.scheduler_enabled=False)")
            return
        from ion.services.scheduler_service import run_scheduler_loop
        try:
            interval = int(os.environ.get("ION_SCHEDULER_INTERVAL_S", str(config.scheduler_interval_s)))
        except ValueError:
            interval = config.scheduler_interval_s
        run_scheduler_loop(interval_s=interval)
        logger.info("Generic scheduler background loop started")
    run_locked(engine, LOCK_SCHEDULER_BG, "scheduler_bg_loop", _start_scheduler,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Autonomous investigation background sweep (single worker —
    # hold_until_close). Honours ION_INVESTIGATION_LOOP_ENABLED.
    # ---------------------------------------------------------------
    def _start_investigation_loop():
        if not config.investigation_loop_enabled:
            logger.info("Investigation loop disabled (config.investigation_loop_enabled=False)")
            return
        from ion.services.investigation_service import start_investigation_loop_if_enabled
        start_investigation_loop_if_enabled(engine=engine)
        logger.info("Autonomous investigation loop startup attempted")
    run_locked(engine, LOCK_INVESTIGATION_BG, "investigation_bg_loop", _start_investigation_loop,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Case grouper background loop (single worker — hold_until_close).
    # Honours ION_CASE_GROUPER_ENABLED / _INTERVAL_S.
    # ---------------------------------------------------------------
    def _start_case_grouper():
        if not config.case_grouper_enabled:
            logger.info("Case grouper disabled (config.case_grouper_enabled=False)")
            return
        from ion.services.case_grouper_service import run_grouper_loop
        try:
            interval = int(os.environ.get("ION_CASE_GROUPER_INTERVAL_S", str(config.case_grouper_interval_s)))
        except ValueError:
            interval = config.case_grouper_interval_s
        run_grouper_loop(interval_s=interval)
        logger.info("Case grouper background loop started")
    run_locked(engine, LOCK_CASE_GROUPER_BG, "case_grouper_bg_loop", _start_case_grouper,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Session cleanup background loop (v0.31.13 — data-min P13 G1).
    # Periodically sweeps user_sessions rows whose owner-user hasn't
    # logged back in to trigger the per-user cleanup. Honours
    # ION_SESSION_CLEANUP_ENABLED (default true) and
    # ION_SESSION_CLEANUP_INTERVAL_HOURS (default 6).
    # ---------------------------------------------------------------
    from ion.storage.database import LOCK_SESSION_CLEANUP_BG
    def _start_session_cleanup():
        from ion.services.session_cleanup_service import (
            start_background_loop as _sc_bg,
        )
        _sc_bg(engine)
        logger.info("Session cleanup background loop started")
    run_locked(engine, LOCK_SESSION_CLEANUP_BG, "session_cleanup_bg_loop", _start_session_cleanup,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Data retention background loop (v0.31.14 — data-min P13 G2+G3).
    # Default no-op: both ION_AUDIT_LOG_RETENTION_DAYS and
    # ION_SECURITY_EVENTS_RETENTION_DAYS are unset by default.
    # Operators opt in per deployment because compliance windows vary
    # wildly (90d vs 7y). Daily sweep when enabled.
    # ---------------------------------------------------------------
    from ion.storage.database import LOCK_DATA_RETENTION_BG
    def _start_data_retention():
        from ion.services.data_retention_service import (
            start_background_loop as _dr_bg,
        )
        _dr_bg(engine)
        logger.info("Data retention background loop started")
    run_locked(engine, LOCK_DATA_RETENTION_BG, "data_retention_bg_loop", _start_data_retention,
               hold_until_close=True)

    # ---------------------------------------------------------------
    # Ticker background producer — REMOVED v0.26.1.
    # The loop crashed every tick on an enum-case mismatch
    # (AlertTriageStatus stored as the enum NAME 'OPEN', queried for
    # 'open') AND its auto-flagging design conflicted with the
    # investigation-queue ownership model. Model + table kept dormant
    # for any future redesign. See _backlog_v0_27.md for the design
    # rethink notes.
    # ---------------------------------------------------------------

    # ---------------------------------------------------------------
    # Case-embedding background producer — embeds cases via Ollama for
    # similarity search. Honours ION_EMBEDDING_ENABLED / _INTERVAL_S.
    # Silently no-ops when Ollama isn't reachable.
    # ---------------------------------------------------------------
    def _start_case_embedding_loop():
        from ion.services.case_embedding_service import (
            start_case_embedding_if_enabled,
        )
        start_case_embedding_if_enabled(engine=engine)
        logger.info("Case-embedding background loop started")
    try:
        _start_case_embedding_loop()
    except Exception as exc:
        logger.warning("Failed to start case-embedding loop: %s", exc)

    # ---------------------------------------------------------------
    # KB-article embedding background producer — embeds Knowledge Base
    # documents via Ollama for Bob's RAG grounding at investigation time.
    # Honours ION_KB_RAG_ENABLED / _INTERVAL_S. Silently no-ops when the
    # "Knowledge Base" collection hasn't been seeded or Ollama is unreachable.
    # ---------------------------------------------------------------
    def _start_kb_embedding_loop():
        from ion.services.kb_embedding_service import (
            start_kb_embedding_if_enabled,
        )
        start_kb_embedding_if_enabled(engine=engine)
        logger.info("KB-embedding background loop started")
    try:
        _start_kb_embedding_loop()
    except Exception as exc:
        logger.warning("Failed to start KB-embedding loop: %s", exc)

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
    """Render the main dashboard (Tailwind refresh)."""
    return templates.TemplateResponse(request=request, name="dashboard_v2.html")


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request, user: User = Depends(require_page_permission("template:read"))):
    """Render the templates page."""
    return templates.TemplateResponse(request=request, name="templates.html")


@app.get("/scheduler", response_class=HTMLResponse)
async def scheduler_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the generic job scheduler page."""
    return templates.TemplateResponse(request=request, name="scheduler.html")


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


@app.get("/alerts/{alert_id}/arkime", response_class=HTMLResponse)
async def alert_arkime_page(
    alert_id: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Arkime PCAP investigation workspace — pulls the raw capture for the
    alert, runs pcap_service analysis, enriches observables via OpenCTI, and
    lets the analyst attach the result to a case."""
    return templates.TemplateResponse(
        request=request,
        name="alert_arkime.html",
        context={"alert_id": alert_id},
    )


@app.get("/alerts/{row_id:int}")
async def alert_deeplink(
    row_id: int,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Deep-link to a single alert by AlertTriage row PK.

    v0.30.0: lab_fixture_service._observable_link returns
    `/alerts/<row_id>` for materialised AlertTriage rows. Pre-fix this
    404'd because the alerts page is keyed on `es_alert_id` (a string),
    not the triage row PK. We look up the row, resolve its es_alert_id,
    and redirect to `/alerts?selected=<es_alert_id>` so the list page
    can pre-open the detail panel.

    If the row doesn't exist we redirect to `/alerts` without a
    `selected` param so the user lands on a sensible page instead of a
    404 error.
    """
    from sqlalchemy.orm import Session

    from ion.models.alert_triage import AlertTriage
    from ion.storage.database import get_session

    s: Session = next(get_session())
    try:
        triage = s.query(AlertTriage).filter(AlertTriage.id == row_id).one_or_none()
        if triage is None:
            return RedirectResponse(url="/alerts", status_code=303)
        return RedirectResponse(
            url=f"/alerts?selected={triage.es_alert_id}", status_code=303
        )
    finally:
        s.close()


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request, user: User = Depends(require_page_permission("case:read"))):
    """Render the cases management page."""
    return templates.TemplateResponse(request=request, name="cases.html")


@app.get("/cases/{row_id:int}")
async def case_deeplink(
    row_id: int,
    user: User = Depends(require_page_permission("case:read")),
):
    """Deep-link to a single case by AlertCase row PK.

    v0.30.0 companion to `alert_deeplink` — see that function's
    docstring for the rationale. We look up the case, resolve its
    `case_number`, and redirect to `/cases?selected=<case_number>`.
    """
    from sqlalchemy.orm import Session

    from ion.models.alert_triage import AlertCase
    from ion.storage.database import get_session

    s: Session = next(get_session())
    try:
        case = s.query(AlertCase).filter(AlertCase.id == row_id).one_or_none()
        if case is None:
            return RedirectResponse(url="/cases", status_code=303)
        return RedirectResponse(
            url=f"/cases?selected={case.case_number}", status_code=303
        )
    finally:
        s.close()


@app.get("/observables", response_class=HTMLResponse)
async def observables_page(request: Request, user: User = Depends(require_page_permission("observable:read"))):
    """Render the observables tracking page."""
    return templates.TemplateResponse(request=request, name="observables.html")


@app.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(request: Request, user: User = Depends(require_page_permission("observable:read"))):
    """Render the threat intel page."""
    return templates.TemplateResponse(request=request, name="threat_intel.html")


@app.get("/threat-intel/actors/{entity_id}", response_class=HTMLResponse)
async def threat_intel_actor_profile_page(
    entity_id: str,
    request: Request,
    user: User = Depends(require_page_permission("observable:read")),
):
    """v0.27.0: actor deep-dive page. Data loaded client-side from
    /api/threat-intel/actors/{id}/profile so the page renders fast
    while OpenCTI roundtrips."""
    return templates.TemplateResponse(
        request=request,
        name="threat_intel_actor.html",
        context={"entity_id": entity_id},
    )


# v0.27.0: /threat-landscape page removed; content folded into /threat-intel
# as new IOC Feed + Reports + Analytics tabs. The /api/threat-landscape/*
# router still exists — the unified page calls it for IOC + reports data.
# Redirect old bookmarks rather than 404'ing them.


@app.get("/threat-landscape")
async def threat_landscape_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/threat-intel", status_code=302)


@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the document tools page."""
    return templates.TemplateResponse(request=request, name="tools.html")


@app.get("/cyab/scoping", response_class=HTMLResponse)
async def cyab_scoping_page(request: Request):
    """Anonymous scoping questionnaire — no system created.

    Intentionally has no auth dependency: this is the stakeholder-facing
    surface for "given your stack, here's what coverage you'd get". The
    convert-to-system CTA does require auth (handled in /api/cyab/scoping/convert).
    """
    from ion.services import cyab_scoping_engine
    questions = cyab_scoping_engine.load_questions()
    initial = cyab_scoping_engine.score_answers({})
    return templates.TemplateResponse(
        request=request,
        name="cyab/scoping.html",
        context={"questions": questions, "initial_scores": initial},
    )


@app.get("/cyab", response_class=HTMLResponse)
async def cyab_overview_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """CyAB Overview landing — KPIs + in-progress + needs-attention.

    Replaces the legacy 3,500-line cyab.html dashboard. Per-system
    content moved to /cyab/systems/{id} (Sub-plan A); fleet table moved
    to /cyab/systems (next task).
    """
    from sqlalchemy import select

    from ion.core.config import get_config
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory
    from ion.web.cyab_api import dashboard_metrics

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        # Reuse the existing /api/cyab/dashboard endpoint internally rather
        # than duplicating the math. Call the function directly to avoid
        # the HTTP round-trip.
        kpis = await dashboard_metrics(session=session)

        # In-progress = 5 most-recently-updated systems
        in_progress = session.execute(
            select(CyabSystem).order_by(CyabSystem.updated_at.desc()).limit(5)
        ).scalars().all()

        # Needs-attention = systems with any critical checklist item not done.
        # Stale-data check (last_event_at > 24h) is a Sub-plan C live signal;
        # for Sub-plan B we approximate using the doc-checklist
        # critical-missing flag.
        all_systems = session.execute(select(CyabSystem)).scalars().all()
        needs_attention = []
        for s in all_systems:
            summary = cyab_doc_checklist_service.coverage_summary(session, s.id)
            crit_missing = summary.get("critical_missing") or []
            if crit_missing:
                needs_attention.append(type("Row", (), {
                    "id": s.id, "name": s.name,
                    "reason": f"{len(crit_missing)} critical doc(s) missing",
                })())

        return templates.TemplateResponse(
            request=request,
            name="cyab/overview.html",
            context={
                "kpis": kpis,
                "in_progress": in_progress,
                "needs_attention": needs_attention[:10],
                "active_tab": "overview",
                "user": user,
            },
        )
    finally:
        session.close()


@app.get("/cyab/systems", response_class=HTMLResponse)
async def cyab_systems_list_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Portfolio list — table loads via HTMX from /cyab/systems/_table."""
    from ion.core.config import get_config
    from ion.services.cyab_subprofile_service import (
        list_pillars,
        list_subprofiles_for_pillar,
    )
    from ion.storage.database import get_engine, get_session_factory

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        pillars = list_pillars(session)
        # Flatten sub-profiles across all pillars for the global filter.
        subprofiles = []
        for p in pillars:
            subprofiles.extend(list_subprofiles_for_pillar(session, p["id"]))
        return templates.TemplateResponse(
            request=request,
            name="cyab/systems_list.html",
            context={
                "active_tab": "systems",
                "user": user,
                "pillars": pillars,
                "subprofiles": subprofiles,
            },
        )
    finally:
        session.close()


@app.get("/cyab/systems/_table", response_class=HTMLResponse)
async def cyab_systems_table_partial(
    request: Request,
    q: str = "",
    pillar: str = "",
    subprofile: str = "",
    status: str = "",
    owner: str = "",
    missing: str = "",
    stale: int = 0,
    user: User = Depends(require_page_permission("alert:read")),
):
    """HTMX partial — filtered + searched portfolio table.

    Reuses the same data set as /api/cyab/systems but filters server-side
    so HTMX swaps stay fast.
    """
    from sqlalchemy import select

    from ion.core.config import get_config
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        stmt = select(CyabSystem)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(
                (CyabSystem.name.ilike(like))
                | (CyabSystem.soc_analyst_owner.ilike(like))
            )
        if status:
            stmt = stmt.where(CyabSystem.status == status)
        if owner:
            stmt = stmt.where(CyabSystem.soc_analyst_owner.ilike(f"%{owner}%"))
        # pillar / subprofile filters work on the data-source level — for
        # simplicity in this sub-plan filter post-fetch (Sub-plan C will
        # join CyabDataSource.subprofile_id → pillar).

        systems = session.execute(
            stmt.order_by(CyabSystem.updated_at.desc().nulls_last())
        ).scalars().all()

        rows = []
        for s in systems:
            summary = cyab_doc_checklist_service.coverage_summary(session, s.id)
            crit = summary.get("critical_missing") or []
            if missing and missing not in crit:
                continue
            rows.append(type("Row", (), {
                "id": s.id,
                "name": s.name,
                "pillar": None,        # joined in via subprofile in Sub-plan C
                "subprofile": None,
                "owner": s.soc_analyst_owner,
                "progress": summary,
                "critical_missing": len(crit),
                "updated_at": s.updated_at,
                "status": s.status,
            })())

        return templates.TemplateResponse(
            request=request,
            name="cyab/_systems_table.html",
            context={"rows": rows},
        )
    finally:
        session.close()


@app.post("/api/cyab/systems/bulk")
async def cyab_systems_bulk(
    payload: dict,
    user: User = Depends(require_page_permission("alert:read")),
):
    """{action, system_ids} — mark-reviewed | export-csv | rerun-health.

    The rerun-health action is a stub for Sub-plan C; the response shape
    matches the other actions so the UI flow stays uniform.
    """
    import csv
    import io
    from datetime import date

    from fastapi.responses import Response
    from sqlalchemy import select

    from ion.core.config import get_config
    from ion.models.cyab import CyabSystem
    from ion.storage.database import get_engine, get_session_factory

    action = payload.get("action")
    ids = payload.get("system_ids") or []
    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        rows = session.execute(
            select(CyabSystem).where(CyabSystem.id.in_(ids))
        ).scalars().all()

        if action == "mark-reviewed":
            today = date.today()
            for s in rows:
                s.last_reviewed_date = today
            session.commit()
            return {"affected": len(rows)}

        if action == "export-csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["id", "name", "department", "owner", "status", "readiness"])
            for s in rows:
                w.writerow([
                    s.id, s.name, s.department, s.soc_analyst_owner or "",
                    s.status, s.readiness_score,
                ])
            return Response(
                content=buf.getvalue(),
                media_type="text/csv",
                headers={"content-disposition": "attachment; filename=cyab-systems.csv"},
            )

        if action == "rerun-health":
            # Stub — Sub-plan C wires the live data-health service into a job.
            return JSONResponse(
                status_code=202,
                content={
                    "affected": len(rows),
                    "note": "queued (stub)",
                },
            )

        # v0.19.7: bulk delete. Reuses _delete_system_row from
        # cyab_api (migrated from cyab_studio_api in v0.20.0) so the
        # data_sources / snapshots cascade is identical to the
        # single-row endpoint.
        # v0.19.16: privilege gate. The enclosing endpoint is
        # require_page_permission("alert:read") because the read-ish
        # actions (mark-reviewed/export-csv/rerun-health) are fine for
        # any analyst. delete-selected is destructive and must match
        # the case:update gate the per-row DELETE /api/cyab/systems/{id}
        # endpoint already enforces.
        # v0.19.16: also catches IntegrityError per-row so a single
        # FK-violation doesn't poison the shared session for the rest
        # of the user's selection.
        if action == "delete-selected":
            if not user.has_permission("case:update"):
                raise HTTPException(
                    status_code=403,
                    detail="case:update permission required for bulk delete",
                )
            from sqlalchemy.exc import IntegrityError

            from ion.web.cyab_api import _delete_system_row
            deleted = 0
            failed: list[int] = []
            for s in rows:
                try:
                    if _delete_system_row(session, s.id):
                        deleted += 1
                except IntegrityError as exc:
                    session.rollback()
                    failed.append(s.id)
                    logger.warning(
                        "bulk delete: FK violation deleting CyAB system %s: %s",
                        s.id, str(exc)[:120],
                    )
                    continue
            out: dict = {"affected": deleted}
            if failed:
                out["failed_ids"] = failed
            return out

        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")
    finally:
        session.close()



@app.get("/cyab/systems/{system_id}", response_class=HTMLResponse)
async def cyab_system_detail_page(
    system_id: int,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Per-system CyAB page (replaces /cyab/studio for a given system)."""
    from ion.core.config import get_config
    from ion.models.cyab import CyabSystem
    from ion.services import cyab_doc_checklist_service
    from ion.storage.database import get_engine, get_session_factory

    config = get_config()
    engine = get_engine(config.db_path)
    Session = get_session_factory(engine)
    session = Session()
    try:
        system = session.get(CyabSystem, system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")

        # Lazy-seed checklist on first access (idempotent)
        cyab_doc_checklist_service.seed_for_system(session, system_id)
        progress = cyab_doc_checklist_service.coverage_summary(session, system_id)

        return templates.TemplateResponse(
            request=request,
            name="cyab/system_detail.html",
            context={"system": system, "user": user, "progress": progress},
        )
    finally:
        session.close()


_CYAB_TABS = {
    "overview": ("Overview", "cyab/tabs/_overview.html"),
    "intake": ("Intake", "cyab/tabs/_intake.html"),
    "sources": ("Sources", "cyab/tabs/_sources.html"),
    "data-health": ("Data Health", "cyab/tabs/_data_health.html"),
    "detection": ("Detection Use Cases", "cyab/tabs/_detection.html"),
    "audit-use-cases": ("Audit Use Cases", "cyab/tabs/_audit_use_cases.html"),
    "signoff": ("Sign-off", "cyab/tabs/_signoff.html"),
}


@app.get("/cyab/systems/{system_id}/tab/{tab_name}", response_class=HTMLResponse)
async def cyab_system_tab(
    system_id: int,
    tab_name: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """HTMX endpoint returning a single tab's content (no page chrome)."""
    if tab_name not in _CYAB_TABS:
        raise HTTPException(status_code=404, detail="Unknown tab")

    label, template_name = _CYAB_TABS[tab_name]

    from ion.core.config import get_config
    from ion.models.cyab import CyabSystem
    from ion.storage.database import get_engine, get_session_factory

    config = get_config()
    engine = get_engine(config.db_path)
    Session = get_session_factory(engine)
    session = Session()
    try:
        system = session.get(CyabSystem, system_id)
        if not system:
            raise HTTPException(status_code=404, detail="System not found")

        ctx = {"system": system, "user": user, "tab_name": tab_name, "tab_label": label}

        if tab_name == "overview":
            from ion.services import cyab_doc_checklist_service
            cyab_doc_checklist_service.seed_for_system(session, system_id)  # idempotent
            ctx["checklist"] = cyab_doc_checklist_service.list_for_system(session, system_id)
            ctx["progress"] = cyab_doc_checklist_service.coverage_summary(session, system_id)
        elif tab_name == "intake":
            from ion.services.cyab_assessment_service import load_answers
            from ion.services.cyab_subprofile_service import (
                get_subprofile_full,
                system_coverage,
            )
            # The sub-profile tag lives on data sources (see
            # CyabDataSource.subprofile_id). For the per-system intake
            # view, pick the first tagged source's sub-profile as the
            # primary one. Future: per-source intake tabs.
            sub_id = next(
                (ds.subprofile_id for ds in system.data_sources if ds.subprofile_id),
                None,
            )
            ctx["subprofile"] = (
                get_subprofile_full(session, sub_id) if sub_id else None
            )
            ctx["coverage"] = system_coverage(session, system_id)
            ctx["answers"] = load_answers(session, system_id) or {}
        elif tab_name == "sources":
            import json as _json

            from sqlalchemy import select

            from ion.models.cyab import CyabDataSource
            sources = session.execute(
                select(CyabDataSource)
                .where(CyabDataSource.system_id == system_id)
                .order_by(CyabDataSource.name)
            ).scalars().all()
            # field_mapping is JSON-as-text on the model; parse once per
            # source so the template can iterate without a custom filter.
            mappings = {}
            for ds in sources:
                if ds.field_mapping:
                    try:
                        parsed = _json.loads(ds.field_mapping)
                        if isinstance(parsed, dict):
                            mappings[ds.id] = parsed
                    except (ValueError, TypeError):
                        pass
            ctx["sources"] = sources
            ctx["source_mappings"] = mappings
        elif tab_name == "data-health":
            from ion.services import cyab_data_health_service as dh
            ctx["ingestion"] = dh.ingestion_freshness(session, system_id)
            ctx["mapping"] = dh.field_mapping_completeness(session, system_id)
            ctx["coverage"] = dh.coverage_rollup(session, system_id)
            ctx["reconciliation"] = dh.reconciliation_panel(session, system_id)
        elif tab_name == "signoff":
            from ion.services import cyab_doc_checklist_service
            ctx["progress"] = cyab_doc_checklist_service.coverage_summary(session, system_id)
            # Existing sign-off history lives on CyabSystem itself
            # (sign_dept_*/sign_soc_* — populated by the existing
            # POST /api/cyab/systems/{id}/onboarding-pack/sign
            # endpoint). The CyabSnapshot model has no ``kind`` or
            # ``signed_by`` columns, so the de-duped history is read
            # directly from the canonical fields on the system row.
            signoffs = []
            if system.sign_dept_name and system.sign_dept_date:
                signoffs.append({
                    "role": "Department",
                    "signed_by": system.sign_dept_name,
                    "signed_on": system.sign_dept_date,
                })
            if system.sign_soc_name and system.sign_soc_date:
                signoffs.append({
                    "role": "SOC",
                    "signed_by": system.sign_soc_name,
                    "signed_on": system.sign_soc_date,
                })
            # Newest first (the two are typically same-day; tie-break by role)
            signoffs.sort(key=lambda x: (x["signed_on"], x["role"]), reverse=True)
            ctx["signoffs"] = signoffs
        elif tab_name in ("detection", "audit-use-cases"):
            from ion.services.cyab_subprofile_service import get_subprofile_full
            # Per Task 5 finding, subprofile_id lives on CyabDataSource (not
            # CyabSystem). Resolve the system's primary sub-profile from the
            # first tagged data source.
            sub_id = next(
                (ds.subprofile_id for ds in system.data_sources if ds.subprofile_id),
                None,
            )
            sub = get_subprofile_full(session, sub_id) if sub_id else None
            cat = (sub or {}).get("catalogue") if sub else {}
            key = "detection_use_cases" if tab_name == "detection" else "audit_use_cases"
            ctx["use_cases"] = (cat or {}).get(key, []) if cat else []
            ctx["subprofile"] = sub
            # Per-source status (existing studio JS cycles via the existing
            # use-case-status endpoint, keyed by source id + uc id).
            from sqlalchemy import select

            from ion.models.cyab import CyabDataSource
            ctx["sources"] = session.execute(
                select(CyabDataSource).where(CyabDataSource.system_id == system_id)
            ).scalars().all()

        # Fall back to the placeholder template if the tab template doesn't exist yet.
        from jinja2 import TemplateNotFound
        try:
            return templates.TemplateResponse(request=request, name=template_name, context=ctx)
        except TemplateNotFound:
            return templates.TemplateResponse(
                request=request,
                name="cyab/tabs/_placeholder.html",
                context={"tab_name": tab_name, "tab_label": label},
            )
    finally:
        session.close()


@app.get("/cyab/coverage", response_class=HTMLResponse)
async def cyab_coverage_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Fleet data-health matrix: systems x dimensions.

    Calls into the matrix builder helper directly (rather than HTTP-calling
    our own /api endpoint) so the request stays in-process. Filters mirror
    the API: ``pillar``, ``owner``, ``any_red``.
    """
    from ion.web.cyab_api import _build_coverage_matrix
    matrix = _build_coverage_matrix(
        pillar=request.query_params.get("pillar") or None,
        owner=request.query_params.get("owner") or None,
        any_red=int(request.query_params.get("any_red") or 0),
    )
    return templates.TemplateResponse(
        request=request,
        name="cyab/coverage.html",
        context={
            "matrix": matrix,
            "user": user,
            "active_tab": "coverage",
            "filters": {
                "pillar":  request.query_params.get("pillar") or "",
                "owner":   request.query_params.get("owner") or "",
                "any_red": request.query_params.get("any_red") or "",
            },
        },
    )


@app.get("/cyab/audit", response_class=HTMLResponse)
async def cyab_audit_page(
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Compliance audit trail.

    Chronological union of sign-offs, checklist deltas, system lifecycle
    events, and containment-authority changes. Calls the audit_feed
    helper directly (rather than HTTP-calling our own /api endpoint) so
    the request stays in-process — same pattern as /cyab/coverage.
    """
    from ion.core.config import get_config
    from ion.storage.database import get_engine, get_session_factory
    from ion.web.cyab_api import audit_feed

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        sid_raw = request.query_params.get("system_id") or ""
        try:
            sid = int(sid_raw) if sid_raw else None
        except ValueError:
            sid = None
        feed = await audit_feed(
            system_id=sid,
            user=request.query_params.get("user") or None,
            action_type=request.query_params.get("action_type") or None,
            since=request.query_params.get("since") or None,
            until=request.query_params.get("until") or None,
            session=session,
        )
    finally:
        session.close()

    return templates.TemplateResponse(
        request=request,
        name="cyab/audit.html",
        context={
            "feed": feed,
            "user": user,
            "active_tab": "audit",
            "filters": {
                "system_id":   request.query_params.get("system_id") or "",
                "user":        request.query_params.get("user") or "",
                "action_type": request.query_params.get("action_type") or "",
                "since":       request.query_params.get("since") or "",
                "until":       request.query_params.get("until") or "",
            },
        },
    )


# ---------------------------------------------------------------------------
# CyAB MITRE ATT&CK Heatmap (v0.22.0)
# ---------------------------------------------------------------------------


@app.get("/cyab/attack-heatmap", response_class=HTMLResponse)
async def cyab_attack_heatmap_page(
    request: Request,
    rollup: str = "subtechnique",
    tactic: str = "",
    state: str = "",
    system_id: str = "",
    user: User = Depends(require_page_permission("alert:read")),
):
    """MITRE ATT&CK technique-coverage heatmap.

    Renders a full-page grid of every technique, colour-coded by coverage
    state. Filters (rollup, tactic, state) are ?param= GET parameters so
    the form can GET-submit with no JS state.
    """
    from ion.core.config import get_config
    from ion.services.mitre_heatmap_service import get_heatmap
    from ion.storage.database import get_engine, get_session_factory

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        sid: int | None = None
        if system_id:
            try:
                sid = int(system_id)
            except ValueError:
                sid = None
        heatmap = get_heatmap(session, system_id=sid)
    finally:
        session.close()

    # Apply client-side filters before template render.
    cells = heatmap["cells"]

    if tactic:
        cells = [c for c in cells if tactic in c["tactic_ids"]]

    if state:
        cells = [c for c in cells if c["cell_state"] == state]

    if rollup == "parent":
        cells = _rollup_to_parent(cells)

    # Group by tactic for section headers.
    tactic_groups = _group_by_tactic(cells)

    return templates.TemplateResponse(
        request=request,
        name="cyab/attack_heatmap.html",
        context={
            "heatmap": heatmap,
            "cells": cells,
            "tactic_groups": tactic_groups,
            "summary": heatmap["summary"],
            "user": user,
            "active_tab": "attack_heatmap",
            "filters": {
                "rollup": rollup,
                "tactic": tactic,
                "state": state,
                "system_id": system_id,
            },
        },
    )


def _rollup_to_parent(cells: list) -> list:
    """Collapse sub-techniques to parent row, taking max cell_state."""
    _state_rank = {
        "not_covered_seen": 3,
        "covered_exercised": 2,
        "covered_not_exercised": 1,
        "not_covered_not_seen": 0,
    }
    parent_map: dict = {}
    standalone = []
    for cell in cells:
        tid = cell["technique_id"]
        if "." in tid:
            parent_id = tid.rsplit(".", 1)[0]
            existing = parent_map.get(parent_id)
            if existing is None or (
                _state_rank.get(cell["cell_state"], 0)
                > _state_rank.get(existing["cell_state"], 0)
            ):
                # Merge sub-technique counts onto parent placeholder.
                merged = dict(cell)
                merged["technique_id"] = parent_id
                parent_map[parent_id] = merged
            else:
                # Accumulate counts onto winner.
                existing["alert_case_count"] += cell["alert_case_count"]
                existing["pin_count"] += cell["pin_count"]
        else:
            standalone.append(cell)

    # Merge parent placeholders with any standalone parent cells.
    by_id = {c["technique_id"]: c for c in standalone}
    for parent_id, merged in parent_map.items():
        if parent_id in by_id:
            existing = by_id[parent_id]
            existing["alert_case_count"] += merged["alert_case_count"]
            existing["pin_count"] += merged["pin_count"]
            if (
                _state_rank.get(merged["cell_state"], 0)
                > _state_rank.get(existing["cell_state"], 0)
            ):
                existing["cell_state"] = merged["cell_state"]
        else:
            by_id[parent_id] = merged

    return sorted(by_id.values(), key=lambda c: c["technique_id"])


def _group_by_tactic(cells: list) -> list:
    """Return [{tactic_id, label, cells}, ...] grouped by first tactic_id."""
    _TACTIC_LABELS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact",
        "TA0042": "Resource Development",
        "TA0043": "Reconnaissance",
    }
    groups: dict = {}
    uncategorized = []
    for cell in cells:
        tactic_ids = cell.get("tactic_ids") or []
        if not tactic_ids:
            uncategorized.append(cell)
            continue
        for tid in sorted(tactic_ids):
            groups.setdefault(tid, []).append(cell)

    result = []
    for tid in sorted(groups.keys()):
        result.append(
            {
                "tactic_id": tid,
                "label": _TACTIC_LABELS.get(tid, tid),
                "cells": groups[tid],
            }
        )
    if uncategorized:
        result.append(
            {"tactic_id": "", "label": "Uncategorized", "cells": uncategorized}
        )
    return result


# ---------------------------------------------------------------------------
# CyAB Onboarding Wizard (Sub-plan B / Task 3)
# ---------------------------------------------------------------------------


@app.get("/cyab/onboard", response_class=HTMLResponse)
async def cyab_onboard_page(
    request: Request,
    wid: str | None = None,
    step: int = 1,
    user: User = Depends(require_page_permission("alert:read")),
):
    """4-step wizard. Without ``wid``, starts a new session and 302s with
    the wid baked in so refresh/back work.

    Each step is a separate URL so back/forward navigation works. POST
    /api/cyab/onboard/{wid}/step/{n} advances state and returns an
    HTMX-replaceable partial.
    """
    from ion.core.config import get_config
    from ion.services import cyab_wizard_service
    from ion.services.cyab_subprofile_service import (
        list_pillars,
        list_subprofiles_for_pillar,
    )
    from ion.storage.database import get_engine, get_session_factory

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        if not wid:
            new_wid = cyab_wizard_service.start_wizard(
                session, user_id=getattr(user, "id", None)
            )
            return RedirectResponse(
                url=f"/cyab/onboard?wid={new_wid}&step=1", status_code=302
            )

        try:
            state = cyab_wizard_service.load_state(session, wid)
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        # Aggregate sub-profiles across all pillars (the catalogue helper
        # is per-pillar; the wizard form needs a flat list for the
        # combined dropdown).
        pillars = list_pillars(session)
        subprofiles: list = []
        for p in pillars:
            subprofiles.extend(list_subprofiles_for_pillar(session, p["id"]))

        ctx = {
            "wid": wid,
            "step": step,
            "state": state,
            "pillars": pillars,
            "subprofiles": subprofiles,
            "active_tab": "onboard",
            "user": user,
        }

        # Step 4 needs the seeded checklist so a refresh on ?step=4 works.
        if step == 4 and state.get("system_id"):
            from ion.services import cyab_doc_checklist_service
            cyab_doc_checklist_service.seed_for_system(
                session, state["system_id"]
            )
            ctx["checklist"] = cyab_doc_checklist_service.list_for_system(
                session, state["system_id"]
            )

        # Step 2 needs the live counter pre-rendered with the current
        # answer set so a hard refresh shows the right numbers (HTMX
        # then takes over for subsequent updates). Same engine as the
        # /cyab/scoping page — shared backend per the spec.
        if step == 2:
            from ion.services import cyab_scoping_engine
            ctx["scoping_initial"] = cyab_scoping_engine.score_answers(
                state.get("intake", {}) or {}
            )

        return templates.TemplateResponse(
            request=request, name="cyab/onboard.html", context=ctx
        )
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/step/1", response_class=HTMLResponse)
async def cyab_onboard_step_1(
    wid: str,
    request: Request,
    name: str = Form(...),
    department: str = Form(...),
    hostname: str = Form(""),
    pillar: str = Form(""),
    subprofile_id: str = Form(""),
    owner: str = Form(""),
    containment_authority: str = Form(""),
    user: User = Depends(require_page_permission("alert:read")),
):
    """Step 1 — Identity. Persists fields and creates the backing
    CyabSystem row via ``cyab_wizard_service.save_identity``. Returns
    the Step 2 partial for HTMX clients, or a 303 redirect for plain
    browsers."""
    from ion.core.config import get_config
    from ion.services import cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory

    config = get_config()
    Session = get_session_factory(get_engine(config.db_path))
    session = Session()
    try:
        try:
            state = cyab_wizard_service.save_identity(
                session,
                wid,
                identity={
                    "name": name,
                    "hostname": hostname,
                    "pillar": pillar,
                    "subprofile_id": subprofile_id,
                    "owner": owner,
                    "department": department,
                    "containment_authority": containment_authority,
                },
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        # Render Step 2 partial inline (HTMX swap), or 303 for non-HTMX clients.
        if request.headers.get("hx-request") == "true":
            from jinja2 import TemplateNotFound
            try:
                return templates.TemplateResponse(
                    request=request,
                    name="cyab/_wizard_step_2_intake.html",
                    context={"wid": wid, "step": 2, "state": state},
                )
            except TemplateNotFound:
                # Step 2 partial lands in Task 4 — fall through to redirect
                # so HTMX clients still progress in the meantime.
                pass
        return RedirectResponse(
            url=f"/cyab/onboard?wid={wid}&step=2", status_code=303
        )
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/step/2", response_class=HTMLResponse)
async def cyab_onboard_step_2(
    wid: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Step 2 — Intake. Persists the snapshot of answers in the wizard
    blob (real autosave goes via the Studio answers endpoint). Returns
    Step 3 partial for HTMX or 303 redirects to the Step 3 URL."""
    from ion.core.config import get_config
    from ion.services import cyab_wizard_service
    from ion.services.cyab_subprofile_service import (
        list_pillars,
        list_subprofiles_for_pillar,
    )
    from ion.storage.database import get_engine, get_session_factory

    form = await request.form()
    answers = {
        k.split("[", 1)[1].rstrip("]"): v
        for k, v in form.items() if k.startswith("answers[")
    }

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            cyab_wizard_service.save_intake(session, wid, answers=answers)
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        if request.headers.get("hx-request") == "true":
            state = cyab_wizard_service.load_state(session, wid)
            # Aggregate sub-profiles across all pillars (same shape the
            # GET handler builds) so the Step 3 partial dropdown renders.
            subprofiles: list = []
            for p in list_pillars(session):
                subprofiles.extend(list_subprofiles_for_pillar(session, p["id"]))
            return templates.TemplateResponse(
                request=request, name="cyab/_wizard_step_3_source.html",
                context={
                    "wid": wid, "step": 3, "state": state,
                    "subprofiles": subprofiles,
                },
            )
        return RedirectResponse(
            url=f"/cyab/onboard?wid={wid}&step=3", status_code=303
        )
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/step/3", response_class=HTMLResponse)
async def cyab_onboard_step_3(
    wid: str,
    request: Request,
    name: str = Form(...),
    data_source_type: str = Form(""),
    subprofile_id: str = Form(""),
    user: User = Depends(require_page_permission("alert:read")),
):
    """Step 3 — First data source. Persists a CyabDataSource on the
    backing system, lazy-seeds the doc checklist so Step 4 has rows to
    render, and either returns the Step 4 partial (HTMX) or redirects."""
    from ion.core.config import get_config
    from ion.services import cyab_doc_checklist_service, cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            state = cyab_wizard_service.save_source(
                session, wid,
                source={
                    "name": name,
                    "data_source_type": data_source_type or None,
                    "subprofile_id": subprofile_id or None,
                },
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")

        # Lazy-seed the checklist now so Step 4 has rows to render.
        cyab_doc_checklist_service.seed_for_system(session, state["system_id"])
        checklist = cyab_doc_checklist_service.list_for_system(
            session, state["system_id"]
        )

        if request.headers.get("hx-request") == "true":
            return templates.TemplateResponse(
                request=request, name="cyab/_wizard_step_4_docs.html",
                context={
                    "wid": wid, "step": 4, "state": state,
                    "checklist": checklist,
                },
            )
        return RedirectResponse(
            url=f"/cyab/onboard?wid={wid}&step=4", status_code=303
        )
    finally:
        session.close()


@app.post("/api/cyab/onboard/{wid}/finish")
async def cyab_onboard_finish(
    wid: str,
    request: Request,
    user: User = Depends(require_page_permission("alert:read")),
):
    """Apply doc-placeholder overrides, mark wizard complete, redirect to
    the per-system page."""
    from ion.core.config import get_config
    from ion.services import cyab_wizard_service
    from ion.storage.database import get_engine, get_session_factory

    form = await request.form()
    # Parse docs[<kind>][<field>] = value
    overrides: dict[str, dict] = {}
    for k, v in form.items():
        if not k.startswith("docs["):
            continue
        # docs[HLD][url] -> ('HLD', 'url')
        rest = k[len("docs["):]
        try:
            kind, field = rest.split("][", 1)
        except ValueError:
            continue
        field = field.rstrip("]")
        overrides.setdefault(kind, {})[field] = v

    Session = get_session_factory(get_engine(get_config().db_path))
    session = Session()
    try:
        try:
            sys_id = cyab_wizard_service.finish(
                session, wid, doc_overrides=overrides
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="Wizard session not found")
        return RedirectResponse(
            url=f"/cyab/systems/{sys_id}", status_code=303
        )
    finally:
        session.close()


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
    """Render the Data Flow visualization page (legacy / modern / compare).

    Recovered from v0.9.61 in v0.9.70 — the page + route + integration
    metrics endpoint were lost when v0.9.61's working tree was never
    committed back to git after the docker push.
    """
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





@app.get("/shift-handover", response_class=HTMLResponse)
async def shift_handover_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Shift Handover Report page."""
    return templates.TemplateResponse(request=request, name="shift_handover.html")


@app.get("/daily-standup", response_class=HTMLResponse)
async def daily_standup_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Daily SOC Standup / Duty Check page."""
    return templates.TemplateResponse(request=request, name="daily_standup.html")


@app.get("/daily-standup/slides", response_class=HTMLResponse)
async def daily_standup_slides_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """v0.19.9: presentation-mode slide deck of the daily standup.

    Pulls the same /api/daily-standup/checks payload as the live page
    and renders one panel per slide. Keyboard-navigable (← / → / Esc /
    F for fullscreen). Shareable URL — useful for screen-sharing the
    standup without overwhelming participants with the full data table
    view.
    """
    return templates.TemplateResponse(request=request, name="daily_standup_slides.html")




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


# v0.27.0: /attack-stories page removed; content folded into the
# /threat-intel "Attack Stories" tab. The /api/attack-stories endpoint
# still exists — the unified page calls it.


@app.get("/attack-stories")
async def attack_stories_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/threat-intel", status_code=302)


@app.get("/executive-report", response_class=HTMLResponse)
async def executive_report_page(request: Request, user: User = Depends(require_page_permission("alert:read"))):
    """Render the Executive Report page."""
    return templates.TemplateResponse(request=request, name="executive_report.html")


# v0.27.0: /threat-hunting page + threat_hunt_api router + ThreatHunt
# model + threat_hunts table removed. The half-built CRUD shell never
# integrated with /discover (where hunt queries actually run) or /cases
# (where findings get recorded), so it was deleted rather than fleshed
# out. Real hunting workflow: write the query in /discover, record the
# verdict in the case the query produced.



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


@app.get("/network-map", response_class=HTMLResponse)
async def network_map_page(request: Request, user: User = Depends(require_page_auth)):
    """Render the Network Mapper / CMDB page."""
    return templates.TemplateResponse(request=request, name="network_map.html")


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
