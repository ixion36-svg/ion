"""Database connection and initialization.

Supports SQLite (default) and PostgreSQL.
Set ION_DATABASE_URL to a PostgreSQL connection string to use PostgreSQL:
    ION_DATABASE_URL=postgresql://user:pass@host:5432/ion

When ION_DATABASE_URL is not set, falls back to SQLite at the configured db_path.
PostgreSQL requires the 'postgres' extra: pip install ion[postgres]
"""

import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Generator, Iterator, Optional
from sqlalchemy import create_engine, Engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from ion.models.base import Base
from ion.core.config import get_config

# Import all models to ensure they are registered with Base.metadata
# This is required for create_all() to create all tables
import ion.models  # noqa: F401

logger = logging.getLogger(__name__)

_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker[Session]] = None

# Module-level store of pinned advisory-lock connections. When a hook is
# wrapped with `hold_until_close=True`, the lock-holding connection is
# stashed here so it never goes out of scope and the lock survives for
# the worker's lifetime — preventing other workers from re-acquiring and
# re-running the same hook (e.g. don't start 4 TIDE background loops).
_pinned_lock_conns: dict = {}


def _is_postgres(engine: Engine) -> bool:
    """Check if the engine is connected to PostgreSQL."""
    return engine.dialect.name == "postgresql"


# =========================================================================
# Cross-worker coordination via Postgres advisory locks
# =========================================================================
#
# uvicorn spawns N worker processes (ION_WORKERS) which all run the
# FastAPI startup event independently. That means each worker tries to
# run every seed/migration/background-task starter in parallel — leading
# to constraint violations, wasted work, and (worst case) postgres
# deadlocks when multiple workers race on the same rows.
#
# `pg_try_advisory_lock` is a session-scoped, non-blocking lock — only
# one worker acquires it; the rest see False and skip. Locks auto-release
# when the holding session closes (so a crashed worker doesn't strand
# them). On non-postgres backends we yield True so single-process setups
# (sqlite dev) still run all hooks.
#
# Lock IDs are unique constants centralised here so they can't collide.

# Lock IDs — MUST be unique across the codebase. Use the 1000-1999 range.
LOCK_RUN_MIGRATIONS         = 1001
LOCK_SEED_PERMISSIONS       = 1002
LOCK_SEED_DEFAULT_PLAYBOOKS = 1003
LOCK_SEED_SOC_TEMPLATES     = 1004
LOCK_SEED_KNOWLEDGE_BASE    = 1005
LOCK_SEED_FORENSIC_PB       = 1006
LOCK_SEED_CAPABILITY_KB     = 1007
LOCK_SKILLS_DAILY_SNAPSHOT  = 1008
LOCK_SEED_ANALYTICS_JOBS    = 1009
LOCK_KIBANA_BG_SYNC         = 1010
LOCK_TIDE_BG_SYNC           = 1011
# 1012 was LOCK_CYAB_REVIEW_CHECK — removed in v0.9.76 with the notifications feature
LOCK_ANALYTICS_BG_LOOP      = 1013


@contextmanager
def advisory_lock(engine: Engine, lock_id: int, *, hold_until_close: bool = False) -> Iterator[bool]:
    """Acquire a non-blocking Postgres advisory lock for cross-worker coordination.

    Yields True if this caller acquired the lock and should run the work,
    False if another worker already holds it (skip the work). On non-postgres
    backends (e.g. SQLite) yields True so single-process setups still run
    all hooks normally.

    Two modes:

    - **hold_until_close=False (default)**: the lock is released as soon as
      the `with` block exits. Subsequent workers can re-acquire it and run
      the same hook again. Use this for idempotent seeds — concurrent races
      are prevented but serial re-runs are harmless because each invocation
      checks "already seeded" and skips.

    - **hold_until_close=True**: the lock-holding connection is pinned to
      module state and never closed for the worker's lifetime. Subsequent
      workers see the lock as held and skip permanently. Use this for
      single-instance background loops (TIDE bg sync, Analytics loop, etc.)
      so we don't end up with 4× duplicate background tasks. The lock
      auto-releases on connection drop, so a worker crash hands ownership
      to a sibling worker on the next restart cycle.
    """
    if not _is_postgres(engine):
        yield True
        return

    # Already pinned by THIS worker? Treat as acquired without re-locking.
    if lock_id in _pinned_lock_conns:
        yield True
        return

    conn = engine.connect()
    acquired = False
    try:
        result = conn.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id})
        acquired = bool(result.scalar())
        yield acquired
    finally:
        if acquired and hold_until_close:
            # Pin the connection to module state so the lock survives the
            # rest of the worker's lifetime. Do NOT close.
            _pinned_lock_conns[lock_id] = conn
            return
        if acquired:
            try:
                conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id})
                conn.commit()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


def run_locked(
    engine: Engine,
    lock_id: int,
    label: str,
    fn: Callable[[], None],
    *,
    hold_until_close: bool = False,
) -> bool:
    """Run `fn` only if this worker acquires the advisory lock.

    `hold_until_close` is passed through to advisory_lock — set True for
    single-instance background loops, False (default) for idempotent seeds.

    Returns True if the work ran, False if skipped (another worker holds
    the lock). Logs at debug for skips, warning for exceptions inside the
    work itself. Does NOT re-raise — startup hooks are best-effort.
    """
    with advisory_lock(engine, lock_id, hold_until_close=hold_until_close) as acquired:
        if not acquired:
            logger.debug("Skipping %s — another worker holds lock %d", label, lock_id)
            return False
        try:
            fn()
            return True
        except Exception as e:
            logger.warning("Failed %s (lock %d): %s", label, lock_id, e)
            return False


def _set_sqlite_pragmas(dbapi_conn, connection_record):
    """Set SQLite pragmas on each new connection for concurrency and durability."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")       # allow concurrent readers + writer
    cursor.execute("PRAGMA busy_timeout=30000")      # wait up to 30s instead of failing immediately
    cursor.execute("PRAGMA synchronous=NORMAL")      # safe with WAL, faster than FULL
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(db_path: Optional[Path] = None) -> Engine:
    """Get or create the database engine.

    If ION_DATABASE_URL is set, connects to that database (PostgreSQL).
    Otherwise falls back to SQLite at db_path.
    """
    global _engine
    if _engine is None:
        database_url = os.environ.get("ION_DATABASE_URL")

        if database_url:
            # PostgreSQL (or any external DB)
            logger.info("Using database: %s", database_url.split("@")[-1] if "@" in database_url else "external")
            _engine = create_engine(
                database_url,
                echo=False,
                # Steady-state pool of 25 connections + 50 burst overflow.
                # The pool_timeout is intentionally short (5s) so a request
                # that can't get a connection fails *fast* with a clear error
                # instead of stalling the worker for 30s. With the new TIDE
                # budget cap (20s) and concurrency throttle (3 concurrent),
                # the typical request should never wait this long anyway.
                pool_size=25,
                max_overflow=50,
                pool_timeout=5,
                pool_pre_ping=True,
                pool_recycle=900,
            )
        else:
            # SQLite (default)
            if db_path is None:
                db_path = get_config().db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            _engine = create_engine(
                f"sqlite:///{db_path}",
                echo=False,
                connect_args={"check_same_thread": False},
                pool_size=5,
                max_overflow=10,
                pool_timeout=30,
                pool_pre_ping=True,
                pool_recycle=600,
            )
            from sqlalchemy import event
            event.listen(_engine, "connect", _set_sqlite_pragmas)
    return _engine


def get_session_factory(engine: Optional[Engine] = None) -> sessionmaker[Session]:
    """Get or create the session factory."""
    global _session_factory
    if _session_factory is None:
        if engine is None:
            engine = get_engine()
        _session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    return _session_factory


def get_session(engine: Optional[Engine] = None) -> Generator[Session, None, None]:
    """Get a database session as a context manager."""
    factory = get_session_factory(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _run_migrations(engine: Engine) -> None:
    """Add missing columns to existing tables. Idempotent."""
    insp = inspect(engine)
    # Use TIMESTAMP for PostgreSQL, DATETIME for SQLite
    dt_type = "TIMESTAMP" if _is_postgres(engine) else "DATETIME"

    # v0.9.76: drop the notifications table — feature removed. Safe & idempotent.
    if insp.has_table("notifications"):
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE notifications"))
            logger.info("Migrated: dropped notifications table (v0.9.76)")

    # Migrations for alert_cases table
    if insp.has_table("alert_cases"):
        existing = {col["name"] for col in insp.get_columns("alert_cases")}
        new_columns = {
            "affected_hosts": "JSON",
            "affected_users": "JSON",
            "triggered_rules": "JSON",
            "evidence_summary": "TEXT",
            "source_alert_ids": "JSON",
            "kibana_case_id": "VARCHAR(100)",
            "kibana_case_version": "VARCHAR(50)",
            "observables": "JSON",
            "dfir_iris_case_id": "INTEGER",
        }
        with engine.begin() as conn:
            for col_name, col_type in new_columns.items():
                if col_name not in existing:
                    conn.execute(
                        text(f"ALTER TABLE alert_cases ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: alert_cases.%s", col_name)

    # AlertCase closure fields
    if insp.has_table("alert_cases"):
        existing = {col["name"] for col in insp.get_columns("alert_cases")}
        for col_name, col_type in {
            "closure_reason": "VARCHAR(50)",
            "closure_notes": "TEXT",
            "closed_by_id": "INTEGER",
            "closed_at": dt_type,
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE alert_cases ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: alert_cases.%s", col_name)

    # Migrations for alert_triage table
    if insp.has_table("alert_triage"):
        existing = {col["name"] for col in insp.get_columns("alert_triage")}
        if "analyst_notes" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN analyst_notes TEXT")
                )
                logger.info("Migrated: alert_triage.analyst_notes")
        if "observables" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN observables JSON")
                )
                logger.info("Migrated: alert_triage.observables")
        if "mitre_techniques" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN mitre_techniques JSON")
                )
                logger.info("Migrated: alert_triage.mitre_techniques")

    # Migrations for playbook_executions table
    if insp.has_table("playbook_executions"):
        existing = {col["name"] for col in insp.get_columns("playbook_executions")}
        if "case_id" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE playbook_executions ADD COLUMN case_id INTEGER REFERENCES alert_cases(id)")
                )
                logger.info("Migrated: playbook_executions.case_id")
        for col, sql in [
            ("outcome", "ALTER TABLE playbook_executions ADD COLUMN outcome VARCHAR(50)"),
            ("outcome_notes", "ALTER TABLE playbook_executions ADD COLUMN outcome_notes TEXT"),
            ("report_document_id", "ALTER TABLE playbook_executions ADD COLUMN report_document_id INTEGER REFERENCES documents(id)"),
        ]:
            if col not in existing:
                with engine.begin() as conn:
                    conn.execute(text(sql))
                    logger.info("Migrated: playbook_executions.%s", col)

    # Migrations for templates table
    if insp.has_table("templates"):
        existing = {col["name"] for col in insp.get_columns("templates")}
        if "document_type" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE templates ADD COLUMN document_type VARCHAR(50)"))
                logger.info("Migrated: templates.document_type")
        if "sections_json" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE templates ADD COLUMN sections_json TEXT"))
                logger.info("Migrated: templates.sections_json")

    # Migration for analyst_notes.folder_id
    if insp.has_table("analyst_notes"):
        existing = {col["name"] for col in insp.get_columns("analyst_notes")}
        if "folder_id" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE analyst_notes ADD COLUMN folder_id INTEGER REFERENCES note_folders(id)")
                )
                logger.info("Migrated: analyst_notes.folder_id")

    # Migrations for users table — account lockout columns + employment type
    if insp.has_table("users"):
        existing = {col["name"] for col in insp.get_columns("users")}
        for col_name, col_type in {
            "failed_login_attempts": "INTEGER DEFAULT 0",
            "locked_until": dt_type,
            "employment_type": "VARCHAR(20) DEFAULT 'cs'",
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: users.%s", col_name)

    # Migrations for forensic_cases table — lock + report + playbook columns
    if insp.has_table("forensic_cases"):
        existing = {col["name"] for col in insp.get_columns("forensic_cases")}
        for col_name, col_type in {
            "is_locked": "BOOLEAN DEFAULT FALSE NOT NULL",
            "locked_by_id": "INTEGER REFERENCES users(id)",
            "locked_at": dt_type,
            "report_document_id": "INTEGER REFERENCES documents(id)",
            "playbook_id": "INTEGER REFERENCES forensic_playbooks(id)",
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE forensic_cases ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: forensic_cases.%s", col_name)

    # Migrations for forensic_playbook_steps — structured fields
    if insp.has_table("forensic_playbook_steps"):
        existing = {col["name"] for col in insp.get_columns("forensic_playbook_steps")}
        if "fields_json" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE forensic_playbook_steps ADD COLUMN fields_json TEXT"))
                logger.info("Migrated: forensic_playbook_steps.fields_json")

    # Migrations for forensic_case_steps — structured fields
    if insp.has_table("forensic_case_steps"):
        existing = {col["name"] for col in insp.get_columns("forensic_case_steps")}
        for col_name in ("fields_json", "fields_data"):
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE forensic_case_steps ADD COLUMN {col_name} TEXT"))
                    logger.info("Migrated: forensic_case_steps.%s", col_name)

    # Migration for user_sessions.active_role_id (focus mode)
    if insp.has_table("user_sessions"):
        existing = {col["name"] for col in insp.get_columns("user_sessions")}
        if "active_role_id" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE user_sessions ADD COLUMN active_role_id INTEGER REFERENCES roles(id)")
                )
                logger.info("Migrated: user_sessions.active_role_id")

    # Migration for users.gitlab_username, elastic_uid (v0.9.13+)
    if insp.has_table("users"):
        existing = {col["name"] for col in insp.get_columns("users")}
        if "gitlab_username" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN gitlab_username VARCHAR(255)")
                )
                logger.info("Migrated: users.gitlab_username")
        if "elastic_uid" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN elastic_uid VARCHAR(255)")
                )
                logger.info("Migrated: users.elastic_uid")
        # v0.9.28: elastic_username and keycloak_sub for identity mapping
        if "elastic_username" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN elastic_username VARCHAR(255)")
                )
                logger.info("Migrated: users.elastic_username")
        if "keycloak_sub" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN keycloak_sub VARCHAR(255)")
                )
                logger.info("Migrated: users.keycloak_sub")

    # Variables: add options column
    if insp.has_table("variables"):
        existing = {col["name"] for col in insp.get_columns("variables")}
        if "options" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE variables ADD COLUMN options TEXT"))
                logger.info("Migrated: variables.options")

    # CyAB: add icon and tags columns to cyab_systems
    if insp.has_table("cyab_systems"):
        existing = {col["name"] for col in insp.get_columns("cyab_systems")}
        if "icon" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cyab_systems ADD COLUMN icon VARCHAR(32) DEFAULT 'monitor'"))
                conn.execute(text("ALTER TABLE cyab_systems ADD COLUMN tags TEXT"))
                logger.info("Migrated: cyab_systems.icon, cyab_systems.tags")

    # CyAB: migrate existing single-source systems to cyab_data_sources
    if insp.has_table("cyab_systems") and insp.has_table("cyab_data_sources"):
        with engine.begin() as conn:
            # Check if any data sources exist already
            result = conn.execute(text("SELECT COUNT(*) FROM cyab_data_sources"))
            ds_count = result.scalar()
            if ds_count == 0:
                # Migrate existing systems that have a name (data source) to the new table
                result = conn.execute(text(
                    "SELECT id, name, data_source_type, sal_tier, uptime_target, "
                    "max_latency, retention, p1_sla, field_mapping, field_mapping_score, "
                    "mandatory_score, readiness_score, risk_rating, sal_compliance, "
                    "field_notes, use_case_status, use_case_review_date, use_case_gaps, "
                    "use_case_remediation FROM cyab_systems WHERE name IS NOT NULL"
                ))
                rows = result.fetchall()
                for row in rows:
                    conn.execute(text(
                        "INSERT INTO cyab_data_sources "
                        "(system_id, name, data_source_type, sal_tier, uptime_target, "
                        "max_latency, retention, p1_sla, field_mapping, field_mapping_score, "
                        "mandatory_score, readiness_score, risk_rating, sal_compliance, "
                        "field_notes, use_case_status, use_case_review_date, use_case_gaps, "
                        "use_case_remediation, created_at, updated_at) "
                        "VALUES (:sid, :name, :dst, :sal, :uptime, :latency, :ret, :p1, "
                        ":fm, :fms, :ms, :rs, :rr, :sc, :fn, :ucs, :ucrd, :ucg, :ucr, "
                        "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ), {
                        "sid": row[0], "name": row[1], "dst": row[2], "sal": row[3],
                        "uptime": row[4], "latency": row[5], "ret": row[6], "p1": row[7],
                        "fm": row[8], "fms": row[9], "ms": row[10], "rs": row[11],
                        "rr": row[12], "sc": row[13], "fn": row[14], "ucs": row[15],
                        "ucrd": row[16], "ucg": row[17], "ucr": row[18],
                    })
                if rows:
                    logger.info("Migrated %d existing CyAB systems to data sources", len(rows))

    # CyAB data sources: add tide_system_id and data_namespace columns
    if insp.has_table("cyab_data_sources"):
        existing = {col["name"] for col in insp.get_columns("cyab_data_sources")}
        if "tide_system_id" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cyab_data_sources ADD COLUMN tide_system_id VARCHAR(64)"))
                logger.info("Migrated: cyab_data_sources.tide_system_id")
        if "data_namespace" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cyab_data_sources ADD COLUMN data_namespace VARCHAR(128)"))
                logger.info("Migrated: cyab_data_sources.data_namespace")

    # Performance indexes on hot tables (alert_cases, alert_triage).
    # create_all() creates indexes for new tables but NOT for tables that
    # already existed before the Index() was added to the model. This
    # migration adds them idempotently via CREATE INDEX IF NOT EXISTS.
    _perf_indexes = [
        ("ix_cases_status", "alert_cases", "status"),
        ("ix_cases_created_at", "alert_cases", "created_at"),
        ("ix_cases_closed_at", "alert_cases", "closed_at"),
        ("ix_cases_assigned_to", "alert_cases", "assigned_to_id"),
        ("ix_cases_severity", "alert_cases", "severity"),
        ("ix_cases_kibana_id", "alert_cases", "kibana_case_id"),
        ("ix_cases_status_created", "alert_cases", "status, created_at"),
        ("ix_alert_triage_status", "alert_triage", "status"),
        ("ix_alert_triage_case_id", "alert_triage", "case_id"),
        ("ix_alert_triage_assigned", "alert_triage", "assigned_to_id"),
        ("ix_alert_triage_status_created", "alert_triage", "status, created_at"),
    ]
    with engine.begin() as conn:
        for idx_name, table, columns in _perf_indexes:
            if insp.has_table(table):
                try:
                    conn.execute(text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({columns})"))
                except Exception:
                    pass  # Index might already exist under a different name

    # Quarterly review fields on service_accounts (PCI 7.2.4 / ISO A.5.16)
    if insp.has_table("service_accounts"):
        existing = {col["name"] for col in insp.get_columns("service_accounts")}
        sa_cols = {
            "last_reviewed_at": dt_type,
            "last_reviewed_by_id": "INTEGER",
            "review_cadence_days": "INTEGER",
            "review_notes": "TEXT",
        }
        with engine.begin() as conn:
            for col_name, col_type in sa_cols.items():
                if col_name not in existing:
                    conn.execute(
                        text(f"ALTER TABLE service_accounts ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: service_accounts.%s", col_name)
            # Backfill default cadence so existing rows aren't NULL
            conn.execute(
                text("UPDATE service_accounts SET review_cadence_days = 90 WHERE review_cadence_days IS NULL")
            )

    # AlertTriage source_system column + index (v0.9.66 — alert→system attribution)
    if insp.has_table("alert_triage"):
        existing = {col["name"] for col in insp.get_columns("alert_triage")}
        if "source_system" not in existing:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE alert_triage ADD COLUMN source_system VARCHAR(128)"
                ))
                logger.info("Migrated: alert_triage.source_system")
        existing_idx = {idx["name"] for idx in insp.get_indexes("alert_triage")}
        if "ix_alert_triage_source_system" not in existing_idx:
            with engine.begin() as conn:
                conn.execute(text(
                    "CREATE INDEX ix_alert_triage_source_system "
                    "ON alert_triage (source_system)"
                ))
                logger.info("Migrated: ix_alert_triage_source_system")

    # AI chat messages: index session_id for count+cleanup queries (v0.9.64)
    if insp.has_table("ai_chat_messages"):
        existing_idx = {idx["name"] for idx in insp.get_indexes("ai_chat_messages")}
        if "ix_ai_chat_messages_session_id" not in existing_idx:
            with engine.begin() as conn:
                conn.execute(text(
                    "CREATE INDEX ix_ai_chat_messages_session_id "
                    "ON ai_chat_messages (session_id)"
                ))
                logger.info("Migrated: ix_ai_chat_messages_session_id")

    # AI chat sessions: composite (user_id, updated_at) for list+order (v0.9.64)
    if insp.has_table("ai_chat_sessions"):
        existing_idx = {idx["name"] for idx in insp.get_indexes("ai_chat_sessions")}
        if "ix_ai_chat_sessions_user_updated" not in existing_idx:
            with engine.begin() as conn:
                conn.execute(text(
                    "CREATE INDEX ix_ai_chat_sessions_user_updated "
                    "ON ai_chat_sessions (user_id, updated_at)"
                ))
                logger.info("Migrated: ix_ai_chat_sessions_user_updated")

    # Notifications: composite (user_id, created_at) for list+order (v0.9.64)
    if insp.has_table("notifications"):
        existing_idx = {idx["name"] for idx in insp.get_indexes("notifications")}
        if "ix_notifications_user_created" not in existing_idx:
            with engine.begin() as conn:
                conn.execute(text(
                    "CREATE INDEX ix_notifications_user_created "
                    "ON notifications (user_id, created_at)"
                ))
                logger.info("Migrated: ix_notifications_user_created")

    # PIR linked_controls (multi-framework compliance evidence)
    if insp.has_table("post_incident_reviews"):
        existing = {col["name"] for col in insp.get_columns("post_incident_reviews")}
        if "linked_controls" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE post_incident_reviews ADD COLUMN linked_controls JSON")
                )
                logger.info("Migrated: post_incident_reviews.linked_controls")

    # Migrate old triage/case statuses to simplified open/acknowledged/closed
    _migrate_status_values(engine)


def _migrate_status_values(engine: Engine) -> None:
    """Map old 6-value triage statuses and 4-value case statuses to new 3-value system.

    investigating/escalated → acknowledged
    resolved/false_positive → closed
    in_progress → acknowledged (cases only)
    Idempotent — only updates rows that still have old values.
    """
    # SQLAlchemy stores enum names (uppercase) for Enum columns
    triage_map = {
        "INVESTIGATING": "ACKNOWLEDGED",
        "ESCALATED": "ACKNOWLEDGED",
        "RESOLVED": "CLOSED",
        "FALSE_POSITIVE": "CLOSED",
        # Also handle lowercase in case values were stored that way
        "investigating": "ACKNOWLEDGED",
        "escalated": "ACKNOWLEDGED",
        "resolved": "CLOSED",
        "false_positive": "CLOSED",
    }
    case_map = {
        "IN_PROGRESS": "ACKNOWLEDGED",
        "RESOLVED": "CLOSED",
        "in_progress": "ACKNOWLEDGED",
        "resolved": "CLOSED",
    }

    with engine.begin() as conn:
        for old, new in triage_map.items():
            result = conn.execute(
                text("UPDATE alert_triage SET status = :new WHERE status = :old"),
                {"new": new, "old": old},
            )
            if result.rowcount:
                logger.info("Migrated %d alert_triage rows: %s → %s", result.rowcount, old, new)

        for old, new in case_map.items():
            result = conn.execute(
                text("UPDATE alert_cases SET status = :new WHERE status = :old"),
                {"new": new, "old": old},
            )
            if result.rowcount:
                logger.info("Migrated %d alert_cases rows: %s → %s", result.rowcount, old, new)


def init_db(db_path: Optional[Path] = None) -> Engine:
    """Initialize the database, creating all tables."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None

    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    _run_migrations(engine)
    return engine


def reset_engine() -> None:
    """Reset the engine and session factory (for testing)."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
