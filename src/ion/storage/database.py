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

from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

# Import all models to ensure they are registered with Base.metadata
# This is required for create_all() to create all tables
import ion.models  # noqa: F401
from ion.core.config import get_config
from ion.models.base import Base

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
LOCK_NETMAP_BG_SYNC         = 1014
LOCK_SCHEDULER_BG           = 1015
LOCK_INVESTIGATION_BG       = 1016
LOCK_CASE_GROUPER_BG        = 1017
LOCK_TICKER_BG              = 1018
LOCK_CASE_EMBEDDING_BG      = 1019
LOCK_KB_EMBEDDING_BG        = 1020
LOCK_SEED_CYAB_SUBPROFILES  = 1021  # v0.12.0 — Onboarding Studio catalogue seeder
LOCK_BOB_EVAL_BG            = 1022  # v0.21.0 — Bob Prompt Eval Harness singleton guard
LOCK_SESSION_CLEANUP_BG     = 1023  # v0.31.13 — data-min P13 G1: periodic expired-session cleanup
LOCK_DATA_RETENTION_BG      = 1024  # v0.31.14 — data-min P13 G2+G3: audit_logs + security_events retention


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
      so we don't end up with 4x duplicate background tasks. The lock
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
        else:
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
                # v0.9.82 safety nets:
                # - statement_timeout: Postgres server-side kill any query
                #   that runs longer than 10s. Converts "ION frozen" into
                #   a clean 500 with a clear error in the log.
                # - application_name: shows up in pg_stat_activity so
                #   "who is holding this lock" is obvious during incidents.
                # - options is the libpq way to pass session GUCs; psycopg2
                #   honours it at connection time.
                connect_args={
                    "options": "-c statement_timeout=10000 -c application_name=ion",
                    "connect_timeout": 5,
                },
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

    # v0.10.4: enable pgvector for case-similarity embeddings. Idempotent.
    # Runs BEFORE the CREATE TABLE sweep so new tables can use VECTOR columns.
    if _is_postgres(engine):
        try:
            with engine.begin() as conn:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
                logger.info("Migrated: CREATE EXTENSION vector (pgvector)")
        except Exception as exc:
            logger.warning(
                "Failed to enable pgvector extension (is the image "
                "pgvector/pgvector:pg16?): %s", exc,
            )
        # Create the HNSW index on case_embeddings — needs the table to
        # exist, so we defer to after create_all (see _finalize_migrations).

    # v0.9.76: drop the notifications table — feature removed. Safe & idempotent.
    if insp.has_table("notifications"):
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE notifications"))
            logger.info("Migrated: dropped notifications table (v0.9.76)")

    # v0.27.0: drop the threat_hunts table — feature removed. The
    # half-built /threat-hunting page never integrated with /discover
    # (where hunt queries actually run) or /cases (where findings get
    # recorded). Workflow now lives in those existing surfaces.
    if insp.has_table("threat_hunts"):
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE threat_hunts"))
            logger.info("Migrated: dropped threat_hunts table (v0.27.0)")

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
        # v0.10.3: Bob's suggested verdict hint on triage rows
        if "suggested_verdict" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN suggested_verdict VARCHAR(50)")
                )
                logger.info("Migrated: alert_triage.suggested_verdict")
        if "suggested_verdict_confidence" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN suggested_verdict_confidence VARCHAR(20)")
                )
                logger.info("Migrated: alert_triage.suggested_verdict_confidence")
        # v0.19.3: rule_name denormalized for case detail rendering
        if "rule_name" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_triage ADD COLUMN rule_name VARCHAR(500)")
                )
                logger.info("Migrated: alert_triage.rule_name")

    # v0.10.3: users.is_service_account for Bob + other service users
    if insp.has_table("users"):
        existing = {col["name"] for col in insp.get_columns("users")}
        if "is_service_account" not in existing:
            with engine.begin() as conn:
                # NOT NULL with default 0 — existing rows all become human users
                conn.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN is_service_account BOOLEAN NOT NULL DEFAULT 0"
                        if not _is_postgres(engine)
                        else "ALTER TABLE users ADD COLUMN is_service_account BOOLEAN NOT NULL DEFAULT FALSE"
                    )
                )
                logger.info("Migrated: users.is_service_account")

    # v0.10.3: MITRE columns on alert_prompt_templates
    if insp.has_table("alert_prompt_templates"):
        existing = {
            col["name"] for col in insp.get_columns("alert_prompt_templates")
        }
        for col_name in ("mitre_techniques_json", "mitre_tactics_json"):
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(
                            f"ALTER TABLE alert_prompt_templates ADD COLUMN {col_name} TEXT"
                        )
                    )
                    logger.info(
                        "Migrated: alert_prompt_templates.%s", col_name
                    )

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

    # v0.20.1: ForensicCase Workbench tables (pins + tamper-evident ledger).
    # Base.metadata.create_all() (called in init_db) creates these tables on
    # fresh databases with correct per-dialect DDL. The blocks below add
    # idempotent indexes for upgrade scenarios where the tables are newly
    # introduced on an existing deployment (create_all skips pre-existing
    # tables but does NOT add indexes to them).
    if insp.has_table("forensic_case_pins"):
        existing_idx = {idx["name"] for idx in insp.get_indexes("forensic_case_pins")}
        with engine.begin() as conn:
            if "ix_forensic_case_pins_case" not in existing_idx:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_forensic_case_pins_case "
                    "ON forensic_case_pins (forensic_case_id)"
                ))
                logger.info("Migrated: ix_forensic_case_pins_case")
            if "ix_forensic_case_pins_status" not in existing_idx:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_forensic_case_pins_status "
                    "ON forensic_case_pins (forensic_case_id, finding_status)"
                ))
                logger.info("Migrated: ix_forensic_case_pins_status")

    if insp.has_table("forensic_case_ledger"):
        existing_idx = {idx["name"] for idx in insp.get_indexes("forensic_case_ledger")}
        with engine.begin() as conn:
            if "ix_forensic_case_ledger_case" not in existing_idx:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_forensic_case_ledger_case "
                    "ON forensic_case_ledger (forensic_case_id)"
                ))
                logger.info("Migrated: ix_forensic_case_ledger_case")
            if "ix_forensic_case_ledger_timestamp" not in existing_idx:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_forensic_case_ledger_timestamp "
                    "ON forensic_case_ledger (timestamp)"
                ))
                logger.info("Migrated: ix_forensic_case_ledger_timestamp")

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
        # v0.12.0: Onboarding Studio sub-profile tag.
        if "subprofile_id" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cyab_data_sources ADD COLUMN subprofile_id VARCHAR(64)"))
                logger.info("Migrated: cyab_data_sources.subprofile_id")

    # v0.12.0: Onboarding Pack containment_authority field on cyab_systems.
    if insp.has_table("cyab_systems"):
        existing = {col["name"] for col in insp.get_columns("cyab_systems")}
        if "containment_authority" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE cyab_systems ADD COLUMN containment_authority TEXT"))
                logger.info("Migrated: cyab_systems.containment_authority")

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

    # v0.10.19: Observable gains TheHive-style IOC handling — TLP/PAP
    # classification, is_ioc flag, and ignore_similarity escape hatch for
    # high-noise values (8.8.8.8, internal DNS resolvers). All defaults
    # match the model so existing rows stay valid after migration.
    if insp.has_table("observables"):
        existing = {col["name"] for col in insp.get_columns("observables")}
        new_cols = {
            "tlp": "VARCHAR(8) NOT NULL DEFAULT 'amber'",
            "pap": "VARCHAR(8) NOT NULL DEFAULT 'amber'",
            "is_ioc": "BOOLEAN NOT NULL DEFAULT FALSE",
            "ignore_similarity": "BOOLEAN NOT NULL DEFAULT FALSE",
        }
        for col_name, col_def in new_cols.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE observables ADD COLUMN {col_name} {col_def}")
                    )
                    logger.info("Migrated: observables.%s", col_name)

    # v0.10.17: CyAB system gains onboarding metadata (contacts + business
    # context). All nullable; pre-v0.10.17 rows stay valid. Idempotent —
    # checks for column existence before each ALTER.
    if insp.has_table("cyab_systems"):
        existing = {col["name"] for col in insp.get_columns("cyab_systems")}
        new_cols = {
            "business_unit": "VARCHAR(255)",
            "data_classification": "VARCHAR(64)",
            "dept_lead_email": "VARCHAR(255)",
            "dept_lead_phone": "VARCHAR(64)",
            "dept_deputy_name": "VARCHAR(255)",
            "dept_deputy_email": "VARCHAR(255)",
            "soc_lead_email": "VARCHAR(255)",
            "soc_analyst_owner": "VARCHAR(255)",
            "stakeholder_distribution": "TEXT",
            "ir_runbook_url": "VARCHAR(2048)",
        }
        for col_name, col_type in new_cols.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE cyab_systems ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: cyab_systems.%s", col_name)

    # v0.10.11: Investigation gains prompt snapshot + raw response + key
    # observations so AIFeedback rows are debuggable (see what Bob saw, not
    # just whether he was right). Idempotent — checks for column existence
    # before attempting the ALTER. Nullable — pre-v0.10.11 rows stay NULL.
    if insp.has_table("investigations"):
        existing = {col["name"] for col in insp.get_columns("investigations")}
        new_cols = {
            "prompt_snapshot": "TEXT",
            "raw_response": "TEXT",
            "key_observations_json": "TEXT",
        }
        for col_name, col_type in new_cols.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE investigations ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: investigations.%s", col_name)

    # v0.21.0: lab_fixtures + lab_session_fixtures for replayable labs.
    # lab_fixtures holds the template rows (what to seed for a lesson).
    # lab_session_fixtures tracks which rows were materialised per-enrolment
    # so teardown only removes the session's own data.
    if not insp.has_table("lab_fixtures"):
        json_type = "JSONB" if _is_postgres(engine) else "JSON"
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE lab_fixtures (
                    id INTEGER PRIMARY KEY {'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'},
                    lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
                    fixture_kind VARCHAR(32) NOT NULL,
                    payload {json_type} NOT NULL,
                    target_table TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_lab_fixtures_lesson ON lab_fixtures (lesson_id)"
            ))
            logger.info("Migrated: CREATE TABLE lab_fixtures")

    if not insp.has_table("lab_session_fixtures"):
        # v0.23.0: session_id ships in the initial CREATE on fresh deploys.
        # The ALTER block below remains the upgrade path for v0.21/v0.22
        # databases that already have the table without the column.
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE lab_session_fixtures (
                    id INTEGER PRIMARY KEY {'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'},
                    enrollment_id INTEGER NOT NULL REFERENCES course_enrolments(id) ON DELETE CASCADE,
                    lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
                    fixture_id INTEGER NOT NULL REFERENCES lab_fixtures(id) ON DELETE CASCADE,
                    materialised_row_id BIGINT NOT NULL,
                    materialised_table TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    torn_down_at TIMESTAMP,
                    session_id INTEGER
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_lab_sess_fix_enroll_lesson "
                "ON lab_session_fixtures (enrollment_id, lesson_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_lab_sess_fix_torn_down "
                "ON lab_session_fixtures (torn_down_at)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_lab_sess_fix_session "
                "ON lab_session_fixtures (session_id)"
            ))
            logger.info("Migrated: CREATE TABLE lab_session_fixtures")

    # v0.21.0: Bob confidence scoring + circuit breakers.
    # Adds numeric confidence columns and circuit-breaker fields.
    if insp.has_table("investigations"):
        existing = {col["name"] for col in insp.get_columns("investigations")}
        for col_name, col_type in {
            "confidence_int": "INTEGER",
            "reasoning_text": "TEXT",
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE investigations ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: investigations.%s", col_name)

    if insp.has_table("alert_triage"):
        existing = {col["name"] for col in insp.get_columns("alert_triage")}
        for col_name, col_type in {
            "suggested_verdict_confidence_int": "INTEGER",
            "bob_escalation_badge": "VARCHAR(30)",
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE alert_triage ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: alert_triage.%s", col_name)

    if insp.has_table("ai_feedback"):
        existing = {col["name"] for col in insp.get_columns("ai_feedback")}
        if "bob_confidence_int" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE ai_feedback ADD COLUMN bob_confidence_int INTEGER")
                )
                logger.info("Migrated: ai_feedback.bob_confidence_int")
        if "auto_escalated" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "ALTER TABLE ai_feedback ADD COLUMN auto_escalated BOOLEAN NOT NULL DEFAULT FALSE"
                        if _is_postgres(engine)
                        else "ALTER TABLE ai_feedback ADD COLUMN auto_escalated BOOLEAN NOT NULL DEFAULT 0"
                    )
                )
                logger.info("Migrated: ai_feedback.auto_escalated")

    if insp.has_table("alert_prompt_templates"):
        existing = {col["name"] for col in insp.get_columns("alert_prompt_templates")}
        if "confidence_threshold_override" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE alert_prompt_templates ADD COLUMN confidence_threshold_override INTEGER")
                )
                logger.info("Migrated: alert_prompt_templates.confidence_threshold_override")

    # v0.21.0: Bob Prompt Evaluation Harness — eval run + sample tables.
    # Base.metadata.create_all creates these on fresh deployments. The blocks
    # below add them idempotently on upgrades and ensure indexes exist.
    if not insp.has_table("bob_eval_runs"):
        ts_type = "TIMESTAMPTZ" if _is_postgres(engine) else "DATETIME"
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE bob_eval_runs (
                    id INTEGER PRIMARY KEY {'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'},
                    template_id INTEGER REFERENCES alert_prompt_templates(id) ON DELETE SET NULL,
                    template_name VARCHAR(255),
                    prompt_body_hash VARCHAR(64) NOT NULL,
                    model_name VARCHAR(128) NOT NULL,
                    model_version VARCHAR(128),
                    sample_size INTEGER NOT NULL,
                    started_at {ts_type},
                    completed_at {ts_type},
                    status VARCHAR(20) NOT NULL DEFAULT 'running',
                    error_message TEXT,
                    triggered_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    precision_score NUMERIC(5,4),
                    recall_score NUMERIC(5,4),
                    f1_score NUMERIC(5,4),
                    tp_count INTEGER NOT NULL DEFAULT 0,
                    fp_count INTEGER NOT NULL DEFAULT 0,
                    fn_count INTEGER NOT NULL DEFAULT 0,
                    tn_count INTEGER NOT NULL DEFAULT 0,
                    abstention_count INTEGER NOT NULL DEFAULT 0,
                    hallucination_proxy NUMERIC(5,4),
                    created_at {ts_type} DEFAULT CURRENT_TIMESTAMP,
                    updated_at {ts_type} DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_bob_eval_runs_template_id ON bob_eval_runs (template_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_bob_eval_runs_started_at ON bob_eval_runs (started_at)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_bob_eval_runs_status ON bob_eval_runs (status)"
            ))
            logger.info("Migrated: CREATE TABLE bob_eval_runs")

    if not insp.has_table("bob_eval_run_samples"):
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE bob_eval_run_samples (
                    id INTEGER PRIMARY KEY {'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'},
                    eval_run_id INTEGER NOT NULL REFERENCES bob_eval_runs(id) ON DELETE CASCADE,
                    ai_feedback_id INTEGER NOT NULL REFERENCES ai_feedback(id) ON DELETE CASCADE,
                    bob_verdict VARCHAR(50),
                    human_verdict VARCHAR(50) NOT NULL,
                    agreement BOOLEAN,
                    confidence_int INTEGER,
                    reasoning_text TEXT,
                    UNIQUE (eval_run_id, ai_feedback_id)
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_bob_eval_run_samples_run_id "
                "ON bob_eval_run_samples (eval_run_id)"
            ))
            logger.info("Migrated: CREATE TABLE bob_eval_run_samples")

    # v0.21.0 Fix 2: add skipped_count to bob_eval_runs for missing-alert tracking.
    if insp.has_table("bob_eval_runs"):
        existing = {col["name"] for col in insp.get_columns("bob_eval_runs")}
        if "skipped_count" not in existing:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE bob_eval_runs ADD COLUMN skipped_count INTEGER NOT NULL DEFAULT 0"
                ))
                logger.info("Migrated: bob_eval_runs.skipped_count")


    # v0.22.0 Feature B: alert_case_annotations -- timestamped timeline annotations.
    # Base.metadata.create_all() handles fresh deploys; this block upgrades
    # existing databases idempotently.
    if not insp.has_table('alert_case_annotations'):
        dt = 'TIMESTAMP' if _is_postgres(engine) else 'DATETIME'
        pk_def = 'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'
        with engine.begin() as conn:
            conn.execute(text(
                f'CREATE TABLE alert_case_annotations ('
                f'    id INTEGER PRIMARY KEY {pk_def},'
                f'    alert_case_id INTEGER NOT NULL'
                f'        REFERENCES alert_cases(id) ON DELETE CASCADE,'
                f'    created_by_id INTEGER NOT NULL REFERENCES users(id),'
                f'    timeline_ts {dt} NOT NULL,'
                f'    body TEXT NOT NULL CHECK (length(body) > 0),'
                f'    created_at {dt} NOT NULL DEFAULT CURRENT_TIMESTAMP,'
                f'    updated_at {dt} NOT NULL DEFAULT CURRENT_TIMESTAMP,'
                f'    deleted_at {dt}'
                f')'
            ))
            conn.execute(text(
                'CREATE INDEX ix_aca_case ON alert_case_annotations (alert_case_id)'
            ))
            conn.execute(text(
                'CREATE INDEX ix_aca_created_by ON alert_case_annotations (created_by_id)'
            ))
            conn.execute(text(
                'CREATE INDEX ix_aca_timeline_ts '
                'ON alert_case_annotations (alert_case_id, timeline_ts)'
            ))
            logger.info('Migrated: CREATE TABLE alert_case_annotations')

    # v0.22.0 Feature B: forensic_case_annotations -- mirror for ForensicCase.
    if not insp.has_table('forensic_case_annotations'):
        dt = 'TIMESTAMP' if _is_postgres(engine) else 'DATETIME'
        pk_def = 'GENERATED ALWAYS AS IDENTITY' if _is_postgres(engine) else 'AUTOINCREMENT'
        with engine.begin() as conn:
            conn.execute(text(
                f'CREATE TABLE forensic_case_annotations ('
                f'    id INTEGER PRIMARY KEY {pk_def},'
                f'    forensic_case_id INTEGER NOT NULL'
                f'        REFERENCES forensic_cases(id) ON DELETE CASCADE,'
                f'    created_by_id INTEGER NOT NULL REFERENCES users(id),'
                f'    timeline_ts {dt} NOT NULL,'
                f'    body TEXT NOT NULL CHECK (length(body) > 0),'
                f'    created_at {dt} NOT NULL DEFAULT CURRENT_TIMESTAMP,'
                f'    updated_at {dt} NOT NULL DEFAULT CURRENT_TIMESTAMP,'
                f'    deleted_at {dt}'
                f')'
            ))
            conn.execute(text(
                'CREATE INDEX ix_fca_case ON forensic_case_annotations (forensic_case_id)'
            ))
            conn.execute(text(
                'CREATE INDEX ix_fca_created_by ON forensic_case_annotations (created_by_id)'
            ))
            conn.execute(text(
                'CREATE INDEX ix_fca_timeline_ts '
                'ON forensic_case_annotations (forensic_case_id, timeline_ts)'
            ))
            logger.info('Migrated: CREATE TABLE forensic_case_annotations')

    # v0.23.0: adaptive lab grading — promote the implicit lab session state
    # (via lab_session_fixtures.torn_down_at) to a first-class lab_sessions
    # parent row carrying score + attempt metadata, add per-lesson rubric
    # table, and a criterion-result audit-trail table.
    if not insp.has_table("lab_sessions"):
        json_type = "JSONB" if _is_postgres(engine) else "JSON"
        pk_def = "GENERATED ALWAYS AS IDENTITY" if _is_postgres(engine) else "AUTOINCREMENT"
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE lab_sessions (
                    id INTEGER PRIMARY KEY {pk_def},
                    enrollment_id INTEGER NOT NULL
                        REFERENCES course_enrolments(id) ON DELETE CASCADE,
                    lesson_id INTEGER NOT NULL
                        REFERENCES lessons(id) ON DELETE CASCADE,
                    attempt_number INTEGER NOT NULL DEFAULT 1,
                    started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    score INTEGER,
                    points_earned INTEGER NOT NULL DEFAULT 0,
                    points_max INTEGER NOT NULL DEFAULT 0,
                    CONSTRAINT uq_lab_session_attempt
                        UNIQUE (enrollment_id, lesson_id, attempt_number)
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_lab_sessions_enroll_lesson "
                "ON lab_sessions (enrollment_id, lesson_id)"
            ))
            conn.execute(text(
                "CREATE INDEX ix_lab_sessions_completed "
                "ON lab_sessions (completed_at)"
            ))
            logger.info("Migrated: CREATE TABLE lab_sessions")

    if not insp.has_table("lab_rubrics"):
        json_type = "JSONB" if _is_postgres(engine) else "JSON"
        pk_def = "GENERATED ALWAYS AS IDENTITY" if _is_postgres(engine) else "AUTOINCREMENT"
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE lab_rubrics (
                    id INTEGER PRIMARY KEY {pk_def},
                    lesson_id INTEGER NOT NULL
                        REFERENCES lessons(id) ON DELETE CASCADE,
                    criterion_kind VARCHAR(48) NOT NULL,
                    criterion_config {json_type} NOT NULL,
                    points INTEGER NOT NULL DEFAULT 10,
                    sort_order INTEGER NOT NULL DEFAULT 0,
                    description TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_lab_rubrics_lesson ON lab_rubrics (lesson_id)"
            ))
            logger.info("Migrated: CREATE TABLE lab_rubrics")

    if not insp.has_table("lab_criterion_results"):
        pk_def = "GENERATED ALWAYS AS IDENTITY" if _is_postgres(engine) else "AUTOINCREMENT"
        with engine.begin() as conn:
            conn.execute(text(f"""
                CREATE TABLE lab_criterion_results (
                    id INTEGER PRIMARY KEY {pk_def},
                    session_id INTEGER NOT NULL
                        REFERENCES lab_sessions(id) ON DELETE CASCADE,
                    rubric_id INTEGER NOT NULL
                        REFERENCES lab_rubrics(id) ON DELETE CASCADE,
                    points_earned INTEGER NOT NULL DEFAULT 0,
                    points_max INTEGER NOT NULL,
                    matched BOOLEAN NOT NULL DEFAULT FALSE,
                    matched_audit_log_id INTEGER,
                    evaluated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT,
                    CONSTRAINT uq_criterion_result UNIQUE (session_id, rubric_id)
                )
            """))
            conn.execute(text(
                "CREATE INDEX ix_lab_criterion_results_session "
                "ON lab_criterion_results (session_id)"
            ))
            logger.info("Migrated: CREATE TABLE lab_criterion_results")

    # v0.23.1: system_runtime_flags — small key/value bag for runtime
    # toggles that must be visible across all workers (e.g. the leader
    # worker that owns the investigation sweep loop AND the request-
    # handling worker that toggles a pause flag from the UI). In-process
    # state on a singleton would not satisfy the multi-worker uvicorn
    # deployment.
    if not insp.has_table("system_runtime_flags"):
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE system_runtime_flags (
                    key VARCHAR(64) PRIMARY KEY,
                    value VARCHAR(255) NOT NULL,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_by_id INTEGER REFERENCES users(id)
                )
            """))
            logger.info("Migrated: CREATE TABLE system_runtime_flags")

    # v0.23.0: link existing lab_session_fixtures rows to their parent session.
    # NULL is permitted for legacy rows persisted before this version.
    if insp.has_table("lab_session_fixtures"):
        existing = {col["name"] for col in insp.get_columns("lab_session_fixtures")}
        if "session_id" not in existing:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE lab_session_fixtures "
                    "ADD COLUMN session_id INTEGER REFERENCES lab_sessions(id) "
                    "ON DELETE SET NULL"
                ))
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_lab_sess_fix_session "
                    "ON lab_session_fixtures (session_id)"
                ))
                logger.info("Migrated: lab_session_fixtures.session_id")

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

    # v0.10.8 FIX: enable pgvector BEFORE create_all. Several models carry
    # VECTOR columns (case_embeddings, kb_document_embeddings) that cannot
    # be created on a fresh database unless the `vector` type exists.
    # _run_migrations also runs CREATE EXTENSION, but that happens AFTER
    # create_all — too late for the initial deploy. Idempotent here, so
    # no harm in running twice on subsequent boots.
    if _is_postgres(engine):
        try:
            with engine.begin() as conn:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        except Exception as exc:
            logger.warning(
                "Early pgvector extension check failed "
                "(is the image pgvector/pgvector:pg16?): %s", exc,
            )

    Base.metadata.create_all(engine)
    _run_migrations(engine)
    # v0.10.4: HNSW index on case_embeddings.embedding needs the table to
    # exist first — runs after create_all and the column migrations.
    try:
        from ion.models.case_embedding import ensure_hnsw_index
        ensure_hnsw_index(engine)
    except Exception as exc:  # pragma: no cover
        logger.debug("HNSW index creation skipped: %s", exc)
    # v0.10.6: HNSW index on kb_document_embeddings.embedding.
    try:
        from ion.models.kb_document_embedding import ensure_kb_hnsw_index
        ensure_kb_hnsw_index(engine)
    except Exception as exc:  # pragma: no cover
        logger.debug("KB HNSW index creation skipped: %s", exc)
    return engine


def reset_engine() -> None:
    """Reset the engine and session factory (for testing)."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
