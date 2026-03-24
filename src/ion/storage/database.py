"""Database connection and initialization.

Supports SQLite (default) and PostgreSQL.
Set ION_DATABASE_URL to a PostgreSQL connection string to use PostgreSQL:
    ION_DATABASE_URL=postgresql://user:pass@host:5432/ion

When ION_DATABASE_URL is not set, falls back to SQLite at the configured db_path.
PostgreSQL requires the 'postgres' extra: pip install ion[postgres]
"""

import logging
import os
from pathlib import Path
from typing import Generator, Optional
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


def _is_postgres(engine: Engine) -> bool:
    """Check if the engine is connected to PostgreSQL."""
    return engine.dialect.name == "postgresql"


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
                pool_size=20,
                max_overflow=30,
                pool_timeout=30,
                pool_pre_ping=True,
                pool_recycle=1800,
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

    # Migration for chat_messages.reply_to_id (v0.9.16+)
    if insp.has_table("chat_messages"):
        existing = {col["name"] for col in insp.get_columns("chat_messages")}
        if "reply_to_id" not in existing:
            with engine.begin() as conn:
                conn.execute(
                    text("ALTER TABLE chat_messages ADD COLUMN reply_to_id INTEGER REFERENCES chat_messages(id)")
                )
                logger.info("Migrated: chat_messages.reply_to_id")

    # Migration for chat_rooms.is_system (system-managed group rooms)
    if insp.has_table("chat_rooms"):
        existing = {col["name"] for col in insp.get_columns("chat_rooms")}
        if "is_system" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE chat_rooms ADD COLUMN is_system BOOLEAN DEFAULT FALSE NOT NULL"))
                logger.info("Migrated: chat_rooms.is_system")

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
