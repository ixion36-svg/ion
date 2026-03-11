"""Database connection and initialization."""

import logging
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


def get_engine(db_path: Optional[Path] = None) -> Engine:
    """Get or create the database engine."""
    global _engine
    if _engine is None:
        if db_path is None:
            db_path = get_config().db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{db_path}", echo=False)
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
            "closed_at": "DATETIME",
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
            "locked_until": "DATETIME",
            "employment_type": "VARCHAR(20) DEFAULT 'cs'",
        }.items():
            if col_name not in existing:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                    )
                    logger.info("Migrated: users.%s", col_name)


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
