"""Database connection and initialization."""

import logging
from pathlib import Path
from typing import Generator, Optional
from sqlalchemy import create_engine, Engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from ixion.models.base import Base
from ixion.core.config import get_config

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
        }
        with engine.begin() as conn:
            for col_name, col_type in new_columns.items():
                if col_name not in existing:
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
