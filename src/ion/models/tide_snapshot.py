"""TIDE snapshot cache model.

Stores pre-fetched TIDE data as JSON blobs so the Detection Engineering
page can load instantly from PostgreSQL instead of hitting TIDE's
single-threaded DuckDB on every page view.

A background worker refreshes these snapshots every N minutes. The
snapshots are keyed by ``data_key`` (e.g. ``posture``, ``gaps``,
``coverage``, ``use_cases``, ``disabled_critical``, ``systems``).
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


class TideSnapshot(Base):
    """A cached snapshot of one TIDE dataset."""

    __tablename__ = "tide_snapshots"
    __table_args__ = (
        Index("ix_tide_snapshot_key", "data_key", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    data_key: Mapped[str] = mapped_column(String(60), nullable=False, unique=True)
    # JSON blob — the full response dict serialised.
    data_json: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )
    # How long the fetch took (ms) — useful for monitoring.
    fetch_duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # If the fetch failed, store the error label here.
    error: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
