"""CISA Known Exploited Vulnerabilities catalog — shipped as a snapshot.

ION deploys into air-gapped and siloed environments, so there is no live feed
to poll. The catalog is bundled with the image at build time
(``ion/data/kev_catalog.json``), seeded into this table on startup, and can be
refreshed in place by an operator uploading a newer file. Nothing here ever
reaches out to cisa.gov at runtime.

The table stores the catalog VERSION on every row. That is what makes the
startup seed idempotent and what lets an operator import be told apart from the
bundled snapshot after the fact — "where did this row come from, and how old is
it" is the first question anyone asks of vulnerability data they did not fetch
themselves.
"""

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Boolean, Date, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base


class KevEntry(Base):
    """One CVE from the KEV catalog."""

    __tablename__ = "kev_entries"
    __table_args__ = (
        Index("ix_kev_entries_date_added", "date_added"),
        Index("ix_kev_entries_vendor", "vendor_project"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Unique: the catalog is keyed on CVE, and a re-import must update rather
    # than duplicate.
    cve_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True, index=True)

    vendor_project: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    vulnerability_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    short_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    required_action: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    date_added: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
    due_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    # CISA publishes this as the string "Known" / "Unknown", not a boolean.
    # Stored as a bool with the raw value kept alongside, because "Unknown"
    # means "not established", NOT "no" — collapsing it to False would assert
    # something the catalog does not.
    known_ransomware: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    known_ransomware_raw: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    cwes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON array as text

    # Provenance — which catalog release this row came from, and whether it
    # arrived in the image or from an operator upload.
    catalog_version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="bundled")
    synced_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "notes": self.notes,
            "date_added": self.date_added.isoformat() if self.date_added else None,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "known_ransomware": self.known_ransomware,
            "known_ransomware_raw": self.known_ransomware_raw,
            "catalog_version": self.catalog_version,
            "source": self.source,
        }

    def __repr__(self) -> str:
        return f"<KevEntry({self.cve_id}, {self.vendor_project} {self.product})>"
