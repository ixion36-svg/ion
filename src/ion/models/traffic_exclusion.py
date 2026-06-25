"""Traffic-analytics exclusion list.

A small admin/lead-managed list of IPs or CIDR ranges to filter OUT of the
Arkime Traffic Analytics views (top talkers, countries, per-node, overview).
Applied server-side as an Arkime ``ip != <cidr>`` expression so excluded
ranges never enter the aggregation — useful for muting backup networks,
monitoring scanners, or known-noisy hosts that drown out flows of interest.

Shared (not per-user): one analyst's exclusion shapes everyone's view, so
mutations are gated at the lead (``security:read``) level and audit-logged.
"""

from typing import Optional

from sqlalchemy import Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin


class TrafficExclusion(Base, TimestampMixin):
    """One IP/CIDR excluded from the traffic-analytics aggregations."""

    __tablename__ = "traffic_exclusions"
    __table_args__ = (
        UniqueConstraint("cidr", name="uq_traffic_exclusion_cidr"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # An IP (10.0.0.5) or CIDR (10.0.0.0/8). Validated as an ip_network before insert.
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "cidr": self.cidr,
            "note": self.note,
            "created_by_id": self.created_by_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
