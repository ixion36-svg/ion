"""Tenants — one client estate, with its own Elasticsearch and Kibana.

ION has always talked to exactly one Elastic: ``elasticsearch_alert_index`` and
``kibana_space_id`` are process-global config and the ES client is a module
global. A tenant moves that connection into a row, so one ION instance can serve
several client estates, each with its own cluster, credentials and index.

**Arkime and OpenCTI are deliberately NOT here.** They stay shared across all
tenants — PCAP retrieval and threat intelligence are estate-wide services, not
per-client ones. Adding connection columns for them would imply an isolation
this design does not provide.

Alerts themselves live in Elasticsearch, so tenant isolation for them is a
matter of which cluster ION queries. ION's own rows — triage, cases, notes —
carry a ``tenant_id`` instead; see the Phase 2 columns.

``users.tenant_id`` is nullable and NULL means platform-global: a support or
oversight account that can act across tenants. Every other user is bound to one.

Credentials here are written by an admin and read by the ES client factory. They
are stored the same way the existing single-tenant config stores them, which is
in the clear — a tenant row is not a new secret-handling posture, it is the
existing one made per-client. Treat the table as sensitive at rest accordingly.
"""

from typing import Optional

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ion.models.base import Base, TimestampMixin

# Slug is the stable external identifier: it appears in audit records, export
# filenames and the tenant switcher. Renaming the display name is safe; changing
# the slug re-labels history, so it is validated once and then left alone.
TENANT_SLUG_MAX = 64
TENANT_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$"


class Tenant(Base, TimestampMixin):
    """One client estate and the Elastic/Kibana it is served from."""

    __tablename__ = "tenants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(TENANT_SLUG_MAX), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # A disabled tenant keeps its data and stops being selectable or queried.
    # Deleting one would orphan every row that references it, so disable is the
    # supported operation and there is no delete path.
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )

    # Exactly one tenant is the default: the estate ION serves when multi-tenancy
    # is off, and the tenant every pre-existing row is backfilled to.
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    # --- Elasticsearch (per tenant: separate cluster per client) ---
    es_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    es_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    es_password: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    es_api_key: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    es_alert_index: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    es_verify_ssl: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="0"
    )

    # --- Kibana (cases + spaces) ---
    kibana_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    kibana_username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    kibana_password: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    kibana_space_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Tenant {self.slug!r} active={self.is_active}>"

    def es_config(self) -> dict:
        """Connection dict for the ES client factory.

        Only keys with a value are returned, so a tenant that leaves a field
        blank inherits the process-wide setting rather than overriding it with
        an empty string — which is what a half-filled tenant row would otherwise
        do to a working connection.
        """
        candidate = {
            "url": self.es_url,
            "username": self.es_username,
            "password": self.es_password,
            "api_key": self.es_api_key,
            "alert_index": self.es_alert_index,
        }
        out = {k: v for k, v in candidate.items() if v}
        out["verify_ssl"] = bool(self.es_verify_ssl)
        return out

    def kibana_config(self) -> dict:
        """Connection dict for the Kibana cases client. Same inherit-on-blank rule."""
        candidate = {
            "url": self.kibana_url,
            "username": self.kibana_username,
            "password": self.kibana_password,
            "space_id": self.kibana_space_id,
        }
        return {k: v for k, v in candidate.items() if v}
