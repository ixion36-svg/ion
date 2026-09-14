"""Tenants — the identity of one client estate.

ION has always talked to exactly one Elastic: ``elasticsearch_alert_index`` and
``kibana_space_id`` are process-global config. A tenant names an estate so one
instance can serve several, each with its own cluster, index and Kibana space.

**Identity here, connection in the environment.** The row carries only what has
to be stable — an id the ``tenant_id`` columns can reference, and a slug that
appears in audit records — while the Elasticsearch and Kibana connection comes
from ``ION_TENANT_<SLUG>_*`` environment variables, matching the
``ION_<NAME>_*`` family every other ION integration already uses. Credentials
then stay in ``.env`` with every other credential instead of becoming a new
secret store in the database, and an air-gapped estate configures a tenant the
same way it configures everything else. The cost is that adding a tenant needs a
restart, which is how these deployments change anyway.

**Arkime and OpenCTI are deliberately not per-tenant.** They stay shared — PCAP
retrieval and threat intelligence are estate-wide services, not per-client ones.
Giving them a per-tenant connection would imply an isolation this design does
not provide.

Alerts themselves live in Elasticsearch, so tenant isolation for them is a
matter of which cluster ION queries. ION's own rows — triage, cases, notes —
carry a ``tenant_id`` instead.

``users.tenant_id`` is nullable and NULL means platform-global: a support or
oversight account that can act across tenants. Every other user is bound to one.
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

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Tenant {self.slug!r} active={self.is_active}>"

    @property
    def env_prefix(self) -> str:
        """Environment-variable prefix for this tenant's connection settings.

        ``acme-uk`` -> ``ION_TENANT_ACME_UK``, so the family reads
        ``ION_TENANT_ACME_UK_ES_URL``, ``..._KIBANA_SPACE`` and so on.
        """
        return "ION_TENANT_" + self.slug.upper().replace("-", "_")
