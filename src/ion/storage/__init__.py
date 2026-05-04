"""Storage layer with repository pattern."""

from ion.storage.database import get_engine, get_session, init_db
from ion.storage.document_repository import DocumentRepository
from ion.storage.template_repository import TemplateRepository
from ion.storage.version_repository import VersionRepository

__all__ = [
    "get_engine",
    "get_session",
    "init_db",
    "TemplateRepository",
    "VersionRepository",
    "DocumentRepository",
]
