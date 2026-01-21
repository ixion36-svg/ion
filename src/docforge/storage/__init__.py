"""Storage layer with repository pattern."""

from docforge.storage.database import get_engine, get_session, init_db
from docforge.storage.template_repository import TemplateRepository
from docforge.storage.version_repository import VersionRepository
from docforge.storage.document_repository import DocumentRepository

__all__ = [
    "get_engine",
    "get_session",
    "init_db",
    "TemplateRepository",
    "VersionRepository",
    "DocumentRepository",
]
