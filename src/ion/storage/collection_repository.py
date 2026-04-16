"""Repository for Collection operations."""

from typing import Optional, List
from sqlalchemy import select, and_
from sqlalchemy.orm import Session, selectinload

from ion.models.template import Collection, Template
from ion.models.document import Document


class CollectionRepository:
    """Repository for Collection CRUD operations."""

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        name: str,
        description: str | None = None,
        icon: str | None = None,
        parent_id: int | None = None,
    ) -> Collection:
        """Create a new collection/folder."""
        collection = Collection(
            name=name,
            description=description,
            icon=icon,
            parent_id=parent_id,
        )
        self.session.add(collection)
        self.session.flush()
        return collection

    def get_by_id(self, collection_id: int) -> Optional[Collection]:
        """Get a collection by ID."""
        stmt = (
            select(Collection)
            .options(
                selectinload(Collection.templates),
                selectinload(Collection.documents),
                selectinload(Collection.children),
            )
            .where(Collection.id == collection_id)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_name(self, name: str) -> Optional[Collection]:
        """Get a collection by name (first match)."""
        stmt = (
            select(Collection)
            .options(selectinload(Collection.templates))
            .where(Collection.name == name)
        )
        return self.session.execute(stmt).scalars().first()

    def get_by_name_and_parent(self, name: str, parent_id: int | None) -> Optional[Collection]:
        """Get a collection by name within a specific parent folder."""
        if parent_id is None:
            stmt = (
                select(Collection)
                .where(and_(Collection.name == name, Collection.parent_id.is_(None)))
            )
        else:
            stmt = (
                select(Collection)
                .where(and_(Collection.name == name, Collection.parent_id == parent_id))
            )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_all(self) -> List[Collection]:
        """List all collections with eager loading."""
        stmt = (
            select(Collection)
            .options(
                selectinload(Collection.templates),
                selectinload(Collection.documents),
                selectinload(Collection.children),
            )
            .order_by(Collection.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def list_root_collections(self) -> List[Collection]:
        """List only root-level collections (no parent)."""
        stmt = (
            select(Collection)
            .options(
                selectinload(Collection.templates),
                selectinload(Collection.documents),
                selectinload(Collection.children),
            )
            .where(Collection.parent_id.is_(None))
            .order_by(Collection.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def list_children(self, parent_id: int) -> List[Collection]:
        """List child collections of a parent."""
        stmt = (
            select(Collection)
            .options(
                selectinload(Collection.templates),
                selectinload(Collection.documents),
                selectinload(Collection.children),
            )
            .where(Collection.parent_id == parent_id)
            .order_by(Collection.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def update(
        self,
        collection: Collection,
        name: str | None = None,
        description: str | None = None,
        icon: str | None = None,
        parent_id: int | None = None,
    ) -> Collection:
        """Update a collection."""
        if name is not None:
            collection.name = name
        if description is not None:
            collection.description = description
        if icon is not None:
            collection.icon = icon
        if parent_id is not None:
            collection.parent_id = parent_id
        elif parent_id is None and hasattr(collection, '_set_parent_none'):
            # Allow explicitly setting parent_id to None
            collection.parent_id = None
        self.session.flush()
        return collection

    def delete(self, collection: Collection) -> None:
        """Delete a collection (templates/documents are not deleted, just unlinked)."""
        # Unlink all templates from this collection
        for template in collection.templates:
            template.collection_id = None
        # Unlink all documents from this collection
        for doc in collection.documents:
            doc.collection_id = None
        # Move child collections to parent or root
        for child in collection.children:
            child.parent_id = collection.parent_id
        self.session.delete(collection)
        self.session.flush()

    def add_template(self, collection: Collection, template: Template) -> None:
        """Add a template to a collection."""
        template.collection_id = collection.id
        self.session.flush()

    def remove_template(self, template: Template) -> None:
        """Remove a template from its collection."""
        template.collection_id = None
        self.session.flush()

    def add_document(self, collection: Collection, document: Document) -> None:
        """Add a document to a collection."""
        document.collection_id = collection.id
        self.session.flush()

    def remove_document(self, document: Document) -> None:
        """Remove a document from its collection."""
        document.collection_id = None
        self.session.flush()

    def get_templates(self, collection_id: int) -> List[Template]:
        """Get all templates in a collection."""
        stmt = (
            select(Template)
            .where(Template.collection_id == collection_id)
            .order_by(Template.name)
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_documents(self, collection_id: int) -> List[Document]:
        """Get all documents in a collection."""
        stmt = (
            select(Document)
            .where(Document.collection_id == collection_id)
            .order_by(Document.name)
        )
        return list(self.session.execute(stmt).scalars().all())
