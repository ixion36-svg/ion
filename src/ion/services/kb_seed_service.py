"""Seed built-in Knowledge Base articles on startup.

Creates ~392 SOC analyst reference articles organized into 28 collections
under a 'Knowledge Base' parent collection. Idempotent — checks for existing
parent collection with documents before running.
"""

import logging

logger = logging.getLogger(__name__)


def seed_knowledge_base() -> None:
    """Seed all built-in Knowledge Base articles into the database.

    Idempotent: skips entirely if the Knowledge Base parent collection
    already has child collections with documents.
    """
    from ion.storage.database import get_engine, get_session_factory
    from ion.storage.collection_repository import CollectionRepository
    from ion.storage.document_repository import DocumentRepository

    engine = get_engine()
    factory = get_session_factory(engine)
    session = factory()

    try:
        collection_repo = CollectionRepository(session)
        doc_repo = DocumentRepository(session)

        # Quick check: if KB parent exists and has documents, skip entirely
        parent = collection_repo.get_by_name("Knowledge Base")
        if parent:
            existing = collection_repo.get_by_id(parent.id)
            if existing and existing.children:
                # Check if any child collection has documents
                for child in existing.children:
                    child_full = collection_repo.get_by_id(child.id)
                    if child_full and child_full.documents:
                        logger.info(
                            "Knowledge Base already seeded (%d child collections), skipping",
                            len(existing.children),
                        )
                        return
            parent_id = parent.id
        else:
            parent = collection_repo.create(
                name="Knowledge Base",
                description=(
                    "SOC Analyst Reference Library — comprehensive knowledge base "
                    "covering security operations, threat hunting, detection "
                    "engineering, incident response, and more."
                ),
            )
            session.flush()
            parent_id = parent.id

        # Load all article modules
        from ion.data.kb_articles import COLLECTIONS as KB_MAIN
        from ion.data.kb_blueteam import COLLECTIONS as KB_BLUETEAM
        from ion.data.kb_foundations import COLLECTIONS as KB_FOUNDATIONS
        from ion.data.kb_fundamentals import COLLECTIONS as KB_FUNDAMENTALS

        all_modules = [
            ("Main KB", KB_MAIN, True),         # COLLECTIONS entries use functions
            ("Blue Team", KB_BLUETEAM, True),
            ("Foundations", KB_FOUNDATIONS, True),
            ("Fundamentals", KB_FUNDAMENTALS, False),  # Uses lists of dicts
        ]

        total = 0
        for module_name, collections, uses_functions in all_modules:
            for col_name, col_desc, article_source in collections:
                # Get or create child collection
                child = collection_repo.get_by_name_and_parent(col_name, parent_id)
                if not child:
                    child = collection_repo.create(
                        name=col_name,
                        description=col_desc,
                        parent_id=parent_id,
                    )
                    session.flush()

                # Get articles (function call or direct list)
                if uses_functions:
                    articles = article_source()
                    # Format: [(title, [tags], content), ...]
                    for title, tags, content in articles:
                        existing_doc = doc_repo.get_by_name(title)
                        if existing_doc:
                            continue
                        doc = doc_repo.create(
                            name=title,
                            rendered_content=content,
                            output_format="markdown",
                        )
                        doc.collection_id = child.id
                        doc_repo.set_tags(doc, tags)
                        total += 1
                else:
                    # Format: [{"title": ..., "tags": [...], "content": ...}, ...]
                    for article in article_source:
                        title = article["title"]
                        existing_doc = doc_repo.get_by_name(title)
                        if existing_doc:
                            continue
                        doc = doc_repo.create(
                            name=title,
                            rendered_content=article["content"],
                            output_format="markdown",
                        )
                        doc.collection_id = child.id
                        doc_repo.set_tags(doc, article.get("tags", []))
                        total += 1

            # Commit per module to avoid huge transactions
            session.commit()
            logger.info("Seeded %s KB module", module_name)

        logger.info("Knowledge Base seeding complete: %d articles created", total)

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
