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
    from ion.storage.collection_repository import CollectionRepository
    from ion.storage.database import get_engine, get_session_factory
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
        from ion.data.kb_cloud_siem import COLLECTIONS as KB_CLOUD_SIEM
        from ion.data.kb_forensics_advanced import COLLECTIONS as KB_FORENSICS_ADV
        from ion.data.kb_forensics_analysis import COLLECTIONS as KB_FORENSICS
        from ion.data.kb_forensics_ir import COLLECTIONS as KB_FORENSICS_IR
        from ion.data.kb_foundations import COLLECTIONS as KB_FOUNDATIONS
        from ion.data.kb_foundations_extended import COLLECTIONS as KB_FOUNDATIONS_EXT
        from ion.data.kb_fundamentals import COLLECTIONS as KB_FUNDAMENTALS
        from ion.data.kb_networking_defense import COLLECTIONS as KB_NET_DEF
        from ion.data.kb_networking_protocols import COLLECTIONS as KB_NET_PROTO
        from ion.data.kb_offensive_access import COLLECTIONS as KB_OFF_ACCESS
        from ion.data.kb_offensive_advanced import COLLECTIONS as KB_OFF_ADVANCED

        # Registry: (label, COLLECTIONS).  article_source in each COLLECTIONS
        # entry may be a callable returning [(title, tags, content), ...] or a
        # plain list of {"title", "tags", "content"} dicts — detected at load
        # time via callable() so new modules need no flag.
        all_modules = [
            ("Main KB", KB_MAIN),
            ("Blue Team", KB_BLUETEAM),
            ("Foundations", KB_FOUNDATIONS),
            ("Fundamentals", KB_FUNDAMENTALS),
            ("Offensive — Access & Escalation", KB_OFF_ACCESS),
            ("Offensive — C2, Web & Evasion", KB_OFF_ADVANCED),
            ("Foundations Extended", KB_FOUNDATIONS_EXT),
            ("Networking — Protocols & Infra", KB_NET_PROTO),
            ("Networking — Defense & Analysis", KB_NET_DEF),
            ("Forensics — Analysis", KB_FORENSICS),
            ("Forensics — Advanced", KB_FORENSICS_ADV),
            ("Forensics — IR & Logs", KB_FORENSICS_IR),
            ("Cloud, SIEM & Governance", KB_CLOUD_SIEM),
        ]

        total = 0
        for module_name, collections in all_modules:
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

                # Normalise: callable → [(title, tags, content)]; list → same via dict access
                if callable(article_source):
                    articles_iter = article_source()
                    for title, tags, content in articles_iter:
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
