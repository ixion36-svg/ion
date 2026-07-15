"""v0.51.0 — chunk-level KB embeddings (RAG rework Phase 3).

The KB RAG layer previously embedded each article as ONE vector over the
first 8,000 chars — long articles lost their tails to nomic's end-window
truncation, and the prompt excerpt was the first 800 chars of the doc head
rather than the passage that matched. v0.51.0 chunks every article
(``_chunk_body``), embeds each chunk into the new ``kb_chunk_embeddings``
table (composite PK document_id+chunk_index, chunk_text stored), and
retrieval dedups top chunks back to documents, quoting the matched chunk.
"""

import os

from ion.models.document import Document
from ion.models.kb_document_embedding import KBChunkEmbedding
from ion.models.template import Collection
from ion.services import kb_embedding_service as kbe


class _StubEmbed:
    """Stand-in for EmbeddingService — deterministic, no Ollama."""

    def __init__(self, fail_after=None):
        self.is_enabled = True
        self.model_tag = "stub+tp1"
        self.model = "stub"
        self.calls = 0
        self.fail_after = fail_after

    def embed(self, text, mode="document"):
        assert mode == "document"
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            return None
        return [0.1] * 768


# ---------------------------------------------------------------------------
# _chunk_body
# ---------------------------------------------------------------------------

def test_chunk_empty_body():
    assert kbe._chunk_body("") == []
    assert kbe._chunk_body(None) == []
    assert kbe._chunk_body("   \n\n  ") == []


def test_chunk_short_doc_is_single_chunk():
    chunks = kbe._chunk_body("One paragraph.\n\nAnother paragraph.")
    assert chunks == ["One paragraph.\n\nAnother paragraph."]


def test_chunk_packs_paragraphs_to_target():
    para = "x" * 900
    chunks = kbe._chunk_body(f"{para}\n\n{para}\n\n{para}")
    # 900+2+900 > 1600 → two paragraphs never share a chunk here.
    assert len(chunks) == 3
    assert all(len(c) <= kbe._CHUNK_TARGET_CHARS for c in chunks)


def test_chunk_hard_splits_long_paragraph_with_overlap():
    body = "y" * 4000  # one paragraph, far over target
    chunks = kbe._chunk_body(body)
    assert len(chunks) >= 3
    assert all(len(c) <= kbe._CHUNK_TARGET_CHARS for c in chunks)
    # Overlap: each subsequent chunk starts before the previous one ended.
    step = kbe._CHUNK_TARGET_CHARS - kbe._CHUNK_OVERLAP_CHARS
    assert chunks[1] == body[step:step + kbe._CHUNK_TARGET_CHARS]
    # Every char of the source is covered.
    assert sum(len(c) for c in chunks) >= len(body)


def test_chunk_count_is_capped():
    body = "\n\n".join("z" * 1500 for _ in range(100))
    chunks = kbe._chunk_body(body)
    assert len(chunks) == kbe._MAX_CHUNKS_PER_DOC


def test_chunk_source_text_prepends_title_every_chunk():
    doc = Document(name="Kerberos attacks", rendered_content="irrelevant")
    text = kbe._chunk_source_text(doc, "Golden Ticket detection details")
    assert text.startswith("Title: Kerberos attacks\n")
    assert "Content: Golden Ticket detection details" in text


# ---------------------------------------------------------------------------
# run_kb_embedding_once — chunk rows lifecycle
# ---------------------------------------------------------------------------

def _seed_kb(session, content: str, name: str = "KB article") -> Document:
    root = (
        session.query(Collection)
        .filter(Collection.name == "Knowledge Base", Collection.parent_id.is_(None))
        .first()
    )
    if root is None:
        root = Collection(name="Knowledge Base", parent_id=None)
        session.add(root)
        session.commit()
    doc = Document(
        name=name,
        collection_id=root.id,
        rendered_content=content,
        status="active",
    )
    session.add(doc)
    session.commit()
    return doc


def _chunk_rows(session, doc_id):
    return (
        session.query(KBChunkEmbedding)
        .filter(KBChunkEmbedding.document_id == doc_id)
        .order_by(KBChunkEmbedding.chunk_index)
        .all()
    )


def test_loop_writes_chunk_rows_and_skips_fresh(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: stub)
    doc = _seed_kb(session, ("a" * 1500) + "\n\n" + ("b" * 1500))

    out = kbe.run_kb_embedding_once(session)
    assert out["embedded"] == 1
    assert out["chunks"] == 2
    rows = _chunk_rows(session, doc.id)
    assert [r.chunk_index for r in rows] == [0, 1]
    assert rows[0].chunk_text.startswith("a")
    assert rows[1].chunk_text.startswith("b")
    assert rows[0].source_text_hash == rows[1].source_text_hash
    assert rows[0].model_name == "stub+tp1"

    # Second pass — nothing changed, nothing re-embedded.
    out2 = kbe.run_kb_embedding_once(session)
    assert out2["embedded"] == 0
    assert out2["skipped_fresh"] == 1


def test_loop_removes_stale_chunks_when_doc_shrinks(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: stub)
    doc = _seed_kb(session, ("a" * 1500) + "\n\n" + ("b" * 1500), name="Shrinker")
    kbe.run_kb_embedding_once(session)
    assert len(_chunk_rows(session, doc.id)) == 2

    doc.rendered_content = "short now"
    session.commit()
    out = kbe.run_kb_embedding_once(session)
    assert out["embedded"] == 1
    rows = _chunk_rows(session, doc.id)
    assert len(rows) == 1
    assert rows[0].chunk_text == "short now"


def test_loop_never_writes_partial_chunk_sets(session, monkeypatch):
    # Second embed call fails → the whole doc is skipped this tick.
    stub = _StubEmbed(fail_after=1)
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: stub)
    doc = _seed_kb(session, ("a" * 1500) + "\n\n" + ("b" * 1500), name="Failer")

    out = kbe.run_kb_embedding_once(session)
    assert out["embedded"] == 0
    assert out["failed"] == 1
    assert _chunk_rows(session, doc.id) == []


def test_loop_processes_at_least_one_doc_despite_chunk_budget(
    session, monkeypatch
):
    stub = _StubEmbed()
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: stub)
    monkeypatch.setitem(os.environ, "ION_KB_EMBEDDING_BATCH", "1")
    doc = _seed_kb(
        session,
        "\n\n".join("c" * 1500 for _ in range(3)),
        name="Long article",
    )
    out = kbe.run_kb_embedding_once(session)
    # Budget of 1 chunk, but the doc is written whole — never partially.
    assert out["embedded"] == 1
    assert out["chunks"] == 3
    assert len(_chunk_rows(session, doc.id)) == 3


def test_model_tag_change_re_embeds(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: stub)
    doc = _seed_kb(session, "stable content", name="Regime flip")
    kbe.run_kb_embedding_once(session)
    assert _chunk_rows(session, doc.id)[0].model_name == "stub+tp1"

    stub.model_tag = "stub+tp2"
    out = kbe.run_kb_embedding_once(session)
    assert out["embedded"] == 1
    assert _chunk_rows(session, doc.id)[0].model_name == "stub+tp2"


# ---------------------------------------------------------------------------
# Retired whole-doc table
# ---------------------------------------------------------------------------

def test_whole_doc_model_is_gone():
    import ion.models.kb_document_embedding as mod
    assert not hasattr(mod, "KBDocumentEmbedding")
    assert KBChunkEmbedding.__tablename__ == "kb_chunk_embeddings"


def test_migration_drops_retired_table():
    import inspect as pyinspect

    from ion.storage import database
    src = pyinspect.getsource(database._run_migrations)
    assert "kb_document_embeddings" in src
    assert "DROP TABLE kb_document_embeddings" in src
