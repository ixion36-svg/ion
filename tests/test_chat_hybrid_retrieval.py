"""Chat RAG fuses substring matching with vector search instead of replacing it.

Chat retrieval was `ILIKE '%keyword%'` only, which cannot tell that "golden
ticket" belongs with a Kerberos article -- so the model got near-misses and
invented the specifics it was missing. Pure vector search would have traded that
for a different failure: embeddings blur identifiers, so a query for one CVE
ranks every other CVE beside it. Both retrievers run, and their rankings fuse.

The load-bearing property is the fallback. Air-gapped deploys, Ollama down, or
embeddings off must retrieve exactly what they retrieved before, in the same
order -- a security tool that silently stops finding its own documentation is
worse than one that never searched semantically.
"""

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ion.services.ai_context_service import (  # noqa: E402
    MIN_VECTOR_SIMILARITY,
    RRF_K,
    AIContextService,
    ContextSnippet,
    RAGContext,
    _chat_vector_rag_enabled,
)


def snip(source_id, title, text="window", score=0.0, source_type="knowledge_base"):
    return ContextSnippet(source_type, source_id, title, text, score)


def prefs(**over):
    p = types.SimpleNamespace(
        rag_knowledge_base=True,
        rag_user_notes=True,
        rag_playbooks=True,
        max_context_snippets=3,
    )
    for k, v in over.items():
        setattr(p, k, v)
    return p


# --------------------------------------------------------------------------
# Fusion.
# --------------------------------------------------------------------------


def test_agreement_between_retrievers_wins():
    """The two disagree often; agreeing is the strongest signal available."""
    keyword = [snip(1, "Kerberos"), snip(2, "Phishing"), snip(3, "Ransomware")]
    vector = [snip(3, "Ransomware"), snip(1, "Kerberos")]

    order = [s.source_id for s in AIContextService._fuse([keyword, vector], 5)]

    assert order[:2] == [1, 3], "docs found by both should lead"
    assert order[-1] == 2, "the keyword-only hit should trail"


def test_a_document_appears_once():
    keyword = [snip(1, "Kerberos")]
    vector = [snip(1, "Kerberos")]
    fused = AIContextService._fuse([keyword, vector], 5)
    assert len(fused) == 1


def test_same_id_from_different_sources_is_not_deduped():
    """KB #7 and playbook #7 are different documents."""
    a = [snip(7, "KB seven", source_type="knowledge_base")]
    b = [snip(7, "PB seven", source_type="playbook")]
    assert len(AIContextService._fuse([a, b], 5)) == 2


def test_the_snippet_comes_from_the_more_confident_retriever():
    keyword = [snip(9, "Doc", text="keyword window")]
    vector = [snip(9, "Doc", text="matching chunk")]
    # Vector ranked it first, keyword ranked it second.
    fused = AIContextService._fuse([[snip(1, "other"), keyword[0]], vector], 5)
    assert next(s for s in fused if s.source_id == 9).snippet == "matching chunk"


def test_limit_is_honoured():
    ranked = [[snip(i, f"d{i}") for i in range(10)]]
    assert len(AIContextService._fuse(ranked, 3)) == 3


def test_no_rankings_yields_nothing():
    assert AIContextService._fuse([], 5) == []
    assert AIContextService._fuse([[]], 5) == []


def test_a_single_ranking_keeps_its_order():
    """Fusion is rank-monotonic, so the degraded path reorders nothing."""
    ranked = [snip(i, f"d{i}") for i in range(6)]
    assert [s.source_id for s in AIContextService._fuse([ranked], 6)] == list(range(6))


def test_rrf_constant_flattens_the_head():
    """With k=60 the top two ranks are close, so one list cannot monopolise."""
    first, second = 1.0 / (RRF_K + 1), 1.0 / (RRF_K + 2)
    assert second / first > 0.95


# --------------------------------------------------------------------------
# Degradation. The whole design rests on this.
# --------------------------------------------------------------------------


class _Svc(AIContextService):
    """AIContextService with the DB half stubbed, so retrieval logic is testable."""

    def __init__(self, keyword=None, kb_vec=None, pb_vec=None, vec=None, tag="m+tp1"):
        self._kw = keyword or []
        self._kb_vec = kb_vec or []
        self._pb_vec = pb_vec or []
        self._vec = vec
        self._tag = tag
        self.embed_calls = []
        self.tags_used = []
        self.db = None

    def _search_knowledge_base(self, keywords, limit):
        return list(self._kw)

    def _search_user_notes(self, keywords, user_id, limit):
        return []

    def _search_playbooks(self, keywords, limit):
        return []

    def _embed_query(self, query):
        self.embed_calls.append(query)
        return None if self._vec is None else (self._vec, self._tag)

    def _vector_search_kb(self, vec, model_tag, k):
        self.tags_used.append(model_tag)
        return list(self._kb_vec)

    def _vector_search_playbooks(self, vec, model_tag, k):
        self.tags_used.append(model_tag)
        return list(self._pb_vec)


def test_without_embeddings_order_matches_keyword_only():
    """Air-gapped: the vector half contributes nothing and nothing is reordered."""
    keyword = [snip(1, "a", score=30), snip(2, "b", score=20), snip(3, "c", score=10)]
    svc = _Svc(keyword=keyword, vec=None)

    ctx = svc.retrieve_context("kerberos golden ticket", 1, prefs())

    assert [s.source_id for s in ctx.snippets] == [1, 2, 3]


def test_without_embeddings_no_vector_query_is_attempted():
    svc = _Svc(keyword=[snip(1, "a")], kb_vec=[snip(99, "never")], vec=None)
    ctx = svc.retrieve_context("kerberos golden ticket", 1, prefs())
    assert 99 not in [s.source_id for s in ctx.snippets]


def test_vector_hits_join_the_results_when_embeddings_are_available():
    svc = _Svc(
        keyword=[snip(1, "keyword only")],
        kb_vec=[snip(42, "semantic match", text="chunk")],
        vec=[0.1] * 8,
    )
    ctx = svc.retrieve_context("how do I spot a golden ticket", 1, prefs())
    assert 42 in [s.source_id for s in ctx.snippets]


def test_the_whole_question_is_embedded_not_the_keywords():
    """Dropping stop words discards the phrasing the embedding exists to capture."""
    svc = _Svc(keyword=[snip(1, "a")], vec=[0.1] * 8)
    query = "how would I tell a golden ticket from a silver ticket"
    svc.retrieve_context(query, 1, prefs())
    assert svc.embed_calls == [query]


def test_disabled_sources_are_not_searched():
    svc = _Svc(keyword=[snip(1, "kb")], kb_vec=[snip(2, "kb vec")], vec=[0.1] * 8)
    ctx = svc.retrieve_context("kerberos ticket attack", 1, prefs(rag_knowledge_base=False))
    assert ctx.snippets == []


def test_a_greeting_retrieves_nothing():
    svc = _Svc(keyword=[snip(1, "a")], vec=[0.1] * 8)
    assert svc.retrieve_context("hi", 1, prefs()).snippets == []
    assert svc.embed_calls == [], "no embedding call for a greeting"


def test_the_char_budget_still_applies():
    big = [snip(i, f"d{i}", text="x" * 2000) for i in range(5)]
    svc = _Svc(keyword=big, vec=None)
    ctx = svc.retrieve_context("kerberos ticket attack", 1, prefs(max_context_snippets=5))
    assert sum(len(s.snippet) for s in ctx.snippets) <= 3000 + 3


# --------------------------------------------------------------------------
# The env gate and the similarity floor.
# --------------------------------------------------------------------------


def test_vector_rag_is_on_by_default(monkeypatch):
    monkeypatch.delenv("ION_CHAT_VECTOR_RAG", raising=False)
    assert _chat_vector_rag_enabled() is True


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off"])
def test_vector_rag_can_be_switched_off(monkeypatch, value):
    monkeypatch.setenv("ION_CHAT_VECTOR_RAG", value)
    assert _chat_vector_rag_enabled() is False


def test_flag_off_skips_embedding_entirely(monkeypatch):
    """Off must not call the embedding service at all, not merely drop results."""
    monkeypatch.setenv("ION_CHAT_VECTOR_RAG", "false")
    called = []

    fake = types.ModuleType("ion.services.embedding_service")

    def get_embedding_service():
        called.append(True)
        raise AssertionError("embedding service reached with the flag off")

    fake.get_embedding_service = get_embedding_service
    monkeypatch.setitem(sys.modules, "ion.services.embedding_service", fake)

    svc = AIContextService.__new__(AIContextService)
    assert svc._embed_query("kerberos golden ticket") is None
    assert called == []


def test_a_disabled_embedding_service_returns_none(monkeypatch):
    fake = types.ModuleType("ion.services.embedding_service")
    fake.get_embedding_service = lambda: types.SimpleNamespace(is_enabled=False)
    monkeypatch.setitem(sys.modules, "ion.services.embedding_service", fake)
    monkeypatch.delenv("ION_CHAT_VECTOR_RAG", raising=False)

    svc = AIContextService.__new__(AIContextService)
    assert svc._embed_query("kerberos golden ticket") is None


def test_an_unreachable_embedder_never_raises(monkeypatch):
    """Ollama down must degrade retrieval, not fail the chat request."""

    def boom():
        raise RuntimeError("connection refused")

    fake = types.ModuleType("ion.services.embedding_service")
    fake.get_embedding_service = boom
    monkeypatch.setitem(sys.modules, "ion.services.embedding_service", fake)
    monkeypatch.delenv("ION_CHAT_VECTOR_RAG", raising=False)

    svc = AIContextService.__new__(AIContextService)
    assert svc._embed_query("kerberos golden ticket") is None


def test_vector_search_without_pgvector_returns_empty():
    """SQLite dev and test setups have no cosine_distance; that is not an error."""

    class NoDB:
        def query(self, *a, **k):
            raise RuntimeError("no such function: cosine_distance")

    svc = AIContextService.__new__(AIContextService)
    svc.db = NoDB()
    assert svc._vector_search_kb([0.1] * 8, "m+tp1", 3) == []
    assert svc._vector_search_playbooks([0.1] * 8, "m+tp1", 3) == []


def test_the_similarity_floor_is_not_tight():
    """KB articles are topic-level, so a tight floor would reject real matches."""
    assert 0.5 < MIN_VECTOR_SIMILARITY < 0.8


# --------------------------------------------------------------------------
# The prompt block still states the grounding contract over fused results.
# --------------------------------------------------------------------------


def test_fused_results_still_carry_the_grounding_contract():
    block = RAGContext(snippets=[snip(1, "Kerberos", "body")]).to_prompt_block()
    assert "ground your answer" in block.lower()
    assert "verbatim" in block.lower()


def test_citations_survive_fusion():
    ctx = RAGContext(snippets=[snip(1, "Kerberos", "body"), snip(2, "Phishing", "b")])
    meta = ctx.to_citations_metadata()
    assert [m["id"] for m in meta] == [1, 2]
    assert all("score" not in m for m in meta), "RRF scores are not citation data"


# --------------------------------------------------------------------------
# Model-tag isolation. A stored vector is only comparable to one made by the
# same model under the same task-prefix regime; changing either re-embeds the
# corpus in the background, so both tags coexist for as long as that takes.
# --------------------------------------------------------------------------


def test_the_query_model_tag_reaches_the_vector_search():
    svc = _Svc(keyword=[snip(1, "a")], kb_vec=[snip(2, "b")], vec=[0.1] * 8,
               tag="nomic-embed-text+tp1")
    svc.retrieve_context("kerberos golden ticket", 1, prefs())
    assert svc.tags_used, "vector search ran without being told the model tag"
    assert set(svc.tags_used) == {"nomic-embed-text+tp1"}


def test_vector_searches_filter_on_the_model_tag():
    """Mid-re-embed, rows under the old tag must not be ranked against the new.

    Compiles the statement the code actually executes -- captured at .all(), so
    every chained .filter() is already on it -- rather than reading the source.
    """
    pytest.importorskip("pgvector")
    from sqlalchemy import create_engine
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.orm import Query, Session

    captured = []

    class CapturingQuery(Query):
        def all(self):
            captured.append(str(self.statement.compile(dialect=postgresql.dialect())))
            return []

    engine = create_engine("postgresql://u:p@localhost/x")  # never connected

    for method in ("_vector_search_kb", "_vector_search_playbooks"):
        captured.clear()
        svc = AIContextService.__new__(AIContextService)
        svc.db = Session(engine, query_cls=CapturingQuery)
        assert getattr(svc, method)([0.1] * 768, "nomic-embed-text+tp1", 3) == []
        assert captured, f"{method} never reached the database"
        sql = captured[0]
        assert "model_name" in sql, f"{method} ranks across embedding regimes"
        assert "<=>" in sql, f"{method} is not using pgvector cosine distance"
        assert "ORDER BY" in sql and "LIMIT" in sql, (
            f"{method} must order by distance and cap, or the HNSW index is unused"
        )
