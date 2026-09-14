"""AI context service — RAG retrieval from KB, notes, and playbooks.

Retrieval is hybrid: substring matching and vector search run independently and
their rankings are fused. Neither alone is adequate for security content --
substring matching cannot tell that "golden ticket" belongs with a Kerberos
article, and embeddings blur exactly the identifiers analysts search by, so a
query for CVE-2024-3094 ranks every other CVE alongside it. Fusing keeps the
recall of one and the precision of the other.

The vector half reads the KB-chunk and playbook embeddings that the background
loops already maintain (``kb_embedding_service`` / ``playbook_embedding_service``,
both on by default since v0.36.0). Analyst notes have no embedding table, so
they stay substring-only.

When embeddings are unavailable -- air-gapped, Ollama down, ION_EMBEDDING_ENABLED
off -- the vector half yields nothing and retrieval degrades to exactly the
substring behaviour that came before it.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ion.models.ai_preferences import AIUserPreference
from ion.models.analyst_note import AnalystNote
from ion.models.document import Document
from ion.models.playbook import Playbook

logger = logging.getLogger(__name__)

MAX_SNIPPET_CHARS = 800
MAX_TOTAL_CONTEXT_CHARS = 3000

# Reciprocal Rank Fusion constant, from the paper the method comes from and the
# value Elasticsearch and OpenSearch ship. It flattens the head of each ranking
# enough that neither retriever can monopolise the results.
RRF_K = 60

# Cosine similarity below this is noise rather than a weak match. Same floor
# alert_prompt_service already applies to KB RAG: topic-level documentation
# overlaps broadly by design, so the threshold is deliberately not tight.
MIN_VECTOR_SIMILARITY = 0.65


def _chat_vector_rag_enabled() -> bool:
    """Semantic half of chat retrieval. On by default: the corpus is already
    embedded, and with no embeddings the code path costs nothing anyway."""
    return os.environ.get("ION_CHAT_VECTOR_RAG", "true").lower() in (
        "true",
        "1",
        "yes",
    )

STOP_WORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "dare", "ought",
    "used", "to", "of", "in", "for", "on", "with", "at", "by", "from",
    "as", "into", "through", "during", "before", "after", "above", "below",
    "between", "out", "off", "over", "under", "again", "further", "then",
    "once", "here", "there", "when", "where", "why", "how", "all", "both",
    "each", "few", "more", "most", "other", "some", "such", "no", "nor",
    "not", "only", "own", "same", "so", "than", "too", "very", "just",
    "don", "now", "and", "but", "or", "if", "while", "that", "this",
    "what", "which", "who", "whom", "these", "those", "am", "it", "its",
    "i", "me", "my", "we", "our", "you", "your", "he", "him", "his",
    "she", "her", "they", "them", "their", "about", "up",
    # Greetings and conversational filler — should not trigger RAG
    "hi", "hey", "hello", "howdy", "yo", "sup", "hiya",
    "thanks", "thank", "cheers", "bye", "goodbye", "ok", "okay",
    "yes", "yeah", "yep", "nope", "nah", "sure", "cool", "nice",
    "please", "sorry", "wow", "lol", "haha", "hmm", "ah", "oh",
}


@dataclass
class ContextSnippet:
    """A single RAG context snippet."""
    source_type: str  # "knowledge_base", "user_note", "playbook"
    source_id: int
    title: str
    snippet: str
    score: float = 0.0


@dataclass
class RAGContext:
    """Container for RAG-retrieved context."""
    snippets: List[ContextSnippet] = field(default_factory=list)

    def to_prompt_block(self) -> str:
        """Format snippets as a system prompt injection block."""
        if not self.snippets:
            return ""

        lines = ["--- REFERENCE CONTEXT ---"]
        for s in self.snippets:
            label = {
                "knowledge_base": "KB Article",
                "user_note": "Your Note",
                "playbook": "Playbook",
            }.get(s.source_type, "Reference")
            lines.append(f"[{label} #{s.source_id}] {s.title}")
            lines.append(s.snippet)
            lines.append("")

        lines.append("--- END REFERENCE CONTEXT ---")
        # Retrieval here is substring matching, so the block regularly contains
        # near-misses. Without an explicit contract a small model treats whatever
        # it retrieved as licence to invent matching specifics.
        lines.append(
            "Ground your answer in the reference context above and cite sources by "
            "type and title. Mark anything you add from general knowledge as such. "
            "Never present a specific -- an IOC, CVE, hostname, rule ID or quotation "
            "-- as coming from the reference context unless it appears there "
            "verbatim. If the context does not answer the question, say so plainly "
            "rather than filling the gap."
        )
        return "\n".join(lines)

    def to_citations_metadata(self) -> List[Dict[str, Any]]:
        """Return citation metadata for the frontend."""
        return [
            {
                "type": s.source_type,
                "id": s.source_id,
                "title": s.title,
            }
            for s in self.snippets
        ]


class AIContextService:
    """Service for RAG context retrieval and user preference management."""

    def __init__(self, db: Session):
        self.db = db

    def get_user_preferences(self, user_id: int) -> AIUserPreference:
        """Get or create default preferences for a user."""
        prefs = (
            self.db.query(AIUserPreference)
            .filter(AIUserPreference.user_id == user_id)
            .first()
        )
        if not prefs:
            prefs = AIUserPreference(user_id=user_id)
            self.db.add(prefs)
            self.db.commit()
            self.db.refresh(prefs)
        return prefs

    def update_preferences(self, user_id: int, updates: dict) -> AIUserPreference:
        """Partial-update user preferences."""
        prefs = self.get_user_preferences(user_id)
        for key, value in updates.items():
            if hasattr(prefs, key) and key not in ("id", "user_id", "created_at", "updated_at"):
                setattr(prefs, key, value)
        self.db.commit()
        self.db.refresh(prefs)
        return prefs

    def retrieve_context(
        self, query: str, user_id: int, preferences: AIUserPreference
    ) -> RAGContext:
        """Retrieve RAG context based on user query and enabled sources."""
        keywords = self._extract_keywords(query)
        if not keywords:
            return RAGContext()

        # Skip RAG for very short queries — keywords under 3 chars match too
        # broadly (e.g. "hi" matches "high", "this", "phishing", etc.)
        keywords = [k for k in keywords if len(k) >= 3]
        if not keywords:
            return RAGContext()

        limit = min(max(preferences.max_context_snippets, 1), 5)

        # Two independently ordered rankings. Fusing them by rank means the
        # keyword score (title hits worth 10, content hits 3) and the cosine
        # similarity never have to be made comparable to each other.
        ranked_lists: List[List[ContextSnippet]] = []

        keyword_hits: List[ContextSnippet] = []
        if preferences.rag_knowledge_base:
            keyword_hits.extend(self._search_knowledge_base(keywords, limit))
        if preferences.rag_user_notes:
            keyword_hits.extend(self._search_user_notes(keywords, user_id, limit))
        if preferences.rag_playbooks:
            keyword_hits.extend(self._search_playbooks(keywords, limit))
        if keyword_hits:
            keyword_hits.sort(key=lambda s: s.score, reverse=True)
            ranked_lists.append(keyword_hits)

        # Embed the whole question, not the extracted keywords -- discarding the
        # stop words discards the phrasing the embedding exists to capture.
        embedded = self._embed_query(query)
        if embedded is not None:
            vec, model_tag = embedded
            vector_hits: List[ContextSnippet] = []
            if preferences.rag_knowledge_base:
                vector_hits.extend(self._vector_search_kb(vec, model_tag, limit))
            if preferences.rag_playbooks:
                vector_hits.extend(
                    self._vector_search_playbooks(vec, model_tag, limit)
                )
            if vector_hits:
                vector_hits.sort(key=lambda s: s.score, reverse=True)
                ranked_lists.append(vector_hits)

        selected = self._fuse(ranked_lists, limit)

        # Enforce total char budget
        final = []
        total_chars = 0
        for s in selected:
            if total_chars + len(s.snippet) > MAX_TOTAL_CONTEXT_CHARS:
                remaining = MAX_TOTAL_CONTEXT_CHARS - total_chars
                if remaining > 100:
                    s.snippet = s.snippet[:remaining] + "..."
                    final.append(s)
                break
            final.append(s)
            total_chars += len(s.snippet)

        return RAGContext(snippets=final)

    def _search_knowledge_base(
        self, keywords: List[str], limit: int
    ) -> List[ContextSnippet]:
        """Search Document table by name/content. Title matches prioritized."""
        try:
            # First pass: title matches (high signal)
            title_filters = []
            for kw in keywords:
                title_filters.append(Document.name.ilike(f"%{kw}%"))

            title_docs = (
                self.db.query(Document)
                .filter(or_(*title_filters))
                .filter(Document.status == "active")
                .limit(20)
                .all()
            )

            # Second pass: content matches (broader, more noise)
            content_filters = []
            for kw in keywords:
                content_filters.append(Document.rendered_content.ilike(f"%{kw}%"))

            seen_ids = {d.id for d in title_docs}
            content_docs = (
                self.db.query(Document)
                .filter(or_(*content_filters))
                .filter(Document.status == "active")
                .filter(~Document.id.in_(seen_ids) if seen_ids else True)
                .limit(30)
                .all()
            )

            docs = title_docs + content_docs

            snippets = []
            for doc in docs:
                plain = self._html_to_plain(doc.rendered_content or "")
                score = self._score_document(doc.name, plain, keywords)
                snippet_text = self._extract_relevant_snippet(plain, keywords)
                snippets.append(ContextSnippet(
                    source_type="knowledge_base",
                    source_id=doc.id,
                    title=doc.name,
                    snippet=snippet_text,
                    score=score,
                ))
            return snippets
        except Exception as e:
            logger.error("KB search failed: %s", e)
            return []

    def _search_user_notes(
        self, keywords: List[str], user_id: int, limit: int
    ) -> List[ContextSnippet]:
        """Search AnalystNote by title/content (all users)."""
        try:
            filters = []
            for kw in keywords:
                pattern = f"%{kw}%"
                filters.append(AnalystNote.title.ilike(pattern))
                filters.append(AnalystNote.content_html.ilike(pattern))

            notes = (
                self.db.query(AnalystNote)
                .filter(or_(*filters))
                .limit(30)
                .all()
            )

            snippets = []
            for note in notes:
                plain = self._html_to_plain(note.content_html or note.content or "")
                score = self._score_document(note.title or "", plain, keywords)
                snippet_text = self._extract_relevant_snippet(plain, keywords)
                snippets.append(ContextSnippet(
                    source_type="user_note",
                    source_id=note.id,
                    title=note.title or "Untitled Note",
                    snippet=snippet_text,
                    score=score,
                ))
            return snippets
        except Exception as e:
            logger.error("Notes search failed: %s", e)
            return []

    def _search_playbooks(
        self, keywords: List[str], limit: int
    ) -> List[ContextSnippet]:
        """Search Playbook by name/description."""
        try:
            filters = []
            for kw in keywords:
                pattern = f"%{kw}%"
                filters.append(Playbook.name.ilike(pattern))
                filters.append(Playbook.description.ilike(pattern))

            playbooks = (
                self.db.query(Playbook)
                .filter(or_(*filters))
                .limit(30)
                .all()
            )

            snippets = []
            for pb in playbooks:
                desc = pb.description or ""
                score = self._score_document(pb.name, desc, keywords)
                snippet_text = desc[:MAX_SNIPPET_CHARS]
                if len(desc) > MAX_SNIPPET_CHARS:
                    snippet_text += "..."
                snippets.append(ContextSnippet(
                    source_type="playbook",
                    source_id=pb.id,
                    title=pb.name,
                    snippet=snippet_text,
                    score=score,
                ))
            return snippets
        except Exception as e:
            logger.error("Playbook search failed: %s", e)
            return []

    # ── Vector half ──────────────────────────────────────────────────────────

    def _embed_query(self, query: str) -> Optional[Tuple[List[float], str]]:
        """Embed the query, returning it with the model tag it was embedded under.

        The tag travels with the vector because a stored vector is only
        comparable to one produced by the same model and task-prefix regime, and
        changing either re-embeds the corpus in the background -- so the table
        holds both tags for as long as that takes.

        Every unavailability -- flag off, embeddings disabled, Ollama
        unreachable, model missing -- returns None rather than raising, so an
        air-gapped deploy retrieves exactly what it did before.
        """
        if not _chat_vector_rag_enabled():
            return None
        try:
            from ion.services.embedding_service import get_embedding_service

            svc = get_embedding_service()
            if not svc.is_enabled:
                return None
            vec = svc.embed(query, mode="query")
            if vec is None:
                return None
            return vec, svc.model_tag
        except Exception as exc:
            logger.debug("chat vector RAG: no embedding (%s)", exc)
            return None

    def _vector_search_kb(
        self, vec: List[float], model_tag: str, k: int
    ) -> List[ContextSnippet]:
        """Nearest KB chunks, deduped back to one snippet per document.

        The stored chunk is the snippet: it is the passage that actually matched,
        which is strictly better context than a window cut around a keyword.
        """
        try:
            from ion.models.kb_document_embedding import KBChunkEmbedding

            distance = KBChunkEmbedding.embedding.cosine_distance(vec)
            rows = (
                self.db.query(
                    Document, KBChunkEmbedding.chunk_text, distance.label("distance")
                )
                .join(KBChunkEmbedding, KBChunkEmbedding.document_id == Document.id)
                .filter(Document.status == "active")
                .filter(KBChunkEmbedding.model_name == model_tag)
                .order_by(distance.asc())
                # Over-fetch: several of the best chunks often share a document.
                .limit(max(1, int(k)) * 4)
                .all()
            )
        except Exception as exc:
            # No pgvector (SQLite dev/test), no table yet, or nothing embedded.
            logger.debug("chat vector RAG: KB query unavailable (%s)", exc)
            return []

        out: List[ContextSnippet] = []
        seen: set = set()
        for doc, chunk_text, dist in rows:
            similarity = 1.0 - float(dist)
            if similarity < MIN_VECTOR_SIMILARITY:
                break  # distance-ordered, so everything after is worse
            if doc.id in seen:
                continue
            seen.add(doc.id)
            out.append(
                ContextSnippet(
                    source_type="knowledge_base",
                    source_id=doc.id,
                    title=doc.name,
                    snippet=(chunk_text or "")[:MAX_SNIPPET_CHARS],
                    score=similarity,
                )
            )
            if len(out) >= max(1, int(k)):
                break
        return out

    def _vector_search_playbooks(
        self, vec: List[float], model_tag: str, k: int
    ) -> List[ContextSnippet]:
        """Nearest playbooks. Embedded whole, so there is no chunk to return."""
        try:
            from ion.models.playbook_embedding import PlaybookEmbedding

            distance = PlaybookEmbedding.embedding.cosine_distance(vec)
            rows = (
                self.db.query(Playbook, distance.label("distance"))
                .join(PlaybookEmbedding, PlaybookEmbedding.playbook_id == Playbook.id)
                .filter(Playbook.is_active.is_(True))
                .filter(PlaybookEmbedding.model_name == model_tag)
                .order_by(distance.asc())
                .limit(max(1, int(k)))
                .all()
            )
        except Exception as exc:
            logger.debug("chat vector RAG: playbook query unavailable (%s)", exc)
            return []

        out: List[ContextSnippet] = []
        for pb, dist in rows:
            similarity = 1.0 - float(dist)
            if similarity < MIN_VECTOR_SIMILARITY:
                break
            desc = pb.description or ""
            snippet_text = desc[:MAX_SNIPPET_CHARS]
            if len(desc) > MAX_SNIPPET_CHARS:
                snippet_text += "..."
            out.append(
                ContextSnippet(
                    source_type="playbook",
                    source_id=pb.id,
                    title=pb.name,
                    snippet=snippet_text,
                    score=similarity,
                )
            )
        return out

    @staticmethod
    def _fuse(
        ranked_lists: List[List[ContextSnippet]], limit: int
    ) -> List[ContextSnippet]:
        """Reciprocal Rank Fusion over the supplied rankings.

        A document found by both retrievers accumulates both contributions and
        outranks one found by either alone, which is the property we want: the
        two disagree often, and agreement is the strongest signal available.
        """
        scores: Dict[Tuple[str, int], float] = {}
        best: Dict[Tuple[str, int], Tuple[int, ContextSnippet]] = {}

        for snippets in ranked_lists:
            for rank, snippet in enumerate(snippets):
                key = (snippet.source_type, snippet.source_id)
                scores[key] = scores.get(key, 0.0) + 1.0 / (RRF_K + rank + 1)
                # Keep the copy from whichever ranking placed it highest, so the
                # snippet comes from the retriever that was most confident about
                # it -- the matching chunk when vector search led, the window
                # around the literal term when substring matching did.
                if key not in best or rank < best[key][0]:
                    best[key] = (rank, snippet)

        ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        out: List[ContextSnippet] = []
        for key, score in ordered[:limit]:
            snippet = best[key][1]
            snippet.score = score
            out.append(snippet)
        return out

    @staticmethod
    def _extract_keywords(query: str) -> List[str]:
        """Tokenize query, remove stop words, return top keywords."""
        words = re.findall(r"[a-zA-Z0-9_\-\.]{2,}", query.lower())
        filtered = [w for w in words if w not in STOP_WORDS]
        # Deduplicate preserving order
        seen = set()
        unique = []
        for w in filtered:
            if w not in seen:
                seen.add(w)
                unique.append(w)
        return unique[:8]

    @staticmethod
    def _score_document(title: str, content: str, keywords: List[str]) -> float:
        """Simple relevance scoring: title match = 10pts, content match = 3pts."""
        score = 0.0
        title_lower = title.lower()
        content_lower = content.lower()
        for kw in keywords:
            if kw in title_lower:
                score += 10.0
            if kw in content_lower:
                score += 3.0
        return score

    @staticmethod
    def _html_to_plain(html: str) -> str:
        """Strip HTML tags via regex."""
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _extract_relevant_snippet(
        text: str, keywords: List[str], window: int = 400
    ) -> str:
        """Find the highest-density keyword window in text."""
        if len(text) <= MAX_SNIPPET_CHARS:
            return text

        text_lower = text.lower()
        best_start = 0
        best_score = 0

        # Slide a window across the text
        step = 50
        for start in range(0, max(1, len(text) - window), step):
            segment = text_lower[start : start + window]
            score = sum(segment.count(kw) for kw in keywords)
            if score > best_score:
                best_score = score
                best_start = start

        snippet = text[best_start : best_start + MAX_SNIPPET_CHARS]
        # Clean up start/end on word boundaries
        if best_start > 0:
            first_space = snippet.find(" ")
            if first_space > 0 and first_space < 30:
                snippet = "..." + snippet[first_space + 1 :]
        if best_start + MAX_SNIPPET_CHARS < len(text):
            last_space = snippet.rfind(" ")
            if last_space > len(snippet) - 30:
                snippet = snippet[:last_space] + "..."

        return snippet
