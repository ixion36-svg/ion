"""AI context service — RAG retrieval from KB, notes, and playbooks."""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from sqlalchemy.orm import Session
from sqlalchemy import or_

from ion.models.ai_preferences import AIUserPreference
from ion.models.document import Document
from ion.models.analyst_note import AnalystNote
from ion.models.playbook import Playbook

logger = logging.getLogger(__name__)

MAX_SNIPPET_CHARS = 800
MAX_TOTAL_CONTEXT_CHARS = 3000

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
        lines.append("Cite sources by type and title when using reference context.")
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

        limit = min(max(preferences.max_context_snippets, 1), 5)
        all_snippets: List[ContextSnippet] = []

        if preferences.rag_knowledge_base:
            all_snippets.extend(self._search_knowledge_base(keywords, limit))

        if preferences.rag_user_notes:
            all_snippets.extend(self._search_user_notes(keywords, user_id, limit))

        if preferences.rag_playbooks:
            all_snippets.extend(self._search_playbooks(keywords, limit))

        # Sort by score descending, take top N
        all_snippets.sort(key=lambda s: s.score, reverse=True)
        selected = all_snippets[:limit]

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
