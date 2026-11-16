"""What Bob and the chat can retrieve: the whole document store, and only the
asker's own notes."""

from sqlalchemy import create_engine, text

from ion.models.analyst_note import AnalystNote
from ion.models.base import Base
from ion.models.document import Document
from ion.models.kb_document_embedding import KBChunkEmbedding
from ion.models.template import Collection
from ion.models.user import User
from ion.services import kb_embedding_service as kbe
from ion.services.ai_context_service import AIContextService
from ion.storage.database import _run_migrations


class _StubEmbed:
    is_enabled = True
    model_tag = "stub+tp1"
    model = "stub"

    def embed(self, text, mode="document"):
        return [0.1] * 768


def _user(session, name):
    u = User(username=name, email=f"{name}@x.test", password_hash="x")
    session.add(u)
    session.commit()
    return u


def _embedded_ids(session):
    return {r[0] for r in session.query(KBChunkEmbedding.document_id).distinct()}


def test_chat_quotes_only_the_askers_own_notes(session):
    alice, bob = _user(session, "alice"), _user(session, "bobby")
    session.add_all([
        AnalystNote(user_id=alice.id, title="phishing triage", content_html="alice phishing steps"),
        AnalystNote(user_id=bob.id, title="phishing private", content_html="bobby phishing secrets"),
    ])
    session.commit()
    hits = AIContextService(session)._search_user_notes(["phishing"], alice.id, 5)
    assert [h.title for h in hits] == ["phishing triage"]


def test_new_preferences_have_every_source_on(session):
    u = _user(session, "carol")
    prefs = AIContextService(session).get_user_preferences(u.id)
    assert (prefs.rag_knowledge_base, prefs.rag_playbooks, prefs.rag_user_notes) == (True, True, True)


def test_documents_outside_the_kb_folder_are_embedded(session, monkeypatch):
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: _StubEmbed())
    folder = Collection(name="Runbooks", parent_id=None)
    session.add(folder)
    session.commit()
    in_folder = Document(name="Runbook", collection_id=folder.id, rendered_content="steps", status="active")
    loose = Document(name="Loose doc", rendered_content="notes", status="active")
    archived = Document(name="Old", rendered_content="gone", status="archived")
    session.add_all([in_folder, loose, archived])
    session.commit()

    kbe.run_kb_embedding_once(session)
    assert _embedded_ids(session) == {in_folder.id, loose.id}


def test_every_document_is_reached_however_many_there_are(session, monkeypatch):
    # The old fixed window (newest 160) never reached document 1 of 300.
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: _StubEmbed())
    monkeypatch.setenv("ION_KB_EMBEDDING_BATCH", "40")
    session.add_all(Document(name=f"d{i}", rendered_content=f"body {i}", status="active") for i in range(300))
    session.commit()

    for _ in range(10):
        kbe.run_kb_embedding_once(session)
    assert len(_embedded_ids(session)) == 300


def test_an_empty_document_does_not_hide_edits(session, monkeypatch):
    monkeypatch.setattr(kbe, "get_embedding_service", lambda: _StubEmbed())
    doc = Document(name="edited", rendered_content="first", status="active")
    session.add_all([doc, Document(name="blank", rendered_content="   ", status="active")])
    session.commit()
    kbe.run_kb_embedding_once(session)

    doc.rendered_content = "second"
    session.commit()
    kbe.run_kb_embedding_once(session)
    chunk = session.query(KBChunkEmbedding).filter_by(document_id=doc.id).one()
    assert chunk.chunk_text == "second"


def test_existing_users_get_sources_switched_on_once(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE ai_user_preferences DROP COLUMN rag_defaults_version"))
        conn.execute(text(
            "INSERT INTO ai_user_preferences (user_id, rag_knowledge_base, rag_user_notes, "
            "rag_playbooks, show_citations, max_context_snippets) VALUES (1, 0, 0, 0, 1, 3)"
        ))

    _run_migrations(engine)
    row = lambda: engine.connect().execute(text(
        "SELECT rag_knowledge_base, rag_playbooks, rag_user_notes, rag_defaults_version "
        "FROM ai_user_preferences")).one()
    assert tuple(row()) == (1, 1, 1, 1)

    with engine.begin() as conn:
        conn.execute(text("UPDATE ai_user_preferences SET rag_user_notes = 0"))
    _run_migrations(engine)
    assert row()[2] == 0


def test_chat_never_quotes_documents_the_asker_cannot_open(session, monkeypatch):
    u = _user(session, "dave")
    session.add(Document(name="Kerberos runbook", rendered_content="kerberos ticket steps", status="active"))
    session.commit()
    svc = AIContextService(session)
    monkeypatch.setattr(svc, "_embed_query", lambda q: None)
    prefs = svc.get_user_preferences(u.id)

    allowed = svc.retrieve_context("kerberos ticket", u.id, prefs, may_read_documents=True, may_read_playbooks=True)
    denied = svc.retrieve_context("kerberos ticket", u.id, prefs, may_read_documents=False, may_read_playbooks=False)
    assert [s.title for s in allowed.snippets] == ["Kerberos runbook"]
    assert denied.snippets == []
