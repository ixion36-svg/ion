"""v0.53.0 — TI-report RAG: local OpenCTI report cache + chunk embeddings
+ a 5th budget-gated prompt layer.

OpenCTI report bodies were never stored locally (every view was a live
GraphQL fetch), so there was nothing for Bob's RAG to retrieve and no
offline value. This release adds:

1. ``TIReport`` — a local cache of recent reports (metadata + bounded
   body), upserted by ``ti_report_service.run_ti_report_sync_once`` keyed
   on the OpenCTI id.
2. ``TIReportChunkEmbedding`` — chunk-level vectors over the cached body
   (same discipline as the v0.51.0 KB corpus: atomic per-report replace,
   whole-report staleness hash with scheme marker, chunk-counted batches).
3. A "Threat Intelligence Context" prompt layer at priority 4 of 5
   (skills is now 5); gate ``ION_TI_REPORT_RAG_ENABLED`` default ON.
"""

from ion.models.ti_report import (
    MAX_REPORT_BODY_CHARS,
    TIReport,
    TIReportChunkEmbedding,
)
from ion.services import ti_report_service as tis
from ion.services.alert_prompt_service import (
    _format_ti_report_context_for_prompt,
    _ti_report_rag_enabled,
)


class _StubEmbed:
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


class _StubOpenCTI:
    def __init__(self, reports, configured=True):
        self._reports = reports
        self.is_configured = configured

    async def fetch_recent_reports(self, limit=100):
        return self._reports[:limit]


def _fetched(**over):
    base = {
        "opencti_id": "report--abc",
        "name": "APT29 spearphishing campaign",
        "published": "2026-07-01T00:00:00Z",
        "report_types": ["threat-report"],
        "confidence": 80,
        "source": "CTI Team",
        "labels": ["apt29", "phishing"],
        "body": "Campaign details.\n\nSecond paragraph of tradecraft.",
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Sync phase
# ---------------------------------------------------------------------------

def test_sync_creates_updates_and_skips_unchanged(session, monkeypatch):
    stub = _StubOpenCTI([_fetched()])
    monkeypatch.setattr(
        "ion.services.opencti_service.get_opencti_service", lambda: stub
    )
    out = tis.run_ti_report_sync_once(session)
    assert out["created"] == 1
    row = session.query(TIReport).one()
    assert row.opencti_id == "report--abc"
    assert row.name == "APT29 spearphishing campaign"
    assert row.labels == ["apt29", "phishing"]
    assert "Second paragraph" in row.content

    # Unchanged fetch → no churn.
    out2 = tis.run_ti_report_sync_once(session)
    assert out2["created"] == 0 and out2["updated"] == 0
    assert out2["unchanged"] == 1

    # Edited upstream → updated in place, same row.
    stub._reports = [_fetched(body="Rewritten body.")]
    out3 = tis.run_ti_report_sync_once(session)
    assert out3["updated"] == 1
    assert session.query(TIReport).count() == 1
    assert session.query(TIReport).one().content == "Rewritten body."


def test_sync_clips_oversized_bodies(session, monkeypatch):
    stub = _StubOpenCTI([_fetched(body="x" * (MAX_REPORT_BODY_CHARS + 5000))])
    monkeypatch.setattr(
        "ion.services.opencti_service.get_opencti_service", lambda: stub
    )
    tis.run_ti_report_sync_once(session)
    assert len(session.query(TIReport).one().content) == MAX_REPORT_BODY_CHARS


def test_sync_noops_when_opencti_unconfigured(session, monkeypatch):
    stub = _StubOpenCTI([], configured=False)
    monkeypatch.setattr(
        "ion.services.opencti_service.get_opencti_service", lambda: stub
    )
    out = tis.run_ti_report_sync_once(session)
    assert out == {"synced": 0, "opencti_unconfigured": True}


# ---------------------------------------------------------------------------
# Embed phase
# ---------------------------------------------------------------------------

def _cached_report(session, **over):
    from datetime import datetime, timezone
    vals = dict(
        opencti_id="report--emb",
        name="Cached report",
        labels=["apt"],
        content=("a" * 1500) + "\n\n" + ("b" * 1500),
        fetched_at=datetime.now(timezone.utc),
    )
    vals.update(over)
    row = TIReport(**vals)
    session.add(row)
    session.commit()
    return row


def _chunks(session, rid):
    return (
        session.query(TIReportChunkEmbedding)
        .filter(TIReportChunkEmbedding.report_id == rid)
        .order_by(TIReportChunkEmbedding.chunk_index)
        .all()
    )


def test_embed_writes_chunks_and_skips_fresh(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(tis, "get_embedding_service", lambda: stub)
    rep = _cached_report(session)

    out = tis.run_ti_report_embedding_once(session)
    assert out["embedded"] == 1 and out["chunks"] == 2
    rows = _chunks(session, rep.id)
    assert [r.chunk_index for r in rows] == [0, 1]
    assert rows[0].source_text_hash == rows[1].source_text_hash

    out2 = tis.run_ti_report_embedding_once(session)
    assert out2["embedded"] == 0 and out2["skipped_fresh"] == 1


def test_embed_re_embeds_on_content_change_and_shrinks(session, monkeypatch):
    stub = _StubEmbed()
    monkeypatch.setattr(tis, "get_embedding_service", lambda: stub)
    rep = _cached_report(session, opencti_id="report--shrink")
    tis.run_ti_report_embedding_once(session)
    assert len(_chunks(session, rep.id)) == 2

    rep.content = "short now"
    session.commit()
    out = tis.run_ti_report_embedding_once(session)
    assert out["embedded"] == 1
    rows = _chunks(session, rep.id)
    assert len(rows) == 1 and rows[0].chunk_text == "short now"


def test_embed_never_writes_partial_chunk_sets(session, monkeypatch):
    stub = _StubEmbed(fail_after=1)
    monkeypatch.setattr(tis, "get_embedding_service", lambda: stub)
    rep = _cached_report(session, opencti_id="report--fail")
    out = tis.run_ti_report_embedding_once(session)
    assert out["embedded"] == 0 and out["failed"] == 1
    assert _chunks(session, rep.id) == []


def test_embed_source_text_carries_title_and_labels(session):
    rep = TIReport(
        opencti_id="x", name="Emotet resurgence", labels=["emotet", "loader"],
        content="body", fetched_at=__import__("datetime").datetime.now(),
    )
    text = tis._report_source_text(rep, "chunk text here")
    assert text.startswith("Report: Emotet resurgence\n")
    assert "Labels: emotet, loader" in text
    assert "Content: chunk text here" in text


# ---------------------------------------------------------------------------
# Prompt layer
# ---------------------------------------------------------------------------

def test_gate_defaults_on_and_disables(monkeypatch):
    assert _ti_report_rag_enabled() is True
    monkeypatch.setenv("ION_TI_REPORT_RAG_ENABLED", "false")
    assert _ti_report_rag_enabled() is False


def test_formatter_frames_as_background_not_evidence():
    assert _format_ti_report_context_for_prompt([]) == ""
    block = _format_ti_report_context_for_prompt([{
        "name": "APT29 spearphishing campaign",
        "published": "2026-07-01",
        "source": "CTI Team",
        "excerpt": "Campaign details about tradecraft.",
        "similarity": 0.82,
    }])
    assert "## Threat Intelligence Context" in block
    assert "NOT evidence about this specific alert" in block
    assert "APT29 spearphishing campaign (2026-07-01 · CTI Team) (similarity 0.82)" in block
    assert "Campaign details about tradecraft." in block


def test_layer_order_ti_reports_between_playbooks_and_skills():
    import inspect

    from ion.services import alert_prompt_service as aps
    # the layer injection moved from render_system_prompt into the
    # shared build_rag_context_blocks (reused by bob_analysis_api).
    src = inspect.getsource(aps.AlertPromptService.build_rag_context_blocks)
    assert (
        src.index("KB RAG")
        < src.index("Gold exemplars")
        < src.index("Playbook RAG")
        < src.index("TI-report RAG")
        < src.index("Elastic Agent Skills")
    )


def test_retrieval_disabled_paths_return_empty(session, monkeypatch):
    from ion.services.alert_prompt_service import AlertPromptService
    svc = AlertPromptService(session)
    # Gate off.
    monkeypatch.setenv("ION_TI_REPORT_RAG_ENABLED", "false")
    assert svc._get_ti_report_context_for_alert({"rule_name": "r"}) == []
    # Gate on but embedding disabled → graceful empty.
    monkeypatch.setenv("ION_TI_REPORT_RAG_ENABLED", "true")
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    assert svc._get_ti_report_context_for_alert({"rule_name": "r"}) == []
