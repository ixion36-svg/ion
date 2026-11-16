"""Unit tests for cyab_scoping_engine — question loader + scoring."""

import pytest


def test_load_questions_returns_nonempty_ordered_list():
    from ion.services import cyab_scoping_engine as svc
    qs = svc.load_questions()
    assert isinstance(qs, list)
    assert 12 <= len(qs) <= 20  # spec range
    # Order is stable (used by progressive disclosure)
    qs2 = svc.load_questions()
    assert [q["id"] for q in qs] == [q["id"] for q in qs2]


def test_each_question_has_required_keys():
    from ion.services import cyab_scoping_engine as svc
    for q in svc.load_questions():
        assert "id" in q and isinstance(q["id"], str)
        assert "text" in q and q["text"]
        assert "type" in q and q["type"] in ("choice", "multi", "text")
        if q["type"] in ("choice", "multi"):
            assert "options" in q and isinstance(q["options"], list)
            for opt in q["options"]:
                assert "value" in opt and "label" in opt


def test_question_set_covers_six_stack_dimensions():
    """Spec calls out: identity provider, endpoint platform, cloud,
    email/collab, network edge, compliance regime."""
    from ion.services import cyab_scoping_engine as svc
    ids = {q["id"] for q in svc.load_questions()}
    expected_dimensions = {
        "stack_identity",
        "stack_endpoint_os",
        "stack_cloud",
        "stack_email",
        "stack_network_edge",
        "compliance_regime",
    }
    missing = expected_dimensions - ids
    assert not missing, f"Question set missing dimensions: {missing}"


def test_score_answers_empty_returns_zeroed_shape():
    from ion.services import cyab_scoping_engine as svc
    out = svc.score_answers({})
    assert out["use_case_count"] == 0
    assert out["threat_actor_matches"] == 0
    assert out["mitre_coverage_pct"] == 0
    assert out["recommended_use_cases"] == []
    assert out["recommended_threat_actors"] == []


def test_score_answers_with_finance_sector_recommends_use_cases(monkeypatch):
    """Finance + ransomware concern → at least one ransomware use case ranked."""
    from ion.services import cyab_scoping_engine as svc

    fake_playbooks = [
        {"id": 1, "name": "Ransomware encryption detection",
         "description": "Detect mass file encryption via shadow copy deletion."},
        {"id": 2, "name": "Generic process injection",
         "description": "Detect process injection chains."},
        {"id": 3, "name": "BEC vendor invoice fraud",
         "description": "Detect business email compromise via vendor impersonation."},
    ]
    monkeypatch.setattr(
        "ion.services.tide_service.get_playbooks_with_kill_chains",
        lambda *_a, **_k: fake_playbooks,
    )

    out = svc.score_answers({
        "org_sector": "finance",
        "concern_top": ["ransomware"],
        "stack_endpoint_os": ["windows"],
        "stack_identity": "entra",
    })

    assert out["use_case_count"] >= 1
    assert out["threat_actor_matches"] >= 1
    assert isinstance(out["recommended_threat_actors"], list)
    assert isinstance(out["recommended_use_cases"], list)
    # MITRE % should be 0..100 inclusive
    assert 0 <= out["mitre_coverage_pct"] <= 100


def test_summary_text_is_human_readable():
    from ion.services import cyab_scoping_engine as svc
    text = svc.summary_text({
        "use_case_count": 47,
        "threat_actor_matches": 12,
        "mitre_coverage_pct": 64,
    })
    # Exactly the live-counter format the spec calls out
    assert "47" in text and "12" in text and "64" in text
    assert "use case" in text.lower()
    assert "%" in text


def test_mitre_coverage_pct_independent_of_playbook_count(monkeypatch):
    """MITRE % is computed from the *named techniques* in matched playbooks,
    not from raw ranked count — a single high-coverage playbook can raise it."""
    from ion.services import cyab_scoping_engine as svc

    one_pb_with_many_techniques = [{
        "id": 1, "name": "Initial access multi-vector",
        "description": "Phishing, exploit-public-facing, supply-chain, valid accounts.",
    }]
    monkeypatch.setattr(
        "ion.services.tide_service.get_playbooks_with_kill_chains",
        lambda *_a, **_k: one_pb_with_many_techniques,
    )
    out = svc.score_answers({"org_sector": "tech", "concern_top": ["phishing"]})
    assert out["mitre_coverage_pct"] > 0
