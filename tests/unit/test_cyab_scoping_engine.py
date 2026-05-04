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
