"""RuleInvestigationTemplate service — build, persist, review.

Covers the LLM-independent half of Bob custom templates: rule-field extraction,
the injection-safe prompt, the pending-review upsert, and approve/reject.
"""

from ion.models.rule_investigation_template import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
)
from ion.services.rule_template_service import (
    build_generation_prompt,
    get_template,
    list_pending,
    rule_fields_from_raw,
    set_status,
    upsert_generated,
)


def test_rule_fields_from_raw_flattened_and_nested():
    flat = rule_fields_from_raw(
        {
            "kibana.alert.rule.name": "Encoded PS via Office",
            "kibana.alert.rule.description": "Detects encoded PowerShell.",
            "kibana.alert.rule.note": "1. Decode -enc\n2. Check parent",
        }
    )
    assert flat["rule_name"] == "Encoded PS via Office"
    assert "encoded PowerShell" in flat["rule_description"]
    assert "Decode" in flat["authored_guide"]

    nested = rule_fields_from_raw(
        {"kibana": {"alert": {"rule": {"name": "Nested Rule", "note": "step one"}}}}
    )
    assert nested["rule_name"] == "Nested Rule"
    assert nested["authored_guide"] == "step one"


def test_generation_prompt_fences_untrusted_input():
    system, user = build_generation_prompt(
        "RuleX",
        "desc",
        "authored guide text",
        "[E1] (observable) 10.0.0.5",
    )
    assert "INVESTIGATION CHECKLIST" in system
    # untrusted rule/alert text is wrapped by prompt_safety, not inlined bare
    assert "authored guide text" in user
    assert "10.0.0.5" in user
    # the wrap_untrusted fence marker is present
    assert "untrusted" in user.lower() or "```" in user or "<" in user


def test_upsert_is_pending_and_regenerates_in_place(session):
    row = upsert_generated(
        session, rule_id="RuleX", rule_name="RuleX",
        checklist_text="1. do a thing", model="llama", evidence_ids=["E1", "E2"],
    )
    assert row.status == STATUS_PENDING
    assert get_template(session, "RuleX").checklist_text == "1. do a thing"

    # regenerate -> same row, reset to pending, review cleared
    row2 = upsert_generated(
        session, rule_id="RuleX", rule_name="RuleX",
        checklist_text="1. do a better thing", model="llama",
    )
    assert row2.id == row.id
    assert row2.status == STATUS_PENDING
    assert row2.reviewed_by_id is None
    assert session.query(type(row)).filter_by(rule_id="RuleX").count() == 1


def test_approve_and_reject_flow(session):
    row = upsert_generated(session, rule_id="RuleX", rule_name="RuleX", checklist_text="x")
    assert len(list_pending(session)) == 1

    approved = set_status(session, row.id, STATUS_APPROVED, user_id=7)
    assert approved.status == STATUS_APPROVED
    assert approved.reviewed_by_id == 7
    assert approved.reviewed_at is not None
    assert list_pending(session) == []

    rejected = set_status(session, row.id, STATUS_REJECTED, user_id=7)
    assert rejected.status == STATUS_REJECTED

    # an invalid status is refused
    assert set_status(session, row.id, "pending_review", user_id=7) is None
