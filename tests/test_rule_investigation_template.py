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


def _generated(session, text="1. Check the parent process"):
    return upsert_generated(
        session, rule_id="RuleX", rule_name="RuleX",
        checklist_text=text, model="llama", evidence_ids=["E1"],
    )


def test_an_edit_replaces_the_text_and_records_who_made_it(session):
    from ion.services.rule_template_service import edit_text

    row = _generated(session)

    edited = edit_text(session, row.id, "1. Check the parent process\n2. Pull the PCAP", user_id=7)

    assert get_template(session, "RuleX").checklist_text.endswith("2. Pull the PCAP")
    assert edited.edited_by_id == 7
    assert edited.edited_at is not None
    assert edited.to_dict()["edited_by_id"] == 7


def test_an_edited_guide_has_to_be_approved_again(session):
    from ion.services.rule_template_service import edit_text

    row = _generated(session)
    set_status(session, row.id, STATUS_APPROVED, user_id=3)

    edited = edit_text(session, row.id, "1. Something nobody has reviewed", user_id=7)

    assert edited.status == STATUS_PENDING
    assert edited.reviewed_by_id is None
    assert edited.reviewed_at is None


def test_editing_a_guide_that_does_not_exist_changes_nothing(session):
    from ion.services.rule_template_service import edit_text

    assert edit_text(session, 999, "text", user_id=7) is None


def test_regenerating_is_bobs_text_again_not_an_edit(session):
    from ion.services.rule_template_service import edit_text

    row = _generated(session)
    edit_text(session, row.id, "a person's wording", user_id=7)

    regenerated = _generated(session, text="1. Bob's new draft")

    assert regenerated.checklist_text == "1. Bob's new draft"
    assert regenerated.edited_by_id is None
    assert regenerated.edited_at is None


class _Editor:
    id = 7
    username = "analyst"


def test_the_route_saves_the_edit_and_writes_it_to_the_audit_log(session):
    from ion.models.user import AuditLog
    from ion.web.rule_template_api import GuideEdit, edit_rule_template

    row = _generated(session)

    out = edit_rule_template(
        row.id, GuideEdit(checklist_text="  1. Edited by a person  "),
        user=_Editor(), session=session)

    assert out["template"]["checklist_text"] == "1. Edited by a person"
    logged = session.query(AuditLog).filter_by(action="rule_guide_edited").one()
    assert logged.user_id == 7
    assert logged.resource_id == row.id


def test_the_route_refuses_an_empty_guide():
    import pytest
    from pydantic import ValidationError

    from ion.web.rule_template_api import GuideEdit

    with pytest.raises(ValidationError):
        GuideEdit(checklist_text="   \n ")


def test_the_route_answers_404_for_a_guide_that_is_gone(session):
    import pytest
    from fastapi import HTTPException

    from ion.web.rule_template_api import GuideEdit, edit_rule_template

    with pytest.raises(HTTPException) as missing:
        edit_rule_template(999, GuideEdit(checklist_text="text"),
                           user=_Editor(), session=session)

    assert missing.value.status_code == 404


def test_an_existing_database_gains_the_edit_columns(tmp_path):
    from sqlalchemy import create_engine, inspect, text

    from ion.models.document import Base
    from ion.storage.database import _run_migrations

    engine = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE rule_investigation_templates"))
        conn.execute(text(
            "CREATE TABLE rule_investigation_templates ("
            "id INTEGER PRIMARY KEY, rule_id VARCHAR(512) NOT NULL UNIQUE, "
            "checklist_text TEXT NOT NULL, status VARCHAR(20) NOT NULL)"))

    _run_migrations(engine)

    columns = {c["name"] for c in inspect(engine).get_columns("rule_investigation_templates")}
    assert {"edited_by_id", "edited_at"} <= columns
