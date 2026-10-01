"""Tests for comm_template_service — incident notification templates.

This module was at 0% when the coverage ratchet first measured the tree. What
it renders is sent to executives, legal counsel and all staff during an
incident, so the failures that cost something are not crashes: an unsubstituted
``{{record_count}}`` left in a breach notification to legal, a variable
silently dropped to the empty string, or the seeder running twice and giving
every analyst six duplicate templates to choose between.

The 225-line ``DEFAULT_TEMPLATES`` block is data, and data rots quietly — a
placeholder typed with a hyphen renders verbatim rather than failing, so the
integrity tests at the bottom check the catalogue itself, not just the code
that reads it.
"""

from __future__ import annotations

import re

import pytest
from sqlalchemy import func, select

from ion.models.oncall import CommTemplate
from ion.models.user import User
from ion.services import comm_template_service as svc

PLACEHOLDER = re.compile(r"\{\{(\s*\w+\s*)\}\}")
# Mirrors the sets documented on CommTemplate.category / .audience.
CATEGORIES = {"breach_notification", "ransomware", "phishing", "executive_brief",
              "status_update"}
AUDIENCES = {"internal", "executive", "legal", "external", "all_staff"}


@pytest.fixture
def author(session):
    u = User(username="analyst", email="a@example.com", password_hash="x")
    session.add(u)
    session.flush()
    return u


def _template(session, name="Tmpl", *, category="status_update",
              audience="internal", subject="S {{title}}", body="B {{summary}}",
              is_default=False, created_by_id=None):
    t = CommTemplate(name=name, category=category, audience=audience,
                     subject_template=subject, body_template=body,
                     is_default=is_default, created_by_id=created_by_id)
    session.add(t)
    session.flush()
    return t


class TestListing:
    def test_an_empty_table_lists_nothing(self, session):
        assert svc.get_templates(session) == []

    def test_templates_come_back_in_name_order(self, session):
        _template(session, "zulu")
        _template(session, "alpha")

        assert [t["name"] for t in svc.get_templates(session)] == ["alpha", "zulu"]

    def test_a_category_filter_narrows_the_list(self, session):
        _template(session, "ransom", category="ransomware")
        _template(session, "status", category="status_update")

        out = svc.get_templates(session, category="ransomware")

        assert [t["name"] for t in out] == ["ransom"]

    def test_no_category_means_no_filter(self, session):
        """``category=None`` is the API default and must not filter on NULL."""
        _template(session, "ransom", category="ransomware")
        _template(session, "status", category="status_update")

        assert len(svc.get_templates(session, category=None)) == 2

    def test_an_unmatched_category_lists_nothing(self, session):
        _template(session, "status", category="status_update")
        assert svc.get_templates(session, category="phishing") == []


class TestFetch:
    def test_a_known_template_is_returned_in_full(self, session, author):
        t = _template(session, "Brief", category="executive_brief",
                      audience="executive", subject="S", body="B",
                      is_default=True, created_by_id=author.id)

        out = svc.get_template(session, t.id)

        assert out["id"] == t.id
        assert out["name"] == "Brief"
        assert out["category"] == "executive_brief"
        assert out["audience"] == "executive"
        assert out["subject_template"] == "S"
        assert out["body_template"] == "B"
        assert out["is_default"] is True
        assert out["created_by_id"] == author.id

    def test_an_unknown_id_returns_empty_not_an_error(self, session):
        """The API turns a falsy result into a 404, so this must stay falsy."""
        assert svc.get_template(session, 999_999) == {}

    def test_timestamps_are_isoformatted(self, session):
        t = _template(session)
        out = svc.get_template(session, t.id)
        assert out["created_at"] == t.created_at.isoformat()
        assert out["updated_at"] == t.updated_at.isoformat()


class TestCreate:
    def test_a_template_is_persisted_and_returned(self, session, author):
        out = svc.create_template(
            session, name="New", category="phishing",
            subject_template="S", body_template="B", audience="all_staff",
            created_by_id=author.id,
        )

        assert out["id"] is not None
        assert session.get(CommTemplate, out["id"]).name == "New"

    def test_a_created_template_is_not_marked_default(self, session):
        """Only the seeder may claim is_default; analyst templates are theirs."""
        out = svc.create_template(session, name="N", category="phishing",
                                  subject_template="S", body_template="B")
        assert out["is_default"] is False


class TestUpdate:
    def test_known_fields_are_changed(self, session):
        t = _template(session, "Old")

        out = svc.update_template(session, t.id, name="New", audience="legal")

        assert out["name"] == "New"
        assert out["audience"] == "legal"
        assert session.get(CommTemplate, t.id).name == "New"

    def test_an_unknown_field_is_ignored_rather_than_raising(self, session):
        """kwargs come straight off a request body; a stray key must not 500."""
        t = _template(session, "Old")

        out = svc.update_template(session, t.id, nonsense="x", name="New")

        assert out["name"] == "New"
        assert not hasattr(session.get(CommTemplate, t.id), "nonsense")

    def test_updating_an_unknown_template_returns_empty(self, session):
        assert svc.update_template(session, 999_999, name="x") == {}


class TestRender:
    def test_variables_are_substituted(self, session):
        t = _template(session, subject="[ION-{{case_number}}] {{title}}",
                      body="Severity: {{severity}}")

        out = svc.render_template(session, t.id, {
            "case_number": "2026-0042", "title": "Phish", "severity": "high",
        })

        assert out["subject"] == "[ION-2026-0042] Phish"
        assert out["body"] == "Severity: high"

    def test_padded_placeholders_are_substituted_too(self, session):
        t = _template(session, subject="{{ title }}", body="{{  severity  }}")

        out = svc.render_template(session, t.id, {"title": "T", "severity": "low"})

        assert out["subject"] == "T"
        assert out["body"] == "low"

    def test_a_missing_variable_is_left_visible_not_blanked(self, session):
        """A blank field reads as 'no affected systems'. The raw placeholder
        reads as 'nobody filled this in', which is the truth."""
        t = _template(session, subject="S", body="Systems: {{affected_systems}}")

        out = svc.render_template(session, t.id, {})

        assert out["body"] == "Systems: {{affected_systems}}"

    def test_non_string_values_are_coerced(self, session):
        t = _template(session, subject="S", body="Records: {{record_count}}")

        out = svc.render_template(session, t.id, {"record_count": 4200})

        assert out["body"] == "Records: 4200"

    def test_repeated_placeholders_are_all_substituted(self, session):
        t = _template(session, subject="S",
                      body="{{analyst_name}} ... {{analyst_name}}")

        out = svc.render_template(session, t.id, {"analyst_name": "bob"})

        assert out["body"] == "bob ... bob"

    def test_surplus_variables_are_harmless(self, session):
        t = _template(session, subject="S", body="{{title}}")

        out = svc.render_template(session, t.id, {"title": "T", "unused": "x"})

        assert out["body"] == "T"

    def test_the_render_carries_its_routing_metadata(self, session):
        """Audience decides who the text may be sent to, so it travels with it."""
        t = _template(session, "Legal", category="breach_notification",
                      audience="legal")

        out = svc.render_template(session, t.id, {})

        assert out["template_id"] == t.id
        assert out["name"] == "Legal"
        assert out["audience"] == "legal"
        assert out["category"] == "breach_notification"

    def test_an_unknown_template_reports_an_error(self, session):
        assert svc.render_template(session, 999_999, {}) == {
            "error": "Template not found"
        }


class TestSeeding:
    def test_seeding_an_empty_table_inserts_the_whole_catalogue(self, session):
        svc.seed_default_templates(session)

        names = [t["name"] for t in svc.get_templates(session)]
        assert len(names) == len(svc.DEFAULT_TEMPLATES)
        assert set(names) == {d["name"] for d in svc.DEFAULT_TEMPLATES}

    def test_seeded_templates_are_marked_default(self, session):
        svc.seed_default_templates(session)
        assert all(t["is_default"] for t in svc.get_templates(session))

    def test_seeded_templates_have_no_author(self, session):
        svc.seed_default_templates(session)
        assert all(t["created_by_id"] is None for t in svc.get_templates(session))

    def test_seeding_twice_does_not_duplicate(self, session):
        svc.seed_default_templates(session)
        svc.seed_default_templates(session)

        assert len(svc.get_templates(session)) == len(svc.DEFAULT_TEMPLATES)

    def test_any_existing_row_suppresses_seeding_entirely(self, session):
        """The guard counts rows, not names — one analyst template is enough to
        skip the seed, which is why nothing is ever half-seeded."""
        _template(session, "an analyst's own")

        svc.seed_default_templates(session)

        assert [t["name"] for t in svc.get_templates(session)] == [
            "an analyst's own"
        ]


class TestSeedingGate:
    """The opt-in gate on the only path by which rows reach comm_templates.

    There is no seeding endpoint and no UI, so this function decides whether a
    boot writes to the database at all. `enabled=False` is the production
    default, which makes it the branch most worth pinning: a regression there
    would mean six rows appearing in a customer's Postgres on upgrade, which no
    test of the seeder itself would catch.
    """

    def test_disabled_writes_nothing_at_all(self, session):
        inserted = svc.seed_default_templates_if_enabled(session, enabled=False)

        assert inserted == 0
        assert session.execute(
            select(func.count(CommTemplate.id))).scalar() == 0
        assert svc.get_templates(session) == []

    def test_disabled_does_not_even_query_the_table(self, session, monkeypatch):
        """Returns before touching the session, so an unmigrated database on an
        upgrade boot cannot fail here either."""
        def boom(*a, **k):
            raise AssertionError("the disabled gate must not touch the session")

        monkeypatch.setattr(session, "execute", boom)

        assert svc.seed_default_templates_if_enabled(session, enabled=False) == 0

    def test_enabled_on_an_empty_table_seeds_the_catalogue(self, session):
        inserted = svc.seed_default_templates_if_enabled(session, enabled=True)

        assert inserted == len(svc.DEFAULT_TEMPLATES)
        assert len(svc.get_templates(session)) == len(svc.DEFAULT_TEMPLATES)

    def test_enabled_with_rows_already_present_writes_nothing(self, session):
        """A second boot with the flag on. Idempotent, so leaving the flag set
        is safe rather than something an operator has to remember to unset."""
        svc.seed_default_templates_if_enabled(session, enabled=True)

        inserted = svc.seed_default_templates_if_enabled(session, enabled=True)

        assert inserted == 0
        assert len(svc.get_templates(session)) == len(svc.DEFAULT_TEMPLATES)

    def test_enabled_leaves_an_operators_own_template_alone(self, session):
        """The guard counts rows rather than matching names, so turning the flag
        on against a table somebody has already populated by hand is a no-op —
        it does not top up the set."""
        _template(session, "an analyst's own")

        inserted = svc.seed_default_templates_if_enabled(session, enabled=True)

        assert inserted == 0
        assert [t["name"] for t in svc.get_templates(session)] == [
            "an analyst's own"
        ]

    def test_startup_commits_when_it_seeded(self, session):
        """The startup wrapper owns the session lifecycle and the conditional
        commit. A missing commit would discard the seed silently."""
        commits = []
        closed = []

        class _Session:
            def __getattr__(self, name):
                return getattr(session, name)

            def commit(self):
                commits.append(1)
                session.flush()

            def close(self):
                closed.append(1)

        seeded = svc.seed_default_templates_at_startup(
            lambda: _Session(), enabled=True,
        )

        assert seeded == len(svc.DEFAULT_TEMPLATES)
        assert commits == [1]
        assert closed == [1]

    def test_startup_does_not_commit_when_it_seeded_nothing(self, session):
        """An empty transaction on every boot is the cost of committing
        unconditionally, and the disabled path is every boot by default."""
        commits = []
        closed = []

        class _Session:
            def __getattr__(self, name):
                return getattr(session, name)

            def commit(self):
                commits.append(1)

            def close(self):
                closed.append(1)

        seeded = svc.seed_default_templates_at_startup(
            lambda: _Session(), enabled=False,
        )

        assert seeded == 0
        assert commits == []
        assert closed == [1]

    def test_startup_closes_the_session_even_when_seeding_raises(self, session):
        """A leaked connection at boot is worse than a failed seed."""
        closed = []

        class _Session:
            def __getattr__(self, name):
                return getattr(session, name)

            def execute(self, *a, **k):
                raise RuntimeError("database not migrated yet")

            def close(self):
                closed.append(1)

        with pytest.raises(RuntimeError):
            svc.seed_default_templates_at_startup(
                lambda: _Session(), enabled=True,
            )

        assert closed == [1]

    def test_the_flag_defaults_to_off_in_config(self):
        """If this ever defaults to True, every boot writes to production."""
        from ion.core.config import Config

        assert Config().comm_templates_seed is False

    def test_the_seeder_reports_what_it_inserted(self, session):
        """Startup commits only on a non-zero return, so the count is load
        bearing rather than decoration."""
        assert svc.seed_default_templates(session) == len(svc.DEFAULT_TEMPLATES)
        assert svc.seed_default_templates(session) == 0


class TestCatalogueIntegrity:
    """The templates are data. These guard the data, not the code."""

    def test_every_entry_has_the_fields_the_seeder_reads(self):
        for d in svc.DEFAULT_TEMPLATES:
            assert set(d) == {"name", "category", "audience",
                              "subject_template", "body_template"}, d["name"]

    def test_names_are_unique(self):
        names = [d["name"] for d in svc.DEFAULT_TEMPLATES]
        assert len(set(names)) == len(names)

    def test_categories_and_audiences_are_recognised_values(self):
        """A typo here silently breaks the category filter the UI lists by."""
        for d in svc.DEFAULT_TEMPLATES:
            assert d["category"] in CATEGORIES, d["name"]
            assert d["audience"] in AUDIENCES, d["name"]

    def test_subjects_fit_the_column(self):
        """subject_template is String(500); an overlong default would only fail
        at seed time, inside a startup try/except."""
        for d in svc.DEFAULT_TEMPLATES:
            assert len(d["subject_template"]) <= 500, d["name"]

    def test_every_placeholder_is_one_the_renderer_can_substitute(self):
        """``{{case-number}}`` and ``{{case.number}}`` do not match the \\w-only
        pattern, so they would be mailed out to legal verbatim."""
        bad: list[str] = []
        for d in svc.DEFAULT_TEMPLATES:
            for text in (d["subject_template"], d["body_template"]):
                for raw in re.findall(r"\{\{[^}]*\}\}", text):
                    if not PLACEHOLDER.fullmatch(raw):
                        bad.append(f"{d['name']}: {raw}")
        assert not bad, "unsubstitutable placeholders:\n  " + "\n  ".join(bad)

    def test_no_stray_single_brace_placeholders(self):
        """``{title}`` looks like a placeholder and renders as literal text."""
        stray: list[str] = []
        for d in svc.DEFAULT_TEMPLATES:
            for text in (d["subject_template"], d["body_template"]):
                without = PLACEHOLDER.sub("", text)
                if "{" in without or "}" in without:
                    stray.append(d["name"])
        assert not stray, f"single-brace placeholders in: {stray}"

    def test_the_seeded_catalogue_renders_without_leftovers(self, session):
        """End to end: seed, then render every template with the union of its
        own placeholders. Nothing may come out still looking like a template."""
        svc.seed_default_templates(session)

        for row in svc.get_templates(session):
            keys = {m.strip() for m in PLACEHOLDER.findall(
                row["subject_template"] + row["body_template"])}
            out = svc.render_template(session, row["id"],
                                      {k: f"<{k}>" for k in keys})
            assert "{{" not in out["subject"] + out["body"], row["name"]
