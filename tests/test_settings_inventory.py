"""Every setting ION reads must be visible somewhere in Settings.

Reported from the running estate, 8 October 2026: environment values were
"not there" in the UI. They partly were. ``GET /api/admin/config`` returns
hand-written sections -- general, gitlab, opencti, elasticsearch, oidc,
kibana, dfir_iris, tide, arkime, ollama, abuseipdb, virustotal -- and the
page renders those correctly, locked, with a "set by environment" badge.

The problem is everything outside those sections. ``ENV_FIELD_MAP`` has 151
fields. The sections carry 67. The other 84 have no field on the page and
no entry in the payload, so there is no way to see from the UI what ION is
actually running with. On this deployment two of them were set from the
environment and invisible:

    ION_RESPONSE_ACTIONS_ENABLED
    ION_RESPONSE_ACTIONS_LIVE

``response_actions_live`` decides whether a containment action is really
executed against a live system or only recorded as a dry run. It was on,
from the environment, and nothing in Settings said so. "Dry-run is not
containment" is only a usable distinction if an operator can find out which
one they are in.

The rest are at their defaults today, which is not the same as harmless:
``csrf_enabled``, ``dev_mode``, ``debug_mode``, ``account_lockout_enabled``
and the ``exec_*`` response credentials are all in that set, and a default
is only reassuring if you can confirm it is still the default.

The fix is an inventory rather than 84 new form fields. Most of these
should not be editable from a web page -- an AD bind password or
``csrf_enabled`` does not belong behind a Save button -- but none of them
should be unknowable. So: one read-only list of every field ION reads, with
its value (secrets masked), where the value came from, and which variable
holds it.

These tests enforce the invariant that makes it worth having: the inventory
is derived from ENV_FIELD_MAP, so a field added to config cannot be absent
from it. A hand-maintained list would drift exactly the way the sections
did.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.core.config import ENV_FIELD_MAP
from ion.web.admin_api import build_config_inventory


@pytest.fixture(scope="module")
def inventory():
    return build_config_inventory()


@pytest.fixture(scope="module")
def by_field(inventory):
    return {row["field"]: row for row in inventory}


# -- Coverage: the whole point --------------------------------------------


class TestCoverage:
    def test_every_env_backed_field_is_present(self, by_field):
        missing = sorted(set(ENV_FIELD_MAP) - set(by_field))
        assert not missing, (
            f"{len(missing)} settings ION reads have no inventory entry, so "
            f"there is no way to see them from the UI: {missing[:12]}"
        )

    def test_nothing_extra_is_invented(self, by_field):
        """The inventory reports what ION reads, not a wish list."""
        extra = sorted(set(by_field) - set(ENV_FIELD_MAP))
        assert not extra, f"inventory reports unknown fields: {extra}"

    def test_it_is_not_a_hand_maintained_list(self, inventory):
        """Derived from ENV_FIELD_MAP, so it cannot drift. 151 today; the
        assertion is on the relationship, not the number."""
        assert len(inventory) == len(ENV_FIELD_MAP)

    @pytest.mark.parametrize("field", [
        "response_actions_enabled",
        "response_actions_live",
    ])
    def test_the_fields_that_were_invisible_are_covered(self, by_field, field):
        """The two that were set from the environment with nowhere to see
        them. response_actions_live is the difference between a dry run and
        a real containment."""
        assert field in by_field


# -- Shape -----------------------------------------------------------------


class TestShape:
    REQUIRED = {"field", "env_var", "source", "value", "is_secret", "editable"}

    def test_every_row_has_the_full_shape(self, inventory):
        for row in inventory:
            assert self.REQUIRED <= set(row), (
                f"{row.get('field')} is missing {self.REQUIRED - set(row)}"
            )

    def test_env_var_names_come_from_the_map(self, by_field):
        """Never derived by upper-casing the field. gitlab_sudo_enabled is
        held by ION_GITLAB_SUDO, so a guessed name sends an operator looking
        for a variable that does not exist."""
        for field, env in ENV_FIELD_MAP.items():
            assert by_field[field]["env_var"] == env

    def test_source_is_one_of_the_three_known_values(self, inventory):
        for row in inventory:
            assert row["source"] in ("environment", "file", "default"), (
                f"{row['field']} has source {row['source']!r}"
            )

    def test_rows_are_sorted_by_field(self, inventory):
        """A 151-row table that is not in a stable order is unreadable, and
        a diff of two of them is useless."""
        names = [r["field"] for r in inventory]
        assert names == sorted(names)


# -- Secrets ---------------------------------------------------------------


class TestSecrets:
    """The inventory exists to make configuration visible. That must not
    turn it into a way to read the secrets back out."""

    SECRETISH = ("password", "token", "secret", "api_key", "license")

    def test_secret_fields_are_flagged(self, by_field):
        for field, row in by_field.items():
            if any(h in field for h in self.SECRETISH):
                assert row["is_secret"], f"{field} is not flagged as secret"

    def test_a_flagged_value_is_masked_or_empty(self, by_field):
        import re
        for field, row in by_field.items():
            if not row["is_secret"]:
                continue
            value = row["value"]
            if value in ("", None):
                continue
            assert re.match(r"^\*+", str(value)), (
                f"{field} is flagged secret but its value is not masked: "
                f"{str(value)[:12]!r}"
            )

    def test_a_short_secret_is_fully_masked(self, by_field):
        """mask_secret shows the last four characters, which for a short
        value is most of it. Those must be fully starred instead."""
        from ion.web.admin_api import mask_secret
        assert mask_secret("abcd") == "****"
        assert set(mask_secret("abc")) == {"*"}

    def test_a_database_url_does_not_leak_its_password(self, by_field):
        """ION_DATABASE_URL carries the password inside the DSN, so masking
        by field name alone would print it in full."""
        row = by_field.get("database_url")
        if row is None:
            pytest.skip("database_url is not an ENV_FIELD_MAP field")
        assert row["is_secret"], "database_url embeds credentials"


# -- Editability -----------------------------------------------------------


class TestEditability:
    def test_fields_the_settings_forms_own_are_marked_editable(self, by_field):
        """So the panel can send the operator to the right form rather than
        implying everything is read-only."""
        for field in ("elasticsearch_url", "gitlab_project_id", "oidc_realm"):
            assert by_field[field]["editable"] is True, field

    def test_fields_with_no_form_are_not_marked_editable(self, by_field):
        for field in ("csrf_enabled", "dev_mode", "response_actions_live"):
            assert by_field[field]["editable"] is False, field

    def test_an_environment_held_field_says_so(self, monkeypatch):
        """Whatever `editable` says, get_config ranks env above the config
        file, so the source is what actually decides. Set here rather than
        asserted against the ambient environment: a bare pytest process has
        no ION_* variables, so that assertion would have passed only by
        accident of how the suite was launched."""
        from ion.core import config as config_mod

        monkeypatch.setenv("ION_RESPONSE_ACTIONS_LIVE", "true")
        config_mod.set_config(None)  # drop the cached Config
        try:
            rows = {r["field"]: r for r in build_config_inventory()}
            assert rows["response_actions_live"]["source"] == "environment"
            assert rows["response_actions_live"]["env_var"] == (
                "ION_RESPONSE_ACTIONS_LIVE"
            )
        finally:
            config_mod.set_config(None)


# -- The environment panel must not print credentials ----------------------


class TestEnvironmentPanelMasking:
    """Settings -> System shows every ION_* variable. It masked by variable
    *name* only, against ["password", "secret", "token", "key"], so a
    credential carried inside a value went out in full::

        ION_DATABASE_URL: postgresql://ion:ion2025@127.0.0.1:5432/ion

    That is the live database password, rendered on an admin page and in
    every screenshot or support bundle taken of it. A DSN is the common
    case, but any URL can carry user:pass@, including the Elasticsearch and
    Kibana URLs.
    """

    def test_a_dsn_password_is_redacted(self):
        from ion.web.admin_api import mask_env_value
        out = mask_env_value(
            "ION_DATABASE_URL", "postgresql://ion:ion2025@127.0.0.1:5432/ion")
        assert "ion2025" not in out

    def test_the_rest_of_the_dsn_survives(self):
        """Redacting the whole value would make the panel useless: the host,
        port and database name are exactly what an operator came to check."""
        from ion.web.admin_api import mask_env_value
        out = mask_env_value(
            "ION_DATABASE_URL", "postgresql://ion:ion2025@127.0.0.1:5432/ion")
        assert "127.0.0.1:5432" in out and "postgresql://" in out

    @pytest.mark.parametrize("url", [
        "https://elastic:testpassword123@es.internal:9200",
        "http://user:p%40ss@host/path",
        # Username and password deliberately different: with both set to
        # "guest" the assertion below cannot tell a surviving username from
        # a leaked password.
        "amqp://guest:rabbitpw@rabbit:5672/",
    ])
    def test_credentials_in_any_url_are_redacted(self, url):
        from ion.web.admin_api import mask_env_value
        out = mask_env_value("ION_SOME_URL", url)
        assert "@" in out, "the host must still be shown"
        secret = url.split("//", 1)[1].split("@", 1)[0].split(":", 1)[1]
        assert secret not in out

    def test_a_url_with_no_credentials_is_untouched(self):
        from ion.web.admin_api import mask_env_value
        url = "http://127.0.0.1:9200"
        assert mask_env_value("ION_ELASTICSEARCH_URL", url) == url

    @pytest.mark.parametrize("name", [
        "ION_ADMIN_PASSWORD", "ION_GITLAB_TOKEN", "ION_TIDE_API_KEY",
        "ION_OIDC_CLIENT_SECRET",
    ])
    def test_name_based_masking_still_applies(self, name):
        from ion.web.admin_api import mask_env_value
        out = mask_env_value(name, "supersecretvalue")
        assert "supersecret" not in out

    def test_a_plain_value_is_unchanged(self):
        from ion.web.admin_api import mask_env_value
        assert mask_env_value("ION_GITLAB_PROJECT_ID", "1") == "1"

    def test_an_empty_value_says_not_set(self):
        from ion.web.admin_api import mask_env_value
        assert mask_env_value("ION_ANYTHING", "") == "(not set)"


# -- Robustness ------------------------------------------------------------


class TestRobustness:
    def test_building_it_twice_gives_the_same_answer(self):
        assert build_config_inventory() == build_config_inventory()

    def test_a_field_config_does_not_expose_is_reported_not_crashed_on(
        self, by_field
    ):
        """ENV_FIELD_MAP and the Config dataclass can drift. A name in the
        map with no attribute must show as unavailable rather than raise and
        take the whole settings page down."""
        for row in by_field.values():
            assert "value" in row
