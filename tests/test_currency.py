"""Money carries a currency, and nothing hardcodes a symbol.

ION had no currency anywhere in the money path. TrainingPlanItem.price,
ProfileRequirement.cost and JourneyRequirement.cost were bare floats, and
six server-rendered templates put a literal "£" in front of them. That
worked only because every price in the product happened to be GBP.

The failure it was waiting for is quiet. Record a GIAC attempt at its
quoted $999 -- which is the correct figure, from the vendor -- and the
forecast adds it to the pounds and prints a £ in front of the total.
Nothing errors, nothing looks odd, and the number a budget is argued from
is wrong.

So: Config.currency says what stored amounts are in, templates format
through one money() global instead of a hardcoded symbol, TrainingPlanItem
records what its own price is denominated in and where the figure came
from, and the forecast reports the currencies it actually saw rather than
silently adding across them.

Still outstanding, deliberately: training.html's client-side certificate
catalogue holds 85 prices and its own "£" literals. That is a separate
piece -- the catalogue wants lifting into Python the way skills_matrix
was -- and this file guards the server-rendered path it does not cover.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.core.config import Config  # noqa: E402
from ion.models.skills import TrainingPlanItem  # noqa: E402
from ion.web.templating import _money  # noqa: E402

_FRAGMENTS = _SRC / "ion" / "web" / "templates" / "_fragments"
_DATABASE = _SRC / "ion" / "storage" / "database.py"
_SKILLS_API = _SRC / "ion" / "web" / "skills_api.py"

#: A hardcoded price: a currency symbol immediately before a number or
#: a template expression. Matched that way rather than on the bare
#: symbol because "$" is the sentinel these templates use in
#: data-args ("$value", "$target", "${...}"), and a test that flagged
#: those would be turned off within the week.
_HARDCODED_PRICE = re.compile(r"[£€$]\s*(?:\{\{|\d)")


class TestTheFormatter:
    def test_it_uses_the_configured_currency_by_default(self):
        assert _money(8780).endswith("8,780")
        assert _money(8780)[0] not in "0123456789"

    def test_an_explicit_currency_overrides_it(self):
        """An amount that records what it is denominated in must render in
        that, not in the estate's setting -- which is the whole point."""
        assert _money(999, "USD") == "$999"

    def test_an_unknown_code_renders_as_the_code(self):
        """A wrong symbol is worse than none: SEK is not kronor-with-a-
        pound-sign."""
        assert _money(1200, "SEK") == "SEK 1,200"

    def test_no_price_is_not_zero(self):
        """"Nothing recorded" and "free" are different claims and only one
        of them is a number."""
        assert _money(None) == "—"
        assert _money("") == "—"

    def test_junk_does_not_raise(self):
        """A template rendering a budget must not 500 on a bad row."""
        assert _money("not a number") == "—"

    def test_it_is_case_insensitive_about_the_code(self):
        assert _money(999, "usd") == _money(999, "USD")


class TestTheSetting:
    def test_config_has_a_currency(self):
        assert hasattr(Config(), "currency")

    def test_it_defaults_to_gbp(self):
        """Every existing row was entered under an implicit GBP. Any other
        default would silently restate them all."""
        assert Config().currency == "GBP"


class TestNoTemplateHardcodesASymbol:
    """One formatter, or the next one drifts."""

    def test_the_server_rendered_fragments_are_clean(self):
        offenders = []
        for path in sorted(_FRAGMENTS.glob("*.html")):
            found = _HARDCODED_PRICE.search(path.read_text(encoding="utf-8"))
            if found:
                offenders.append(f"{path.name}: {found.group(0)!r}")
        assert not offenders, (
            "these fragments hardcode a currency symbol; render through "
            "money() so the estate's setting decides: " + ", ".join(offenders)
        )

    def test_the_formatter_is_registered_as_a_global(self):
        """A fragment calling money() with no global raises UndefinedError
        on a page that otherwise works."""
        from ion.web.templating import make_templates

        assert callable(make_templates().env.globals.get("money"))


class TestTheColumns:
    def test_the_item_records_its_currency(self):
        assert hasattr(TrainingPlanItem, "currency")

    def test_the_item_records_where_the_price_came_from(self):
        """A price with no provenance cannot be checked, and an
        unverifiable number in a budget is worse than a blank."""
        assert hasattr(TrainingPlanItem, "price_source")
        assert hasattr(TrainingPlanItem, "price_checked_on")

    def test_currency_is_nullable(self):
        """NULL means the estate's configured currency, which is what every
        pre-existing row is. Backfilling a literal would assert something
        nobody recorded."""
        assert TrainingPlanItem.__table__.c.currency.nullable is True

    def test_the_migration_adds_all_three(self):
        """create_all() only creates missing TABLES, never missing columns,
        so an existing deploy needs the explicit ALTER."""
        source = _DATABASE.read_text(encoding="utf-8")
        # Anchored on the guard, not the first mention: the comment
        # above it names the table too.
        block = source.split('insp.has_table("training_plan_items")')[1][:600]
        for column in ("currency", "price_source", "price_checked_on"):
            assert column in block, f"{column} is never added to an existing database"


class TestTheForecastWillNotSumSilently:
    def test_it_reports_the_currencies_it_saw(self):
        source = _SKILLS_API.read_text(encoding="utf-8")
        assert "currencies_seen" in source
        assert '"mixed_currencies"' in source

    def test_it_does_not_convert(self):
        """Converting needs a rate and a date. An endpoint that invented
        either would be confidently wrong, which is worse than declining."""
        source = _SKILLS_API.read_text(encoding="utf-8")
        for banned in ("exchange_rate", "fx_rate", "convert_currency"):
            assert banned not in source


class TestTheCheckItself:
    """A guard that cannot detect the thing it guards is worse than none."""

    def test_it_spots_a_hardcoded_template_price(self):
        assert _HARDCODED_PRICE.search("spent £{{ '{:,.0f}'.format(x) }}")

    def test_it_spots_a_hardcoded_literal_price(self):
        assert _HARDCODED_PRICE.search("~£8,780 per seat")
        assert _HARDCODED_PRICE.search("$999")

    def test_it_ignores_the_data_args_sentinels(self):
        """"$value", "$target" and "${...}" are how these templates pass
        arguments. Flagging them would make the check noise."""
        for benign in ('data-args=\'[1, "$value"]\'',
                       'data-args=\'[1, "$target"]\'',
                       '"${escapeHtml(a.es_alert_id)}"'):
            assert not _HARDCODED_PRICE.search(benign), benign

    def test_it_ignores_money_rendered_through_the_global(self):
        assert not _HARDCODED_PRICE.search("spent {{ money(active.spend) }}")
