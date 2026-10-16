"""The `ts` macro, which is how every fragment emits a timestamp.

The fragments replace JavaScript that called `new Date(x).toLocaleString()`,
the viewer's clock. A server knows only its own, so rendering the string
server-side would show an analyst in another timezone the wrong time on
every row. On an audit journal, whose whole purpose is "what happened
when", that is worse than the string-building it replaced.

The macro's job is therefore to emit an instant a script can localise, plus
a fallback that is correct rather than merely present. These tests pin both
halves, because the fallback is what a viewer sees when the script is
blocked, and a fallback that omits its zone is a wrong time with no warning.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ion.web.templating import make_templates

TEMPLATE = (
    '{% from "_fragments/_time.html" import ts %}'
    "{{ ts(value, format, fallback) }}"
)


def render(value, fmt="datetime", fallback="-") -> str:
    env = make_templates().env
    return env.from_string(TEMPLATE).render(value=value, format=fmt,
                                            fallback=fallback)


def test_a_datetime_emits_a_machine_instant_and_a_zoned_fallback():
    html = render(datetime(2026, 10, 12, 9, 41, 7, tzinfo=timezone.utc))
    assert 'datetime="2026-10-12T09:41:07+00:00"' in html
    assert "2026-10-12 09:41 UTC" in html, (
        "the fallback must name its zone, or a viewer with scripts blocked "
        "reads server time as if it were their own"
    )


def test_an_iso_string_is_accepted_too():
    """Some repositories hand back parsed objects and some hand back the
    stored text, and a fragment author cannot tell which from the row."""
    html = render("2026-10-12T09:41:07+00:00")
    assert 'datetime="2026-10-12T09:41:07+00:00"' in html
    # This used to assert the string was echoed into the text verbatim,
    # which is why two conversions reported raw microseconds as the ugliest
    # thing on their page. A parseable string is now formatted exactly as
    # the datetime it encodes, so a column does not change appearance based
    # on whether a repository happened to call .isoformat(). The attribute
    # still carries the full instant for the script to read.
    assert "2026-10-12 09:41 UTC</time>" in html


def test_a_missing_timestamp_is_not_the_epoch_and_not_an_empty_cell():
    """"No timestamp recorded" and "midnight, 1 January 1970" are different
    claims, and an empty cell reads as the row having no time at all."""
    html = render(None)
    assert "1970" not in html
    assert "<time" not in html
    assert ">-<" in html


def test_an_empty_string_is_treated_as_missing():
    """A truthiness test would be right here and wrong for 0 elsewhere, so
    the macro names the two cases it means instead."""
    assert "<time" not in render("")


def test_a_caller_can_say_what_missing_means():
    assert "Not scheduled" in render(None, fallback="Not scheduled")


@pytest.mark.parametrize("fmt", ["datetime", "date", "time"])
def test_the_format_reaches_the_script(fmt):
    """The script reads data-ts-format. Dropping the attribute silently
    gives every timestamp the default presentation."""
    assert f'data-ts-format="{fmt}"' in render(datetime(2026, 1, 1), fmt)


def test_the_instant_is_attribute_escaped():
    html = render('"><script>alert(1)</script>')
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html or "&#34;&gt;" in html


# ---------------------------------------------------------------------------
# Aware versus naive, which is the difference between a localised time and a
# confidently wrong one
# ---------------------------------------------------------------------------


def test_an_aware_value_is_marked_localisable():
    html = render(datetime(2026, 10, 12, 9, 41, 7, tzinfo=timezone.utc))
    assert 'data-ts-local="yes"' in html
    assert "title=" not in html, "an aware value needs no caveat"


def test_a_naive_value_is_not_localised_and_says_whose_clock_it_is():
    """ION stores audit timestamps in a naive column defaulting to the
    database's func.now(), which is UTC on SQLite and the session timezone
    on Postgres, with nothing in the row to say which.

    Localising it anyway is worse than leaving it: JavaScript parses a
    zoneless ISO date-time as local, so the browser would read the digits as
    the viewer's clock, convert out of a zone the value was never in, and
    show a time wrong by the viewer's offset while looking authoritative.
    An unknown zone is not UTC, the same way unmeasured is not zero.
    """
    html = render(datetime(2026, 10, 12, 9, 41, 7))
    assert 'data-ts-local="no"' in html
    assert "stores no timezone" in html
    assert "UTC" not in html, "claiming UTC for an unknown zone invents a fact"


@pytest.mark.parametrize("text,expected", [
    ("2026-10-12T09:41:07+00:00", "yes"),
    ("2026-10-12T09:41:07Z", "yes"),
    ("2026-10-12T09:41:07+0200", "yes"),
    ("2026-10-12T09:41:07", "no"),
    ("2026-10-12 09:41:07", "no"),
])
def test_a_string_is_classified_by_whether_it_carries_an_offset(text, expected):
    assert f'data-ts-local="{expected}"' in render(text)


def test_an_aware_fallback_is_stated_in_utc():
    """Two different zones in one column reads as two different times."""
    from datetime import timedelta

    html = render(datetime(2026, 10, 12, 11, 41, 7,
                           tzinfo=timezone(timedelta(hours=2))))
    assert "2026-10-12 09:41 UTC" in html


# ---------------------------------------------------------------------------
# A string and a datetime of the same instant must render the same
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("aware", [True, False])
def test_an_iso_string_renders_exactly_like_the_datetime_it_encodes(aware):
    """A fragment author cannot tell which type they will be handed.

    Some repositories return parsed objects and some call .isoformat() for
    their JSON consumer, and the fragment sees whichever. Before this, a
    datetime showed "2026-10-12 14:51" while the ISO string of the same
    moment showed "2026-10-12T14:51:48.123456", so the prettiness of a
    column depended on an implementation detail upstream. Two conversions
    reported the raw microseconds as the ugliest thing on their page.
    """
    from ion.web.templating import _ts_parts

    tz = timezone.utc if aware else None
    value = datetime(2026, 10, 12, 14, 51, 48, 123456, tzinfo=tz)
    assert _ts_parts(value)["shown"] == _ts_parts(value.isoformat())["shown"]
    assert _ts_parts(value)["localise"] == _ts_parts(value.isoformat())["localise"]


def test_a_date_with_no_time_is_not_given_a_midnight():
    """Parsing it would render "2026-10-12 00:00", asserting a time of day
    the data never carried. Inventing a midnight on a date is the same
    defect as printing 0 for a figure nobody measured."""
    from ion.web.templating import _ts_parts

    assert _ts_parts("2026-10-12")["shown"] == "2026-10-12"


def test_an_unparseable_value_is_still_shown():
    """An unreadable timestamp is evidence, not something to blank."""
    from ion.web.templating import _ts_parts

    assert _ts_parts("whenever")["shown"] == "whenever"
