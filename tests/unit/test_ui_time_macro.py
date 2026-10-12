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
    assert "2026-10-12T09:41:07+00:00</time>" in html


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
