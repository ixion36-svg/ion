"""Regressions for tools/dead_css.py's reference scanner.

Every test here is a case where the scanner failed to SEE a class that markup
genuinely carries. That direction is the dangerous one: a class the scanner
misses is reported dead, and `--write` deletes its rule. There is no error and
no failing test when that happens -- the styling simply goes, on whichever page
nobody opened that week.

All three were found the same way, by checking the tool's own output against a
plain boundary-grep of the source rather than trusting it.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.dead_css import literal_tokens  # noqa: E402


def test_sees_a_macro_argument_joined_to_a_class_suffix():
    from tools.dead_css import constructed_prefixes

    source = '''{% macro sev_pills(items, prefix, alert_count) %}
        <span class="{{ prefix }}-pill {{ p.short }}">{{ p.count }}</span>
        {% endmacro %}{{ sev_pills(s.pills, 'sys-sev', s.alert_count) }}'''
    assert "sys-sev-" in constructed_prefixes(source, kind="markup")


def test_inline_host_option_is_scanned_as_javascript(tmp_path, monkeypatch):
    from tools import dead_css

    (tmp_path / "cases.html").write_text(
        '<script nonce="{{ csp_nonce }}">ionAlertDetail.mount({classPrefix:"cpanel-alert"});</script>',
        encoding="utf-8")
    monkeypatch.setattr(dead_css, "SEARCH_DIRS", [tmp_path])
    chunks = dead_css.corpus_by_kind()
    prefixes = set().union(*(dead_css.constructed_prefixes(text, kind=kind)
                             for kind, text in chunks.items()))
    assert "cpanel-alert-" in prefixes


def test_macro_class_prefixes_follow_keywords_defaults_and_imports():
    from tools.dead_css import constructed_prefixes

    source = '''{% macro pill(prefix='default') %}<i class="{{ prefix }}-pill"></i>{% endmacro %}
        {{ pill() }}{{ components.pill(prefix='named') }}
        {% macro prose(prefix) %}{{ prefix }}-text{% endmacro %}{{ prose('unrelated') }}'''
    prefixes = constructed_prefixes(source, kind="markup")
    assert {"default-", "named-"} <= prefixes
    assert "unrelated-" not in prefixes


def test_sees_a_class_beside_a_template_literal_interpolation():
    """`class="a b${x}"` was skipped whole: the value pattern banned braces.

    alerts-queue.js builds nearly every cell this way, so aq-caseref, aq-ghead,
    aq-kev and aq-sev-pill all read as dead at once.
    """
    src = """h += `<span class="aq-tag aq-kev${ransom ? ' is-ransomware' : ''}"`"""
    assert "aq-tag" in literal_tokens(src)
    assert "aq-kev" in literal_tokens(src)


def test_sees_a_class_written_inside_the_interpolation():
    """The conditional half of a ternary is a real class on a real element.

    Cutting `${...}` out before splitting loses `aq-closed`, which appears
    nowhere else in the app.
    """
    src = """`<div class="aq-ghead sev-${esc(g.sev || '')}${shut ? ' aq-closed' : ''}">`"""
    toks = literal_tokens(src)
    assert "aq-ghead" in toks
    assert "aq-closed" in toks


def test_an_empty_string_does_not_put_the_quote_scan_out_of_phase():
    """`''` must consume both its quotes or every later quote pairs wrongly.

    Requiring at least one character meant the scan resumed from the first of
    the two, pairing `', cls: '` as a string and dropping `aq-act` into the gap
    between two matches.
    """
    src = "{ k: 'act', label: '', cls: 'aq-act', on: true, fixed: true }"
    assert "aq-act" in literal_tokens(src)


def test_sees_a_class_beside_a_jinja_expression():
    """Templates interpolate into class attributes as routinely as JS does."""
    src = '<div class="card bg-base-200 sr-role sr-c-{{ r.color }}">'
    toks = literal_tokens(src)
    assert "card" in toks
    assert "sr-role" in toks


def test_a_nested_brace_in_an_interpolation_fails_towards_live():
    """The one case still not parsed must skip the attribute, not mis-split it.

    Skipping means the classes are not collected from THIS attribute, so the
    tool can only under-report liveness elsewhere -- never invent a token that
    makes something look reachable when it is not.
    """
    src = '<div class="wrap ${xs.map(x => `${x}`)} tail">'
    toks = literal_tokens(src)
    # Whatever it does, it must not emit a fragment of expression code as a
    # class name that could shadow a real one.
    assert not any(re.search(r"[(){}$`]", t) for t in toks)


def test_sees_a_class_in_an_attribute_the_literal_never_closes():
    """Concatenation closes the attribute, so there is no second quote.

        '<div class="iad-adv iad-adv-kev' + (ransom ? ' is-ransomware' : '')

    The opening `"` gets consumed as the CLOSING quote of `'<div class=`, which
    drops iad-adv-kev into the gap between two matches. All three of
    iad-adv-kev, iad2-fpin and iad2-gseg-ai were invisible this way.
    """
    src = """h += '<div class="iad-adv iad-adv-kev' + (ransom ? ' is-ransomware' : '') + '">'"""
    toks = literal_tokens(src)
    assert "iad-adv" in toks
    assert "iad-adv-kev" in toks


def test_strict_keeps_a_rule_whose_only_dead_class_is_negated():
    """A dead class inside :not() makes a selector match MORE, not less.

    `.nav-links > li > a:not(.nav-dropdown-toggle)` with no
    .nav-dropdown-toggle in the app styles every link in the nav, so treating
    the dead name as proof the rule cannot match deletes the whole nav bar.
    """
    from tools.dead_css import strip_rules
    css = (".nav-links > li > a:not(.nav-dropdown-toggle) { color: red }\n"
           ".gone .alsogone { color: blue }\n")
    out, removed = strip_rules(css, {"nav-dropdown-toggle", "gone", "alsogone"},
                               strict=True)
    assert "nav-links" in out, "a rule negating a dead class must survive"
    assert removed == 1, "the genuinely unmatchable rule should still go"


def test_strict_drops_a_compound_gated_on_one_dead_class():
    """`.ds-badge.success` needs BOTH names on one element.

    The timid all-dead rule kept every such pairing alive, because a modifier
    like .success or .active is live somewhere else in the app. That is what
    made all thirty selectors of design-system.css unreachable and undeletable
    at the same time.
    """
    from tools.dead_css import strip_rules
    css = ".ds-badge.success { color: green }\n"
    out, removed = strip_rules(css, {"ds-badge"}, strict=True)
    assert removed == 1
    assert "ds-badge" not in out


def test_sees_a_class_built_by_a_jinja_interpolation():
    """`class="sr-c-{{ r.color }}"` was invisible: only `${}` was handled.

    Found by covering ion-pages.css, the sheet the redesign's `styled` column
    fills. soc_roles.html builds its role deck as

        <div class="card bg-base-200 shadow sr-role sr-c-{{ r.color }}">

    so all eleven .sr-c-* rules read as dead at once, and --write would have
    removed every one. The deck would have rendered with no per-role colour
    and no error, which is this module's whole subject.

    test_v052_soc_roles_page.py asserts each of those eleven class names
    reaches the page, so the tool and the suite disagreed. The suite was right.
    """
    from tools.dead_css import constructed_prefixes

    src = '<div class="card bg-base-200 shadow sr-role sr-c-{{ r.color }}">'
    assert "sr-c-" in constructed_prefixes(src)


def test_jinja_and_javascript_construction_are_both_seen():
    """The two forms appear side by side in this codebase, so neither may
    regress in favour of the other."""
    from tools.dead_css import constructed_prefixes

    both = constructed_prefixes(
        'class="aq-sev-${sev}" class="sr-c-{{ color }}" '
        "'rail-sev-' + esc(sev)"
    )
    assert {"aq-sev-", "sr-c-", "rail-sev-"} <= both


def test_corpus_reads_python_view_model_class_names(tmp_path, monkeypatch):
    from tools import dead_css

    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "analytics.py").write_text(
        'PANEL_STATUS_CLASSES = {"error": "fp-error"}', encoding="utf-8")
    monkeypatch.setattr(dead_css, "SEARCH_DIRS", [ui])
    assert "fp-error" in dead_css.literal_tokens(dead_css.corpus())


def test_sees_the_real_namespace_percent_format():
    from tools.dead_css import constructed_prefixes

    source = 'return "ns-p%d" % (digest[0] % NAMESPACE_FALLBACKS)'
    assert "ns-p" in constructed_prefixes(source)


def test_sees_python_fstring_class_prefix():
    from tools.dead_css import constructed_prefixes

    assert "severity-" in constructed_prefixes('return f"severity-{level}"')


def test_keeps_literal_prefix_arguments_to_jinja_macros():
    from tools.dead_css import constructed_prefixes

    source = '''{{ closure_bars(slices, total, 'cl-') }}
        <div class="closure-bar-fill {{ prefix }}{{ s.key }}"></div>'''
    assert "cl-" in constructed_prefixes(source)


def test_sees_shared_alert_details_host_prefix_and_default():
    from tools.dead_css import constructed_prefixes

    source = '''IonAlertDetail.init({ classPrefix:'cpanel-alert' });
        var p = _opts.classPrefix || 'alert-parsed';
        return p + '-' + suffix;'''
    assert {"cpanel-alert-", "alert-parsed-"} <= constructed_prefixes(source)


# ---------------------------------------------------------------------------
# A pattern that is an idiom in one language and a coincidence in another
# ---------------------------------------------------------------------------
#
# The two tests below are the other direction from the rest of this file.
# Every case above is a class the scanner failed to SEE; these are strings the
# scanner saw as a class family when they were nothing of the kind. That
# direction is safe, because an over-broad prefix keeps a rule rather than
# deleting a live one, but a one-character prefix marks every class starting
# with that letter live. Sixteen prefixes of two characters or fewer came in
# this way and masked 54 classes, including the rule for topo-page-wrap, which
# no element has ever carried.


def test_a_javascript_modulo_is_not_a_python_format_string():
    """`t%s==0` in a minified bundle made `t` a live prefix, so every
    ti-*, table-* and topo-* class read as live."""
    from tools.dead_css import constructed_prefixes

    source = "function W(t){const i=Math.sqrt(t);for(s=1;s<i;s++)t%s==0&&e.push(s)}"
    assert "t" not in constructed_prefixes(source, kind="js")
    assert "s" not in constructed_prefixes(source, kind="js")


def test_an_svg_path_is_not_a_set_of_class_families():
    """`f"M{x},{y} A{r},{r}"` is a path, and M, A and L are its commands.
    ns-p, the case the f-string pattern exists for, is still seen."""
    from tools.dead_css import constructed_prefixes

    path = 'return f"M{x1:.2f},{y1:.2f} A{r},{r} 0 {large},1 L{x2:.2f},{y2:.2f}"'
    found = constructed_prefixes(path, kind="py")
    assert not {"M", "A", "L"} & found, sorted(found)
    assert "ns-p" in constructed_prefixes('return f"ns-p{n}"', kind="py")


def test_the_corpus_still_reaches_every_language():
    """Scoping the patterns must not drop a language from the scan."""
    from tools.dead_css import corpus_by_kind

    by_kind = corpus_by_kind()
    assert set(by_kind) == {"markup", "js", "py"}
    for kind, text in by_kind.items():
        assert len(text) > 10_000, kind
