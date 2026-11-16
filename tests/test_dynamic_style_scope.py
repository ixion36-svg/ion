"""Every `data-ion-style` expression must reference variables that are in scope.

WHY THIS CLASS OF BUG IS EASY TO SHIP
-------------------------------------
The v0.31.21 migration hashed inline styles into CSS classes. Where the style
was built at runtime it froze the BUILDER into the rule:

    ._ion-s-19fdfcbae6 { background:' + sc.bg + ';color:' + sc.color + '; }

That is invalid CSS, so the browser discards the declaration. Which means the
`sc` binding could disappear from the surrounding code and nothing would ever
complain: the text was inert.

Moving those declarations back into the markup as `data-ion-style` -- which is
the only way to make them work again -- turns the inert text into a live
expression. A name that went missing in the intervening forty-odd releases
then throws, and because these renders are wrapped in a `try`, the throw
surfaces as a generic "Failed to load case details" with a 200 in the server
log and nothing in between.

That is exactly what happened: `sc` had been `statusColors[st]`, the binding
was long gone, and restoring the style took the entire case panel down.
"""

import re
from pathlib import Path

TEMPLATES = Path("src/ion/web/templates")
ATTR = re.compile(r'data-ion-style="([^"]*)"')
ROOT = re.compile(r"(?<![\w.$])([A-Za-z_$][\w$]*)")
DECL = "const|let|var|function"

# CSS keywords, units and built-ins that appear inside these expressions but
# are not variables.
NOT_VARIABLES = {
    "true", "false", "null", "undefined", "var", "new", "typeof", "return",
    "px", "em", "rem", "solid", "dashed", "none", "auto", "block", "flex",
    "grid", "inline", "transparent", "currentColor", "calc", "rgba", "rgb",
    "Math", "String", "Number", "Boolean", "JSON", "Date", "Object", "Array",
}


def _declared(name: str, scope: str, whole_file: str) -> bool:
    """Is `name` bound anywhere that could reach this expression?

    Deliberately generous. A false positive here is a failing test on working
    code, which is worse than missing an exotic binding -- the check exists to
    catch a name that is gone entirely, not to model JS scoping.
    """
    esc = re.escape(name)
    patterns = (
        rf"(?:{DECL})\s+{esc}\b",                        # const x = ...
        rf"\b{esc}\s*=>",                                 # x => ...
        rf"\(\s*[^)]*\b{esc}\b[^)]*\)\s*(?:=>|\{{)",      # (a, x) => / function (x) {
        rf"function\s+\w*\s*\([^)]*\b{esc}\b",
        rf"for\s*\([^)]*\b{esc}\b[^)]*\)",                # for (const [k, x] of ...)
        rf"(?:{DECL})\s*[\[{{][^\]}}]*\b{esc}\b",         # const {{x}} = / const [x] =
        rf"\.\s*(?:forEach|map|filter|find|some|every|reduce)\s*\(\s*"
        rf"(?:function\s*)?\(?[^)]*\b{esc}\b",            # .forEach(x => ...)
    )
    if any(re.search(p, scope) for p in patterns):
        return True
    # Module-scope declaration anywhere in the file.
    return bool(re.search(rf"(?:{DECL})\s+{esc}\b", whole_file))


def _scan(text: str, name: str = "<snippet>") -> tuple[int, list[str]]:
    """How many dynamic expressions `text` holds, and which do not resolve.

    Split out of the test so the positive control can run the checker over a
    snippet whose answer is known.
    """
    problems: list[str] = []
    checked = 0
    lines = text.splitlines()
    whole = "\n".join(lines)
    for i, line in enumerate(lines):
        for m in ATTR.finditer(line):
            expr = m.group(1)
            # The JS halves only: `' + expr + '` and `${expr}`.
            bits = re.findall(r"'\s*\+(.*?)\+\s*'", expr)
            bits += re.findall(r"\$\{(.*?)\}", expr)
            if not bits:
                continue
            checked += 1
            names = set()
            for bit in bits:
                bit = re.sub(r"'[^']*'|\"[^\"]*\"", " ", bit)
                names.update(ROOT.findall(bit))
            names -= NOT_VARIABLES
            scope = "\n".join(lines[max(0, i - 120):i + 40])
            for n in sorted(names):
                if not _declared(n, scope, whole):
                    problems.append(f"{name}:{i + 1} `{n}` in {expr[:60]}")
    return checked, problems


#: A builder whose binding is gone, which is the bug in this file's header:
#: `sc` had been `statusColors[st]` and the binding was removed while the
#: declaration sat inert inside a hashed class, so restoring the style took
#: the whole case panel down.
_GONE = """
<script>
function render(row) {
  html += '<span data-ion-style="background:' + sc.bg + '"></span>';
}
</script>
"""

_IN_SCOPE = """
<script>
function render(row) {
  const sc = palette[row.status];
  html += '<span data-ion-style="background:' + sc.bg + '"></span>';
}
</script>
"""


def test_the_checker_catches_a_builder_whose_binding_is_gone():
    """The positive control.

    It was `checked > 100`, a count of the production sites, and this
    redesign is removing those sites on purpose: the count read 77 one
    morning and 49 that afternoon, so the floor failed by succeeding while
    saying nothing about whether the checker still worked. This asserts the
    checker against an input whose answer is known, so it does not decay.
    """
    checked, problems = _scan(_GONE)
    assert checked == 1
    assert len(problems) == 1, problems
    assert "`sc`" in problems[0]


def test_the_checker_passes_a_builder_that_is_in_scope():
    """The other half. A checker that flagged everything would satisfy the
    test above too."""
    checked, problems = _scan(_IN_SCOPE)
    assert checked == 1
    assert problems == []


def test_no_template_builds_a_style_expression_in_javascript():
    """Inverted, because the last one is gone.

    This used to assert every `data-ion-style` expression resolved, and
    it guarded itself with `checked > 0` so an empty scan could not pass
    for the wrong reason. That guard fired: the case panel's alert status
    badge, `background:' + sc.bg + ';color:' + sc.color`, was the last
    JavaScript-built style attribute in any template, and it is a class
    now.

    So the assertion is stronger than it was. A style expression built in
    JavaScript is a declaration no stylesheet sweep can reach and, when
    the v0.31.21 migration froze such builders into CSS rules, one whose
    binding had gone missing threw inside a try and surfaced as a generic
    failure message. None exist, and none should come back.

    The two controls above still run, so the checker is known to
    distinguish a builder whose binding is gone from one in scope. That
    is what keeps this from being a test that passes because it looks at
    nothing.
    """
    problems = []
    found_any = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        found, bad = _scan(
            path.read_text(encoding="utf-8", errors="replace"), path.name)
        if found:
            found_any.append("%s: %d" % (path.name, found))
        problems += bad

    assert not found_any, (
        "a template builds a data-ion-style value in JavaScript again. "
        "Put the declaration in a class, or in a Jinja expression the "
        "server resolves, rather than a string the browser assembles:\n  "
        + "\n  ".join(found_any))
    # Kept so the message still exists if the first assertion is ever
    # relaxed: an expression that does survive must at least resolve.
    assert not problems, "\n  ".join(problems)
