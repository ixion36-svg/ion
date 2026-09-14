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


def test_every_dynamic_style_expression_resolves():
    problems = []
    checked = 0
    for path in sorted(TEMPLATES.rglob("*.html")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
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
                        problems.append(
                            f"{path.name}:{i + 1} `{n}` in {expr[:60]}")

    assert checked > 100, f"expected many expressions to check, saw {checked}"
    assert not problems, (
        "data-ion-style expressions referencing names that are not in scope. "
        "These throw at render time and the surrounding try/catch turns that "
        "into a generic failure message:\n  " + "\n  ".join(problems))
