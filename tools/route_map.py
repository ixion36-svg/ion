"""Generate docs/ROUTE_MAP.md: every route ION serves, and who calls it.

Why this is generated and not written. Three things about ION's routing are
invisible to a reader with grep:

  server.py registers 19 canonical path aliases after the routers are
  mounted, so /api/alerts/triage/batch is a real route that appears in no
  decorator anywhere. Searching the decorators for it finds nothing and the
  obvious conclusion, that the page calls a URL that does not exist, is
  wrong.

  A router's prefix is applied at include_router, so the path in the
  decorator is never the path a caller uses.

  A permission gate can be on the decorator, on the signature, or on the
  router, and only the built dependency tree has all three.

So this reads the application object. Static analysis fills in the parts
the route table does not know: which template a fragment renders, and which
templates and scripts reference each path.

    python tools/route_map.py            write docs/ROUTE_MAP.md
    python tools/route_map.py --check    fail if the file is out of date
    python tools/route_map.py --broken   list dangling references only
"""
from __future__ import annotations

import argparse
import ast
import os
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
WEB = SRC / "ion" / "web"
TEMPLATES = WEB / "templates"
STATIC = WEB / "static"
OUT = ROOT / "docs" / "ROUTE_MAP.md"

sys.path.insert(0, str(SRC))
# Importing the app runs its startup validation, which refuses a weak or
# absent admin password. This process only builds the route table; it never
# listens and never touches a database.
os.environ.setdefault("ION_ADMIN_PASSWORD", "RouteMap-Import-Only-9f2b7c")

VENDOR = re.compile(r"\.min\.js$|quill|vis-network|jsvectormap|topojson|htmx",
                    re.I)
#: A URL in a template attribute or a script. Jinja and template literals
#: both interpolate, so a path is captured up to the first brace.
REF = re.compile(r"""["'`(\s](/(?:api|ui)/[A-Za-z0-9_\-./{}$]*)""")

#: Comments, which is where most prose mentions of a URL live. Stripping
#: them is what makes the dangling list worth reading: without it the list
#: was 36 entries of which every one checked was a sentence such as "KEV
#: reads /api/kev." or a Jinja note about which fragment swaps a control.
COMMENTS = [
    re.compile(r"\{#.*?#\}", re.S),         # Jinja
    re.compile(r"<!--.*?-->", re.S),        # HTML
    re.compile(r"/\*.*?\*/", re.S),         # JS block
    re.compile(r"(?m)^[ \t]*//.*$"),        # JS line, at the start of a line
]


def strip_comments(text: str) -> str:
    for rx in COMMENTS:
        text = rx.sub(" ", text)
    return text


#: A permission name, as require_permission takes it. Used for the gates
#: whose names are literals in the function body rather than closure cells.
_PERMISSION_NAME = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")

#: Factories whose qualname carries the permission in a closure cell.
#: require_page_permission is not a substring of the other two, and the
#: other two are not substrings of it: "require_permission" does not occur
#: inside "require_page_permission".
_CLOSURE_GATES = (
    "require_page_permission",
    "require_any_permission",
    "require_permission",
)

#: Gates that are not factories. The names sit in co_consts. Leaving them
#: unrecognised recorded fifteen integration routes and the enrichment
#: lookup as open.
_LITERAL_GATES = ("require_integration_access", "_require_enrich")

#: Gates that accept any one of the permissions they carry, rather than
#: all of them. require_integration_access is
#: `has_permission("integration:read") or has_permission("alert:read")`,
#: and require_any_permission is any-of by name.
#:
#: This distinction is the whole reason the cell is not a plain join. The
#: separator in that column means all-of, so flattening an any-of gate
#: into it states something definite and false, and false in the
#: direction that looks more tightly held than it is.
_ANY_OF_GATES = ("require_any_permission", "require_integration_access")


def _literal_permissions(call) -> list[str]:
    code = getattr(call, "__code__", None)
    consts = getattr(code, "co_consts", ()) or ()
    return [v for v in consts if isinstance(v, str) and _PERMISSION_NAME.fullmatch(v)]


def permission_of(route) -> str:
    """The permission a route requires, read out of its dependency tree.

    require_permission builds a closure over the name, so the name is in
    the closure cell. require_page_permission does the same, and also
    records the name on the function as `_ion_page_permission` for the
    navigation. Walking the built dependant catches the gate wherever it
    was declared: the decorator's `dependencies`, the signature, or the
    router.

    require_page_auth is not a permission. It means signed in, and a blank
    cell is what this function returns for it. require_de_module and
    require_workforce_module are feature gates, not permissions.
    """
    found: list[str] = []

    def walk(dep, depth=0):
        if depth > 4:
            return
        call = getattr(dep, "call", None)
        if call is not None:
            qual = getattr(call, "__qualname__", "") or ""
            recorded = getattr(call, "_ion_page_permission", None)
            names: list[str] = []
            if isinstance(recorded, str) and recorded:
                names = [recorded]
            elif getattr(call, "__closure__", None) and any(
                gate in qual for gate in _CLOSURE_GATES
            ):
                for cell in call.__closure__:
                    value = cell.cell_contents
                    if isinstance(value, str):
                        names.append(value)
                    elif isinstance(value, (list, tuple)):
                        names.extend(v for v in value if isinstance(v, str))
            elif qual in _LITERAL_GATES:
                names = _literal_permissions(call)
            elif "require_admin" in qual or qual == "require_admin":
                names = ["admin"]
            if getattr(call, "__name__", "") == "require_admin":
                names.append("admin")
            if names:
                any_of = any(gate in qual for gate in _ANY_OF_GATES)
                found.append((any_of and len(names) > 1, tuple(sorted(set(names)))))
        for sub in getattr(dep, "dependencies", []) or []:
            walk(sub, depth + 1)

    dependant = getattr(route, "dependant", None)
    if dependant is not None:
        walk(dependant)
    if not found:
        return ""
    parts = []
    for any_of, names in sorted(set(found)):
        if any_of:
            # Parenthesised so that a route carrying both kinds reads
            # unambiguously: "(a or b) + c", not "a or b + c".
            parts.append(("(%s)" if len(found) > 1 else "%s")
                         % " or ".join(names))
        else:
            parts.extend(names)
    return " + ".join(parts)


def _repo_relative(path: str) -> str:
    """A source path relative to the repo.

    ``Path.resolve()`` follows a junction. A worktree whose ``.venv`` is a
    junction to another checkout then fails ``relative_to`` and the map
    drops the handler site, which is how the slowapi limiter lines went
    blank. The ``.venv`` suffix is the same path the map already records.
    """
    raw = pathlib.Path(path)
    for candidate in (raw, raw.resolve()):
        try:
            return str(candidate.relative_to(ROOT)).replace("\\", "/")
        except ValueError:
            continue
    resolved = str(raw.resolve())
    marker = f"{os.sep}.venv{os.sep}"
    idx = resolved.lower().find(marker.lower())
    if idx != -1:
        return resolved[idx + 1:].replace("\\", "/")
    raise ValueError(path)


def handler_site(endpoint) -> tuple[str, int]:
    """Where the handler is written, relative to the repo."""
    try:
        import inspect

        f = inspect.getsourcefile(endpoint) or ""
        _, line = inspect.getsourcelines(endpoint)
        return (_repo_relative(f), line)
    except Exception:
        return ("", 0)


def templates_rendered() -> dict[str, set[str]]:
    """Handler name -> the template names it renders.

    Read from the source because the name is usually a module constant and
    the route table only holds the function.
    """
    out: dict[str, set[str]] = defaultdict(set)
    for path in sorted((WEB / "ui").glob("*.py")) + [WEB / "server.py"]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except Exception:
            continue
        consts = {
            t.id: n.value.value
            for n in tree.body if isinstance(n, ast.Assign)
            for t in n.targets
            if isinstance(t, ast.Name) and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str) and n.value.value.endswith(".html")
        }
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                fn = getattr(sub.func, "attr", None) or getattr(sub.func, "id", None)
                if fn not in ("TemplateResponse", "render_view"):
                    continue
                args = list(sub.args) + [k.value for k in sub.keywords
                                         if k.arg == "name"]
                for a in args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        if a.value.endswith(".html"):
                            out[node.name].add(a.value)
                    elif isinstance(a, ast.Name) and a.id in consts:
                        out[node.name].add(consts[a.id])
    return out


def references() -> dict[str, set[str]]:
    """Path -> the files that name it, from templates and ION's own scripts."""
    out: dict[str, set[str]] = defaultdict(set)
    files = [f for f in sorted(TEMPLATES.rglob("*.html"))]
    files += [f for f in sorted(STATIC.glob("js/*.js")) if not VENDOR.search(f.name)]
    for f in files:
        text = strip_comments(f.read_text(encoding="utf-8", errors="replace"))
        for m in REF.finditer(text):
            url = m.group(1)
            if "${" in url or "{{" in url:
                url = url.split("${")[0].split("{{")[0]
            # a sentence's full stop, a closing paren, a trailing slash
            url = url.rstrip("/?&.,;:)\"'`")
            if not url or "..." in url:
                continue
            out[url].add(str(f.relative_to(ROOT)).replace("\\", "/"))
    return out


def normalise(path: str) -> str:
    """A route path with its parameters blanked, for matching a reference."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def collect() -> list[dict]:
    from ion.web.server import app

    rendered = templates_rendered()
    rows = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        endpoint = getattr(route, "endpoint", None)
        if not path or not methods or endpoint is None:
            continue
        name = getattr(endpoint, "__name__", "")
        file, line = handler_site(endpoint)
        rows.append({
            "path": path,
            "methods": sorted(m for m in methods if m != "HEAD"),
            "handler": name,
            "file": file,
            "line": line,
            "permission": permission_of(route),
            "templates": sorted(rendered.get(name, ())),
            "alias": str(getattr(route, "name", "")).endswith("__alias"),
        })
    rows.sort(key=lambda r: (r["path"], r["methods"]))
    return rows


def match_references(rows, refs):
    """Attach callers to routes, and find references that match no route."""
    by_shape = defaultdict(list)
    for r in rows:
        by_shape[normalise(r["path"])].append(r)
        r["callers"] = set()

    unmatched = {}
    for url, files in refs.items():
        shape = normalise(url)
        hit = by_shape.get(shape)
        if hit is None:
            # A reference that names a parameterised route's stem, or a base
            # a script concatenates onto, such as `const DE_API = '/api/de'`.
            # Those are correct and must not read as dangling.
            hit = [r for s, rs in by_shape.items() for r in rs
                   if s.startswith(shape.rstrip("/") + "/")] or None
        if hit:
            for r in hit:
                r["callers"] |= files
        else:
            unmatched[url] = files
    return unmatched


def render_markdown(rows, unmatched) -> str:
    ui = [r for r in rows if r["path"].startswith("/ui/")]
    api = [r for r in rows if r["path"].startswith("/api/")]
    other = [r for r in rows if r not in ui and r not in api]
    aliases = [r for r in rows if r["alias"]]
    ungated = [r for r in api if not r["permission"]]
    uncalled = [r for r in ui if not r["callers"]]

    L: list[str] = []
    add = L.append
    add("# ION route map")
    add("")
    add("Generated by `tools/route_map.py`. Do not edit by hand; run the tool.")
    add("")
    add(f"- **{len(rows)}** routes: {len(api)} under `/api`, {len(ui)} under "
        f"`/ui`, {len(other)} elsewhere")
    add(f"- **{len(aliases)}** are canonical path aliases registered in "
        f"`server.py`, which appear in no decorator")
    add(f"- **{len(ungated)}** `/api` routes carry no permission dependency")
    add(f"- **{len(uncalled)}** `/ui` fragment routes are named by no template "
        f"or script")
    add(f"- **{len(unmatched)}** referenced paths match no route")
    add("")

    if unmatched:
        add("## Referenced but not served")
        add("")
        add("A URL a template or script names that no route answers. Check "
            "these first when something silently does nothing: a `fetch` that "
            "404s is usually swallowed.")
        add("")
        add("| path | named in |")
        add("| --- | --- |")
        for url in sorted(unmatched):
            where = ", ".join(f"`{f}`" for f in sorted(unmatched[url])[:3])
            add(f"| `{url}` | {where} |")
        add("")

    for title, group, note in (
        ("/ui fragments", ui,
         "Server-rendered fragments. `render_view` routes also answer the "
         "view model as JSON to a caller sending `Accept: application/json`."),
        ("/api", api, "JSON endpoints."),
        ("Everything else", other, "Pages, static mounts and infrastructure."),
    ):
        if not group:
            continue
        add(f"## {title}")
        add("")
        add(note)
        add("")
        add("| method | path | permission | handler | renders | called from |")
        add("| --- | --- | --- | --- | --- | --- |")
        for r in group:
            methods = "/".join(r["methods"])
            site = f"[{r['file'].split('/')[-1]}:{r['line']}]({r['file']}#L{r['line']})" \
                if r["file"] else ""
            tpl = "<br>".join(f"`{t}`" for t in r["templates"]) or ""
            callers = ", ".join(f"`{c.split('/')[-1]}`"
                                for c in sorted(r["callers"])[:4]) or ""
            if len(r["callers"]) > 4:
                callers += f" +{len(r['callers']) - 4}"
            flag = " *(alias)*" if r["alias"] else ""
            perm = f"`{r['permission']}`" if r["permission"] else "—"
            add(f"| {methods} | `{r['path']}`{flag} | {perm} | "
                f"{site} | {tpl} | {callers} |")
        add("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the written map is out of date")
    ap.add_argument("--broken", action="store_true",
                    help="print referenced-but-not-served paths and exit")
    args = ap.parse_args()

    rows = collect()
    unmatched = match_references(rows, references())

    if args.broken:
        for url in sorted(unmatched):
            print(f"{url}  <- {', '.join(sorted(unmatched[url]))}")
        return 1 if unmatched else 0

    text = render_markdown(rows, unmatched)
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is out of date; "
                  f"run python tools/route_map.py")
            return 1
        print(f"{OUT.relative_to(ROOT)} is current")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} routes, "
          f"{len(unmatched)} dangling references")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
