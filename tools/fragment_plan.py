"""What one page needs before its `server` column can be converted.

Every conversion starts by rediscovering the same facts: which permission
the page is behind, which endpoints its JavaScript fetches, what those
endpoints are gated on, where the innerHTML sites are, and which of the
known traps the page is going to hit. Five conversions did that by hand,
and the one thing among them that is easy to get wrong is the permission,
because a fragment that is softer than the API it mirrors is not visible
in a diff.

So it is a tool rather than a paragraph of instructions. Read-only.

    python tools/fragment_plan.py audit_logs
    python tools/fragment_plan.py --all        # every unconverted page

The permission it prints for an endpoint is read out of the closure cell
`require_permission` closes over, not guessed from the source text, so a
route built by a decorator stack still reports correctly.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

# This prints arbitrary lines out of ION's templates, which contain box
# drawing and arrow characters. Windows defaults stdout to cp1252, so one
# such line aborted a --all run partway through with a UnicodeEncodeError
# and the pages after it were silently never planned.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
TEMPLATES = SRC / "ion" / "web" / "templates"
WEB = SRC / "ion" / "web"

EXPLICIT: dict = {}

WRITE_RE = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")
FETCH_RE = re.compile(r"""fetch\(\s*[`'"]([^`'"]+)""")
TEMPLATED_FETCH_RE = re.compile(r"""fetch\(\s*`([^`]+)`""")
SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S)


def _page_table() -> dict[str, tuple[str, str]]:
    """template name -> (url path, permission), from server.py's _PAGES.

    Parsed rather than imported: importing server pulls in the whole app,
    a database and a licence check, and this has to run before any of that
    is set up.
    """
    tree = ast.parse((WEB / "server.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets = getattr(node, "targets", []) or ([node.target] if hasattr(node, "target") else [])
        for t in targets:
            if isinstance(t, ast.Name) and t.id == "_PAGES":
                out = {}
                for row in node.value.elts:
                    try:
                        path, template, perm = [ast.literal_eval(e) for e in row.elts]
                    except (ValueError, AttributeError):
                        continue
                    out[template] = (path, perm)
                return out
    return {}


def _inline_js(html: str) -> str:
    return "\n".join(SCRIPT_RE.findall(html))


def _endpoint_gates() -> dict[str, list[str]]:
    """url path -> the gates on it, read off the live application.

    Source parsing got this wrong in a way that mattered. api.py declares
    its router with no prefix and server.py mounts it under /api, so every
    route came out as /users rather than /api/users and nothing matched.
    Importing the app costs a few seconds and is authoritative: it reports
    the gates a request actually meets, including ones contributed by the
    router or the mount rather than the decorator.

    The permission is read out of the closure cell require_permission
    closes over, so a factory-built dependency reports its real argument
    instead of the word "dependency".
    """
    sys.path.insert(0, str(SRC))
    from ion.web.server import app  # noqa: E402  (needs the path above)

    gates: dict[str, dict[str, list[str]]] = {}
    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        methods = sorted(getattr(route, "methods", None) or ["GET"])
        found: list[str] = []
        stack = list(dependant.dependencies)
        while stack:
            dep = stack.pop()
            call = dep.call
            if call is not None:
                name = getattr(call, "__qualname__", "") or ""
                base = name.split(".")[0]
                if base in ("require_permission", "require_any_permission"):
                    cells = dict(zip(
                        call.__code__.co_freevars,
                        (c.cell_contents for c in (call.__closure__ or ())),
                    ))
                    arg = cells.get("permission_name") or cells.get("permission_names")
                    found.append(f"{base}({arg!r})")
                elif base in ("require_admin", "get_current_user",
                              "require_page_permission", "require_page_auth",
                              "require_de_module", "require_workforce_module"):
                    found.append(base)
            stack.extend(dep.dependencies)
        for method in methods:
            # Keyed by method as well as path. Merging them reported
            # require_permission('user:create') for a GET of /api/users,
            # because POST on the same path has the stricter gate and the
            # first version kept whichever had more of them.
            gates.setdefault(route.path, {})[method] = sorted(set(found))
    return gates


def _explicit_page_routes() -> dict[str, tuple[str, str]]:
    """template -> (url, gates) for pages registered as their own handler.

    Half of ION's pages are rows in _PAGES and half are `@app.get`
    functions. A conversion that only checked the table reported "(not in
    _PAGES)" and had nothing to match its fragment's permission against.
    """
    out: dict[str, tuple[str, str]] = {}
    # Every web module, not just server.py: a page handler also lives next
    # to its own API, as change_requests.html does in change_request_api.py,
    # and the first version reported "(unknown)" for those.
    nodes = []
    for py in sorted(WEB.glob("*.py")):
        prefix = ""
        text = py.read_text(encoding="utf-8")
        m = re.search(r"APIRouter\(\s*prefix\s*=\s*[\"']([^\"']+)", text)
        if m:
            prefix = m.group(1)
        for n in ast.walk(ast.parse(text)):
            nodes.append((n, prefix))
    for node, _prefix in nodes:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = ast.unparse(node)
        templates = re.findall(r"""['\"]([a-z0-9_]+[.]html)['\"]""", body)
        if not templates:
            continue
        url = None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, "attr", "") == "get" and dec.args:
                try:
                    url = ast.literal_eval(dec.args[0])
                except ValueError:
                    pass
        if url is None:
            continue
        sig = ast.unparse(node.args)
        perms = re.findall(
            r"""require_(?:page_)?permission[(]\s*['\"]([^'\"]+)""", sig)
        if perms:
            gate = perms[0]
        else:
            # The argument may be a constant rather than a literal, which is
            # the better pattern: change_request_api passes _PERM so the page
            # and its API cannot drift. Report the expression instead of
            # "(no gate found)", which was actively misleading.
            expr = re.search(
                r"require_(?:page_)?permission[(]\s*([A-Za-z_][\w.]*)", sig)
            if expr:
                gate = f"{expr.group(1)} (a constant, resolve it in the module)"
            elif "require_page_auth" in sig:
                gate = "require_page_auth (any logged-in user)"
            elif "require_admin" in sig:
                gate = "require_admin"
            else:
                gate = "(no gate found in the signature)"
        for t in set(templates):
            out.setdefault(t, (_prefix + url, gate))
    return out


def _resolve_js_constants(js: str, urls: list[str]) -> list[str]:
    """Substitute `${API_BASE}` style constants declared in the same script.

    Eight of the remaining pages hold their base path in a const and build
    every URL from it, so without this the tool reported "check by hand"
    for exactly the pages it was written to help. Only string literals are
    substituted; anything computed stays as it is, because a guess here
    would report a permission for the wrong endpoint.
    """
    consts = dict(re.findall(
        r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"]([^'"]+)['"]""", js))
    out = []
    for url in urls:
        resolved = url
        for name, value in consts.items():
            resolved = resolved.replace("${" + name + "}", value)
        out.append(resolved)
    return out


def _match_gate(url: str, gates: dict) -> list[tuple[str, dict]]:
    """Every declared route whose shape matches a fetched URL.

    A fetched URL carries real values, a template literal carries `${id}`,
    and a declared route carries `{param}`. The first version treated an
    interpolation as matching anything, so `/api/users/${userId}` matched
    the literal `/api/users/assignable`. An interpolated segment now
    matches only a parameter segment, and a literal fetched segment
    prefers a literal route segment over a parameter one.
    """
    want = [s for s in url.split("?")[0].split("/") if s]
    exact: list[tuple[str, dict]] = []
    loose: list[tuple[str, dict]] = []
    for route, by_method in gates.items():
        have = [s for s in route.split("/") if s]
        if len(have) != len(want):
            continue
        literal = 0
        ok = True
        for h, w in zip(have, want):
            interpolated = "${" in w or w.startswith(":")
            if h.startswith("{"):
                ok = ok and True
            elif interpolated:
                # A real value went here, so a literal route segment is a
                # different endpoint, not this one.
                ok = False
            elif h == w:
                literal += 1
            else:
                ok = False
        if not ok:
            continue
        (exact if literal == len(want) else loose).append((route, by_method))
    if exact or loose:
        return exact or loose

    # Nothing matched under the strict rule. Retry letting an interpolated
    # segment stand in for a literal one, because a page sometimes selects
    # among literal routes that way: /api/admin/config/${section} picks
    # between /api/admin/config/arkime and its siblings. These are labelled
    # as possibilities by the caller, never as the answer, since the strict
    # rule exists to stop /api/users/${id} matching /api/users/assignable.
    maybe: list[tuple[str, dict]] = []
    for route, by_method in gates.items():
        have = [s for s in route.split("/") if s]
        if len(have) != len(want):
            continue
        if all(h == w or h.startswith("{") or "${" in w for h, w in zip(have, want)):
            maybe.append((route, by_method))
    return [("MAYBE " + r, m) for r, m in maybe[:4]]


def plan(template: str, pages: dict, gates: dict) -> None:
    path = TEMPLATES / template
    if not path.exists():
        print(f"{template}: no such template")
        return
    html = path.read_text(encoding="utf-8")
    js = _inline_js(html)

    url, perm = pages.get(template, (None, None))
    if url is None:
        url, perm = EXPLICIT.get(template, ("(not found)", "(unknown)"))
    print(f"\n=== {template}")
    print(f"  page route        {url}")
    print(f"  page permission   {perm}")

    writes = [(i, line.strip()[:76])
              for i, line in enumerate(html.splitlines(), 1)
              if WRITE_RE.search(line)]
    print(f"  innerHTML sites   {len(writes)}")
    for lineno, text in writes:
        print(f"    {template}:{lineno}  {text}")

    urls = sorted(set(FETCH_RE.findall(js)) | set(TEMPLATED_FETCH_RE.findall(js)))
    urls = sorted(set(_resolve_js_constants(js, urls)))
    print(f"  fetches           {len(urls)}")
    for u in urls:
        print(f"    {u}")
        hits = _match_gate(u, gates)
        if not hits:
            print("      declared as   (no matching route found, check by hand)")
            continue
        for route, by_method in hits:
            for method, found in sorted(by_method.items()):
                if method in ("HEAD", "OPTIONS"):
                    continue
                label = route
                if route.startswith("MAYBE "):
                    label = route[6:] + "   <- a guess, confirm it"
                print(f"      {method:6} {label}")
                print(f"             gated on {', '.join(found) or '(nothing found)'}")

    traps = []
    if "toLocaleString" in js or "toLocaleDateString" in js or "new Date(" in js:
        traps.append("timestamps: use the ts macro, do not format server-side")
    if "esc(" in js or "escapeHtml" in js or "innerText" in js and "div" in js:
        traps.append("a hand-rolled esc(): Jinja autoescapes, delete it")
    if re.search(r"\|\|\s*0|\|\|\s*'-'|\|\|\s*\"-\"|\?\s*[\w.]+\s*:\s*0", js):
        traps.append("a `|| 0` or `? x : 0` default: that is how None becomes zero")
    if re.search(r"if\s*\(\s*!?\w+\.\w+\s*\)", js):
        traps.append("truthiness on a field: that is how a measured 0 becomes unknown")
    if "status" in js or "severity" in js or "risk" in js:
        traps.append("likely SQLEnum column: use ui._shared.plain")
    if 'href="' in html and "${" in js:
        traps.append("a URL built in JS: put any stored URL through |safe_url")
    if "localStorage" in js or "sessionStorage" in js:
        traps.append("browser storage: state that must survive belongs on the server")
    print(f"  likely traps      {len(traps)}")
    for t in traps:
        print(f"    - {t}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("page", nargs="*", help="template name, with or without .html")
    ap.add_argument("--all", action="store_true",
                    help="every template that still has an innerHTML site")
    args = ap.parse_args()

    pages = _page_table()
    globals()["EXPLICIT"] = _explicit_page_routes()
    gates = _endpoint_gates()

    if args.all:
        names = sorted(
            p.name for p in TEMPLATES.glob("*.html")
            if WRITE_RE.search(p.read_text(encoding="utf-8"))
        )
    elif args.page:
        names = [p if p.endswith(".html") else p + ".html" for p in args.page]
    else:
        ap.error("name a page, or pass --all")
        return 2

    for name in names:
        plan(name, pages, gates)
    return 0


if __name__ == "__main__":
    sys.exit(main())
