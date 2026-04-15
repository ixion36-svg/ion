"""
Second-pass template refinement: convert legacy `.page-header` wrappers into
Tailwind flex sections across every template that was bulk-ported.

The first pass (port_templates.py) wrapped the content block in .ion-tw-page
and restyled <h1>. This pass replaces the legacy page-header div with a clean
Tailwind flex section so the header buttons align properly without style.css.
"""

from pathlib import Path
import re

TEMPLATES_DIR = Path(r"C:\Users\Tomo\ixion\src\ion\web\templates")

# Pages where the header has already been hand-crafted in this session.
ALREADY_DONE = {
    "alerts.html", "cases.html", "observables.html",
    "dashboard_v2.html",
    "playbooks.html", "cyab.html", "detection_engineering.html",
    "threat_intel.html", "forensics.html", "analyst.html",
    "base.html", "_components.html", "_icons.html",
    "login.html", "index.html",
}

# Replace `<div class="page-header" [any style]> ... </div>` where
# contents include an h1 with the Tailwind class from the bulk port.
# We'll just turn the opening div into a Tailwind section and the closing
# div into /section.
OPEN_RX = re.compile(
    r'<div\s+class="page-header"(?:\s+[^>]*)?>',
    re.MULTILINE,
)

SECTION_OPEN = (
    '<section class="flex items-end justify-between flex-wrap gap-6 mb-8 rise d-1">'
)

# Replace `header-actions` inner div with a Tailwind flex gap row (keeps any
# existing children like legacy <button class="btn"> but places them in a row).
HEADER_ACTIONS_RX = re.compile(
    r'<div\s+class="header-actions"(?:\s+[^>]*)?>',
    re.MULTILINE,
)

HEADER_ACTIONS_OPEN = (
    '<div class="flex items-center gap-2 flex-wrap">'
)


def process(path: Path) -> bool:
    if path.name in ALREADY_DONE:
        return False
    src = path.read_text(encoding="utf-8")
    if '<div class="page-header"' not in src and "class='page-header'" not in src:
        return False

    # Step 1: open-tag substitution
    new_src = OPEN_RX.sub(SECTION_OPEN, src)

    # Step 2: Find each opened section and replace its matching </div> with </section>.
    # Simple approach: walk through and pair braces.
    out = []
    i = 0
    while i < len(new_src):
        if new_src[i:i + len(SECTION_OPEN)] == SECTION_OPEN:
            # Find matching close by depth-counting <div> and </div>.
            out.append(SECTION_OPEN)
            i += len(SECTION_OPEN)
            depth = 1
            while i < len(new_src) and depth > 0:
                # Cheap tokenisation — look for next `<div` or `</div>`
                next_open = new_src.find("<div", i)
                next_close = new_src.find("</div>", i)
                if next_close == -1:
                    # Malformed — bail
                    out.append(new_src[i:])
                    i = len(new_src)
                    break
                if next_open != -1 and next_open < next_close:
                    out.append(new_src[i:next_open + 4])  # include "<div"
                    i = next_open + 4
                    depth += 1
                else:
                    out.append(new_src[i:next_close])
                    if depth == 1:
                        out.append("</section>")
                    else:
                        out.append("</div>")
                    i = next_close + len("</div>")
                    depth -= 1
        else:
            # Copy char
            out.append(new_src[i])
            i += 1
    new_src = "".join(out)

    # Step 3: header-actions div → Tailwind flex row (don't touch closing tag — it's paired with any </div>)
    new_src = HEADER_ACTIONS_RX.sub(HEADER_ACTIONS_OPEN, new_src)

    if new_src == src:
        return False
    path.write_text(new_src, encoding="utf-8")
    return True


def main():
    touched = 0
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        if process(path):
            touched += 1
            print(f"  fixed: {path.name}")
    print(f"\n{touched} pages updated")


if __name__ == "__main__":
    main()
