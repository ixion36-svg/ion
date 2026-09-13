Convert the hashed CSP classes in exactly one Jinja2 template to Tailwind
utilities:

    src/ion/web/templates/<PAGE>.html

This is ION, an air-gapped SOC platform. `static/css/ion.css` is already built
and loaded, providing Tailwind v4 utilities plus daisyUI 5.

## Background: what `_ion-s-*` classes are

They are NOT dynamic-value carriers, despite what older docs in this repo say.
They are static styling — `color`, `font-size`, `padding`, `margin`, `display`
— that the v0.31.21 migration hashed out of inline `style="..."` attributes to
satisfy `style-src-attr 'none'`. Measured: 894 of 905 rules are plain static
styling, and no template constructs one in JavaScript.

Now that Tailwind utilities are available on every page, these classes are
redundant. Your job is to replace them with the equivalent utilities.

## Use the lookup table. Do not improvise.

`tools/hashed_class_map.json` maps every hashed class to its Tailwind
equivalent. Read it. Each entry looks like:

    "ion-s-59b87fdbd1": {
      "css": "margin-bottom:0.5rem;",
      "tailwind": "mb-2",
      "kind": "exact",
      "unmapped": []
    }

For each `_ion-s-XXXX` in the template:

- `"kind": "exact"` or `"arbitrary"` — replace the hashed class with the
  `tailwind` string, in place, keeping every other class on that element.
- `"kind": "manual"` — **LEAVE THE HASHED CLASS EXACTLY AS IT IS.** Its
  `unmapped` list shows declarations with no clean utility. Do not guess at
  these; a wrong margin or colour is invisible and will not be noticed.

Do not derive your own Tailwind for a rule. If a class is not in the table,
leave it alone and say so in your report.

## Rules

**1. NEVER introduce a raw `style="..."` attribute.** It is silently refused by
the browser under `style-src-attr 'none'` — no error, no console warning, no
failed request, just an unstyled element.

**2. Touch only the one template named above.** Do not edit
`tools/hashed_class_map.json`, `tools/ui_rewrite_baseline.json`, or
`src/ion/web/static/css/ion-migrated-styles.css`.

**3. Change nothing but the class attributes.** Keep all Jinja logic, block
structure, `hx-*` attributes, `data-*` hooks (especially `data-click-action`
and `data-keydown-action`), element ids, and all JavaScript exactly as they
are. This pass edits classes and nothing else.

**4. Watch for classes referenced from JavaScript.** If a `_ion-s-*` string
appears inside a `<script>` block or a `querySelector`, converting the markup
without converting the script breaks the lookup. Search the template's
JavaScript before you change a class, and if a class is referenced in script,
leave it and report it.

## Before you report back

Run:

    python tools/ui_rewrite_audit.py --check

This currently fails on *lost* hashed classes, which is the opposite of this
pass's goal, so ignore what it says about losses in your own file. What matters
is that it reports no NEW raw inline styles.

Then report:
1. The file you changed
2. How many hashed classes you converted, and how many you left (with reasons)
3. Any class you found referenced from JavaScript
4. Anything in the table you disagreed with and did not apply
