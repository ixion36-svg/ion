# Converting a page's `server` column

The redesign's `server` column passes when a template contains no
`innerHTML`, `insertAdjacentHTML` or `outerHTML`. The reason is not taste.
Markup assembled from strings in JavaScript cannot be restyled from the
stylesheet, so every such site is a place a sweep silently fails to reach,
and the sweep reports success.

Worked examples, in increasing order of how much they cover:

* `src/ion/web/ui/service_accounts.py` with `_fragments/service_accounts.html`.
  Two parallel fetches and 55 lines of concatenation, including a
  hand-rolled `esc()`, became one request.
* `src/ion/web/ui/bob_eval.py` with `_fragments/bob_eval_samples.html`.
  A paginated table whose pager is htmx rather than JavaScript.

## The shape

The page template keeps its shell and holds an empty slot:

```jinja
<div id="x-content" hx-get="/ui/x" hx-trigger="load" hx-swap="innerHTML">
  <div class="text-center p-10 text-base-content/60">
    <span class="loading loading-spinner loading-sm text-primary"></span>
    Loading...
  </div>
</div>
```

`hx-trigger="load"` keeps the shell's first paint immediate and the data
arriving in its own request, which is what the fetch it replaces already
did. A Refresh button is `hx-get` at the same URL, so "what refresh does"
has one definition.

The fragment carries the card chrome, not the page. That removes the
hidden/reveal dance: nothing requested means nothing shown.

## Rules that came from defects

**Reuse the function the JSON endpoint calls.** If the pagination maths or
a feature gate sits inline in the JSON route, extract it to a
`*_payload(...) -> dict | None` and have both call it. `bob_eval_api` is
the example. A second copy of a feature gate keeps emitting after the flag
flips.

**Permission matches the JSON endpoint exactly.** A fragment must never be
a softer way in than the API it mirrors. Use `require_permission`, not
`require_page_permission`: the page dependency redirects to `/login`, and
htmx would swap a login form into the middle of a dashboard.

**`is not none`, never truthiness, for any number.** `{% if age %}` renders
a password changed today as "Unknown". Zero is a measurement. The
JavaScript being replaced usually got this right with `!= null`, so a
truthiness port is a regression, not a port.

**Three-state booleans stay three.** `{% if x is true %}` / `{% elif x is
false %}` / `{% else %}`. A truthiness test folds None into the false
branch, which turns "declined to judge" into "was wrong".

**A failed read is not empty data.** Catch, log with `logger.exception`,
and render a fragment that says the read failed. Never print 0 for it.
"Nothing there" and "we could not look" lead to opposite actions. This is
the same honesty rule the services follow: unknown is not healthy, and
unmeasured is not zero.

**Chrome wraps both states.** If the panel has a Close button, the error
branch needs it too, and the heading needs a value that exists when the
payload is None (pass it from the route). Otherwise an error swap strands
the panel open with no way out but a reload. This one was invisible in the
template and only showed up when the pager was driven in a browser.

**Build a URL as one value.** `{{ base }}&page={{ n }}` emits `&amp;` for
the variable's ampersand and a bare `&` for the literal one, because
template text is not escaped and a variable is. Use
`{% set u = '...?a=' ~ x ~ '&b=' ~ y %}` and then `{{ u ~ '&page=' ~ n }}`.

**Delete the hand-rolled `esc()`.** Jinja autoescapes. Assert it with a
test that feeds `<script>`.

## Files you own

One page per conversion, and nothing shared:

```
src/ion/web/ui/<page>.py                      new
src/ion/web/templates/_fragments/<page>*.html new
src/ion/web/templates/<page>.html             edit
tests/unit/test_ui_fragment_<page>.py         new
```

Registration is discovery, so there is no list to add to. Do not touch
`ui/__init__.py`, `ui/_shared.py`, `tests/unit/test_ui_fragments.py`,
`tests/unit/test_ui_fragment_registry.py`, `frontend/*.css` or any other
page's files. Import the shared Jinja env with
`from ion.web.ui._shared import templates`; never call `make_templates()`
in a page module.

## Verifying

Jinja `auto_reload` is off outside debug, so a template edit needs a server
restart before any browser check means anything.

1. `python tools/ui_redesign_status.py` shows the page with `server` yes and
   a writes count of 0.
2. The page answers 200, the fragment answers 200 authed and 401 unauthed.
3. `node --check` on any JavaScript left in the page.
4. Drive anything interactive in a browser. Tests read the template; the
   browser is what catches a swap that removes its own escape hatch.
5. Targeted tests pass. Leave the full suite to the end of the batch.

A test that passes the moment you write it has proved nothing. Make each
one fail first, for the reason you expect.
