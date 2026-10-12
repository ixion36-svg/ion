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

## Start here

    python tools/fragment_plan.py <page>

It prints the page's own route and permission, every URL its JavaScript
fetches with the method and gates each one actually carries, the innerHTML
sites with line numbers, and which of the traps below the page is likely to
hit. The gates are read off the live application, out of the closure cell
`require_permission` closes over, so they are what a request really meets
rather than what the decorator looks like.

Five conversions worked this out by hand before the tool existed. The one
thing among it that is easy to get wrong is the permission, because a
fragment softer than the API it mirrors is not visible in a diff. Where the
tool prints `a guess, confirm it`, confirm it.

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

**Never format a timestamp on the server.** The JavaScript called
`toLocaleString()`, which is the viewer's clock. A server knows only its
own, so a server-formatted timestamp shows an analyst in another timezone
the wrong time on every row. Use the macro:

```jinja
{% from "_fragments/_time.html" import ts %}
<td>{{ ts(log.timestamp) }}</td>
<td>{{ ts(run.started_at, 'time') }}</td>
<td>{{ ts(row.due, fallback='Not scheduled') }}</td>
```

It emits `<time datetime>` with a UTC-labelled fallback, and
`static/js/local-time.js` rewrites the text after load and after every
htmx swap. That assignment is `textContent`, so the `server` column still
passes. A missing timestamp renders the fallback, never the epoch.

**Unwrap SQLEnum columns with `ui._shared.plain`.** ION's status, severity
and risk columns are `SQLEnum`, so a row read through the ORM carries the
enum member. The JSON endpoints got the string for free because FastAPI
serialises a str-mixin enum by value. A template does not: on Python 3.12
`str(ChangeRequestStatus.SUBMITTED)` is `"ChangeRequestStatus.SUBMITTED"`,
which is what the pill renders. Value equality still holds, so a colour map
keyed by the string keeps working and only the visible text is wrong, which
is why it survives a glance. Two conversions hit this independently.

**Do not write your own failure handler.** `static/js/htmx-errors.js` is
the one definition: a 401 redirects with a way back, and everything else
clones an alert out of a template in base.html into the failed target. A
per-page listener is one copy per page of a decision about what an expired
session means. Your route should still catch what it can and return a 200
fragment that says the read failed, because that is the case you can word
properly.

**Keep the controls outside the swap target.** A filter, a window select or
a Refresh button inside the fragment is removed by any render that does not
include it, so a failed read can take away the control that would retry.
Put them in the page shell and send their values with `hx-include`. If a
control must be in the fragment because only the fragment knows its state,
re-render it with its state and say so in a comment.

**Put any stored URL through `|safe_url`.** Jinja escapes characters, not
schemes, so `href="{{ row.url }}"` with `javascript:alert(1)` in that
column renders a link that executes on click. The filter allows http,
https, mailto and a site-relative path, and drops everything else including
protocol-relative `//host`, stripping the ASCII whitespace and control
characters a browser strips before reading the scheme.

**You get the in-flight cue for free, so do not build one.**
`static/js/htmx-busy.js` marks the element htmx is about to replace with
`.ion-busy` for the duration of the request, and the stylesheet fades it.
htmx leaves the old content on screen until the response arrives, so
without that a filter change on a slow query reads as a click that did
nothing and the user clicks again. The content is dimmed rather than
blanked on purpose: the figures on screen are still the last ones that
were really read, and replacing them with a spinner throws away true
information to announce that newer information is coming. A page wanting a
stronger cue can still declare `hx-indicator`, which now works, because
the `.htmx-indicator` pair is defined in `frontend/ion-legacy.css`.

**No htmx feature that compiles a string.** ION serves
`script-src 'self' 'nonce-...'` with no `unsafe-eval`, so anything htmx
hands to `Function()` throws and the feature silently does nothing. That
rules out an `hx-trigger` event filter such as
`hx-trigger="keyup[key=='Enter']"`, the `js:` form of `hx-vals` and
`hx-headers`, and `hx-on`. For an Enter key, wrap the controls in a real
`<form>` carrying the `hx-get`: it submits natively, needs no expression,
and still works with htmx disabled.

This is invisible outside a browser console. The markup looks right and
the fragment the server returns is right, so a conversion that reads
correctly and passes every HTTP check still ships a dead control. A
browser smoke crawl across the converted pages is what found the one
instance. `tests/test_review_20261008_page_wiring_guards.py` now guards
all three.

**A nested request must not send a parameter twice.** `hx-include` is
inherited, so every element your fragment renders inside a container that
carries one sends that control's value on its own requests too. Where the
inner request also bakes that same parameter in server-side, it goes out
twice and FastAPI reads the last copy, which is the appended inherited one.
The control then decides the parameter and the baked value is ignored, which
is the reverse of what the markup says.

The defect is the duplicate, not the inheritance. Inheritance is often the
mechanism you want: a nested control that needs the page's current filters
is how it gets them. Do not strip a container's `hx-include` to stop a
duplicate, and do not add `hx-disinherit` reflexively. Work out which of
the two is sending the parameter and remove that one:

    <div id="x-content"
         hx-get="/ui/x/panel"
         hx-trigger="load"
         hx-include="#x-days"
         hx-disinherit="hx-include"
         hx-swap="innerHTML">

`hx-disinherit` governs only what children inherit, so the container's own
request still sends the control, and an element with its own `hx-include`
uses that rather than the inherited one either way. Guard both halves,
because deleting the container's `hx-include` to stop a duplicate breaks the
restored-select case it was added for.

Two pages had it, found independently: `detection_health` through its
drill-down, where `drill_url` baked `days` and the panel sent `days`, and
`stories` through its nested run table, which was one disagreement away
from a 422. In both the two copies agreed, so nothing looked wrong.

All fourteen containers of this shape have now been checked. Ten render no
nested request at all, so nothing inherits. `audit_logs` and
`entity_timeline` both render one and are clean, measured in a browser:
`audit_logs` pagination declares its own `hx-include`, and
`entity_timeline` bakes `sources`, which its container does not send, so it
is clean whether the pill declares an include or inherits one. Both were
measured rather than read, including by injecting a control into the real
container where the dev data rendered none.

None of this is visible in the markup or in an HTTP check, and a static
scan cannot see it: a request URL built from a Jinja expression such as
`hx-get="{{ row.drill_url }}"` has no literal query string to find, which
is exactly the shape that carries the duplicate. Measure the request the
browser sends, with a listener on `page.on("request")`.

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

## Guards you will be measured against

`tests/unit/test_ui_fragment_registry.py` holds the invariants that apply
to every fragment, so they are a check rather than a line in 35 briefs.
Run it with your own tests. It asserts that your module is discovered and
mounted, that your route requires authentication, that it declares
`response_class=HTMLResponse`, and that it uses no redirecting page
dependency. If your endpoint mirrors a JSON endpoint that gates on bare
`get_current_user` rather than a named permission, add its path to
`BARE_AUTH_FRAGMENTS` with a comment saying why, which is the point: that
drop has to be a claim somebody made on purpose.

## Two ways a test of yours will lie to you

Both were found by mutation passes, not by reading, and both are likely
rather than unlikely on these conversions.

**A page-level substring assertion passes on your own comment.** One
conversion asserted `'hx-params="none"' in src` over the whole page, and
removing the attribute from the button left it green, because the comment
two lines above the button quotes the attribute by name. These conversions
carry a lot of explanatory comments, so every whole-file substring
assertion is exposed. Extract the element first and assert inside it, or
strip comments before matching. The same shape has bitten three times now:
a test asserting a deleted helper was gone matched the comment explaining
its deletion, a CSS guard flagged a Jinja comment that mentioned
`<script>`, and Tailwind emitted a utility because a comment named it.

**A three-state test that only arranges `None` is vacuous.** `None`
behaves identically under `is true`, truthiness and `is not None`, so no
plausible mutation can fail it. Parametrise over a non-boolean too, and
mutate by deleting the middle branch rather than weakening the first
condition, which changes nothing while the `elif` still catches `None`.

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
