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
