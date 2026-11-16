/* Show that a fragment request is in flight, on the thing being replaced.
 *
 * The JavaScript these fragments replace wrote a spinner into the
 * container before every fetch, so a filter change or a Refresh click
 * visibly did something. htmx does not: the old content stays until the
 * response arrives and is swapped. On a slow query that reads as a click
 * that did nothing, and the user clicks again.
 *
 * htmx's own answer is `hx-indicator`, which needs a spinner element and
 * an attribute on every page. That is fine and a page wanting a stronger
 * cue should still declare one. But it is per-page markup, and the gap is
 * in all of them, so the shared half is done here: htmx tells us which
 * element is about to be replaced, and we mark it for the duration.
 *
 * `.ion-busy` is defined in frontend/ion-legacy.css, so the appearance is
 * in the stylesheet like everything else rather than inline here.
 *
 * This adds and removes a class. It builds no markup, so a page relying on
 * it still passes the redesign's `server` column.
 */
(function () {
  'use strict';

  function target(evt) {
    return evt && evt.detail ? evt.detail.target : null;
  }

  document.addEventListener('htmx:beforeRequest', function (evt) {
    var el = target(evt);
    // The swap target, not the element that triggered the request. A
    // Refresh button dimming itself tells the user their click landed; the
    // table going quiet tells them what is being replaced, which is the
    // part that was missing.
    if (el && el.classList) el.classList.add('ion-busy');
  });

  function clear(evt) {
    var el = target(evt);
    if (el && el.classList) el.classList.remove('ion-busy');
  }

  // afterRequest covers success and a non-2xx alike. The error handler in
  // htmx-errors.js replaces the target's children on a failure, so the
  // class has to come off either way or a failed panel stays dimmed and
  // reads as still loading, which is the exact confusion this removes.
  document.addEventListener('htmx:afterRequest', clear);
  document.addEventListener('htmx:sendError', clear);
  document.addEventListener('htmx:timeout', clear);
  document.addEventListener('htmx:responseError', clear);
})();
