/* Render every server-emitted timestamp in the viewer's own timezone.
 *
 * Server-rendered fragments broke a thing the JavaScript they replaced got
 * right. Thirty-two templates formatted timestamps with
 * `new Date(x).toLocaleString()`, which is the viewer's clock. A fragment
 * rendered on the server knows only the server's clock, so moving those
 * tables to Jinja would have quietly shown an analyst in another timezone
 * the wrong time on every audit row. For a journal whose whole purpose is
 * "what happened when", that is worse than the string-building it fixed.
 *
 * So the server emits the machine-readable instant and a correct-but-UTC
 * fallback, and this localises it:
 *
 *   <time datetime="2026-10-12T09:41:07+00:00" data-ts-format="datetime">
 *     2026-10-12 09:41 UTC
 *   </time>
 *
 * The element already reads correctly before this runs and if this never
 * runs at all, because the fallback carries its zone. Nothing here builds
 * markup: it assigns textContent, so a page using it still passes the
 * redesign's `server` column.
 *
 * `data-ts-format` picks the presentation, defaulting to date and time:
 *   datetime  12/10/2026, 09:41:07
 *   date      12/10/2026
 *   time      09:41:07
 */
(function () {
  'use strict';

  var FORMATTERS = {
    datetime: function (d) { return d.toLocaleString(); },
    date: function (d) { return d.toLocaleDateString(); },
    time: function (d) { return d.toLocaleTimeString(); },
  };

  function localise(el) {
    // Done once per element. An htmx swap can re-deliver an element that
    // was already localised, and re-parsing a localised string with the
    // Date constructor is how you get "Invalid Date" on the second pass.
    if (el.dataset.tsLocalised === '1') return;

    var raw = el.getAttribute('datetime');
    if (!raw) return;

    var parsed = new Date(raw);
    if (isNaN(parsed.getTime())) {
      // Leave the server's fallback text in place. A timestamp we cannot
      // parse is not a timestamp we should blank: the audit row still has
      // to say when it happened, and the raw value is evidence.
      el.dataset.tsLocalised = '1';
      return;
    }

    var fmt = FORMATTERS[el.dataset.tsFormat] || FORMATTERS.datetime;
    el.textContent = fmt(parsed);
    el.dataset.tsLocalised = '1';
  }

  function localiseWithin(root) {
    if (!root || !root.querySelectorAll) return;
    if (root.matches && root.matches('time[datetime]')) localise(root);
    root.querySelectorAll('time[datetime]').forEach(localise);
  }

  window.ionLocaliseTimes = localiseWithin;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      localiseWithin(document);
    });
  } else {
    localiseWithin(document);
  }

  // Fragments arrive after load, so the swapped subtree needs the same
  // pass. Without this the first paint is local and every refresh is UTC,
  // which is the kind of inconsistency that reads as a data bug.
  document.addEventListener('htmx:afterSwap', function (evt) {
    localiseWithin(evt.detail && evt.detail.target ? evt.detail.target : document);
  });
})();
