/* Say so when a fragment request fails, instead of spinning forever.
 *
 * htmx deliberately does not swap a non-2xx response, which is the right
 * default: swapping a 403 body, or a login form, into the middle of a
 * dashboard shows the user a lie. But the consequence is that the
 * placeholder stays put, and every converted page's placeholder is a
 * spinner reading "Loading...". So an expired session, a revoked
 * permission or a 500 all leave the page claiming to still be working.
 *
 * The JavaScript these fragments replace caught `!response.ok` and said
 * "Failed to load", so without this the conversion is a regression in
 * exactly the case where the user most needs to be told.
 *
 * This is the one definition of that behaviour. A per-page handler was the
 * alternative, and that is one copy per page of a decision about what an
 * expired session means.
 *
 * It builds no markup. The alert lives in a <template> in base.html, so
 * the stylesheet reaches it like anything else, and this clones the node
 * and sets textContent. A string assigned to textContent is text, not
 * markup, so a page relying on this still passes the redesign's `server`
 * column.
 */
(function () {
  'use strict';

  var MESSAGES = {
    403: 'You do not have permission to view this. Nothing is missing from '
       + 'the system: this account cannot read it.',
    404: 'This is no longer available. It may have been deleted since the '
       + 'page was opened.',
    network: 'The server could not be reached. This is not an empty result: '
           + 'nothing here has been measured.',
    server: 'The server failed to produce this. This is not an empty result: '
          + 'nothing here has been measured.',
  };

  function messageFor(status) {
    if (MESSAGES[status]) return MESSAGES[status];
    if (!status) return MESSAGES.network;
    return MESSAGES.server;
  }

  function show(target, status) {
    if (!target) return;

    var tpl = document.getElementById('htmx-error-template');
    if (!tpl || !tpl.content) {
      // No template on this page. Plain text still beats a spinner that
      // claims to be loading something that will never arrive.
      target.textContent = messageFor(status);
      return;
    }

    var node = tpl.content.firstElementChild.cloneNode(true);
    var slot = node.querySelector('[data-error-message]');
    if (slot) slot.textContent = messageFor(status);

    // Append failures keep the already loaded page; replacement failures
    // remove the loading placeholder.
    if (target.hasAttribute('data-ion-fragment-append')) {
      node.setAttribute('data-ion-append-error', '');
      target.append(node);
    } else {
      target.replaceChildren(node);
    }
  }

  function handle(evt) {
    var detail = evt.detail || {};
    var status = detail.xhr ? detail.xhr.status : 0;

    // An expired session is the one case where staying on the page is not
    // the honest answer: nothing on it will refresh again. Send them to
    // the login form with somewhere to come back to.
    if (status === 401) {
      var back = window.location.pathname + window.location.search;
      window.location.href = '/login?redirect=' + encodeURIComponent(back);
      return;
    }

    show(detail.target, status);
  }

  document.addEventListener('htmx:responseError', handle);
  document.addEventListener('htmx:sendError', handle);
  document.addEventListener('htmx:timeout', handle);
})();
