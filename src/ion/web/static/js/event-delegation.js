/*
 * event-delegation.js (v0.31.4)
 *
 * Migration target for inline `onclick="foo()"` handlers. ION's CSP
 * (set in src/ion/web/server.py:SecurityHeadersMiddleware) is moving
 * toward `script-src-attr 'none'`, at which point browsers will block
 * every inline event handler. Templates migrating off `onclick=` swap
 * in `data-click-action="foo"` and rely on the single delegated
 * listener below to dispatch.
 *
 * Usage from a template:
 *
 *   <button data-click-action="toggleUserDropdown">User menu</button>
 *
 *   <a href="/somewhere"
 *      data-click-action="logout"
 *      data-prevent-default
 *      data-stop-propagation>Sign out</a>
 *
 * For per-element parameters, declare extra `data-*` attributes; the
 * dispatched function receives them as its second argument:
 *
 *   <button data-click-action="addNote" data-case-id="42">Add note</button>
 *   function addNote(event, dataset) { console.log(dataset.caseId); }
 *
 * Special-purpose built-in delegations:
 *
 *   [data-close-target="someElementId"]
 *       Hides the element with that id when clicked.
 *
 *   [data-close-on-self-click]
 *       If a click hits THIS element directly (not bubbled from a
 *       child), hide it. Pairs with [data-close-target] for the close
 *       button + the click-outside-the-modal pattern on the same modal.
 *
 *   [data-script-onerror-flag="windowFlagName"] on a <script> tag
 *       Replaces the inline `onerror="window.__foo=true"` pattern. The
 *       helper attaches an error listener that sets window[flagName]=true
 *       when the script fails to load. Note: <script> needs the attribute
 *       BEFORE the browser parses it for the helper to attach in time —
 *       but `<script>` elements with src= fire onerror only when the
 *       fetch fails, which gives the helper time to attach during
 *       document parsing. If precise pre-parse handling is needed, use
 *       an inline `<script nonce>` block right after the failing tag.
 *
 * Looking up the action function:
 *   - `window[name]` first (most ION JS exposes functions as globals)
 *   - Logs at debug level if missing — helps catch typos during migration
 *
 * The helper is intentionally tiny and dependency-free; load it before
 * page-specific JS so delegation is wired by the time the first user
 * click can fire.
 */
(function () {
  'use strict';

  var EVENT_ATTRS = {
    click: 'data-click-action',
    change: 'data-change-action',
    input: 'data-input-action',
    submit: 'data-submit-action',
    keydown: 'data-keydown-action',
    keyup: 'data-keyup-action',
    blur: 'data-blur-action',
    focus: 'data-focus-action',
  };

  function pickAction(target, attr) {
    var el = target.closest('[' + attr + ']');
    if (!el) return null;
    return { el: el, name: el.getAttribute(attr) };
  }

  function buildDataset(el) {
    // Copy the dataset *excluding* the action-binding and built-in
    // control attributes so the receiving function gets a clean view of
    // template-supplied parameters.
    var skip = new Set([
      'clickAction', 'changeAction', 'inputAction', 'submitAction',
      'keydownAction', 'keyupAction', 'blurAction', 'focusAction',
      'preventDefault', 'stopPropagation',
      'closeTarget', 'closeOnSelfClick',
    ]);
    var out = {};
    for (var key in el.dataset) {
      if (skip.has(key)) continue;
      out[key] = el.dataset[key];
    }
    return out;
  }

  function dispatch(event, attr) {
    var hit = pickAction(event.target, attr);
    if (!hit) return;
    if (hit.el.hasAttribute('data-prevent-default')) event.preventDefault();
    if (hit.el.hasAttribute('data-stop-propagation')) event.stopPropagation();
    var fn = window[hit.name];
    if (typeof fn !== 'function') {
      // Surface during development; non-fatal so partial migrations don't
      // brick navigation.
      if (window.console && console.debug) {
        console.debug('[delegation] missing action:', hit.name);
      }
      return;
    }
    try {
      fn.call(hit.el, event, buildDataset(hit.el));
    } catch (err) {
      if (window.console && console.error) {
        console.error('[delegation] action', hit.name, 'threw:', err);
      }
    }
  }

  // Register the per-event delegated dispatchers.
  for (var evt in EVENT_ATTRS) {
    (function (e, attr) {
      document.addEventListener(e, function (event) { dispatch(event, attr); });
    }(evt, EVENT_ATTRS[evt]));
  }

  // Built-in: close-target — hide the element whose id matches.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-close-target]');
    if (!trigger) return;
    var targetId = trigger.getAttribute('data-close-target');
    var target = document.getElementById(targetId);
    if (target) target.style.display = 'none';
  });

  // Built-in: close-on-self-click — hide self when the click was on
  // this element directly (modal-backdrop pattern). Won't fire if the
  // click bubbled from a child.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-close-on-self-click]');
    if (!trigger) return;
    if (event.target === trigger) {
      trigger.style.display = 'none';
    }
  });

  // Built-in: data-script-onerror-flag — replaces inline `onerror=` on
  // optional-dependency <script> tags.
  function wireScriptErrorFlags() {
    var scripts = document.querySelectorAll('script[data-script-onerror-flag]');
    scripts.forEach(function (s) {
      var flag = s.getAttribute('data-script-onerror-flag');
      if (!flag) return;
      s.addEventListener('error', function () {
        window[flag] = true;
      }, { once: true });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireScriptErrorFlags);
  } else {
    wireScriptErrorFlags();
  }
}());
