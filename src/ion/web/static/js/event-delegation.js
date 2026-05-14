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
    // v0.31.5: drag and drop for the Kanban + Workbench surfaces.
    dragstart: 'data-dragstart-action',
    dragend: 'data-dragend-action',
    dragover: 'data-dragover-action',
    dragenter: 'data-dragenter-action',
    dragleave: 'data-dragleave-action',
    drop: 'data-drop-action',
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
      'dragstartAction', 'dragendAction', 'dragoverAction',
      'dragenterAction', 'dragleaveAction', 'dropAction',
      'preventDefault', 'stopPropagation', 'onlySelfClick',
      'closeTarget', 'closeOnSelfClick', 'args',
      'removeTarget', 'removeSelfOnSelfClick', 'scriptOnerrorFlag',
      'removeParent', 'removeClosest',
    ]);
    var out = {};
    for (var key in el.dataset) {
      if (skip.has(key)) continue;
      out[key] = el.dataset[key];
    }
    return out;
  }

  function substituteRuntimeArgs(args, event) {
    // Sentinel tokens for values only known at click time. The original
    // `onclick="foo(this.value)"` form encoded these implicitly; we
    // need an explicit marker now.
    //   "$event"   → the Event object itself (DragEvent, MouseEvent, ...)
    //   "$value"   → event.target.value (form fields)
    //   "$checked" → event.target.checked (checkboxes / radios)
    //   "$target"  → event.target (raw element reference)
    return args.map(function (a) {
      if (a === '$event') return event;
      if (a === '$value') return event.target.value;
      if (a === '$checked') return event.target.checked;
      if (a === '$target') return event.target;
      return a;
    });
  }

  function dispatch(event, attr) {
    var hit = pickAction(event.target, attr);
    if (!hit) {
      // No action attribute on this element. Still honour bare event-control
      // attributes — replaces the `onclick="event.stopPropagation()"` pattern
      // where there's no function call, only event-flow control.
      var ctrl = event.target.closest('[data-stop-propagation],[data-prevent-default]');
      if (ctrl) {
        if (ctrl.hasAttribute('data-stop-propagation')) event.stopPropagation();
        if (ctrl.hasAttribute('data-prevent-default')) event.preventDefault();
      }
      return;
    }
    // `data-only-self-click` gates the action on the click being a direct
    // hit on this element (not bubbled from a child). Mirrors the inline
    // `if(event.target===this) ...` modal-backdrop pattern.
    if (hit.el.hasAttribute('data-only-self-click') && event.target !== hit.el) return;
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
      // Two calling conventions, selected by which data-args attribute is set:
      //   (a) `data-${event}-args="[…]"` (e.g. data-click-args, data-drop-args)
      //       or fallback `data-args="[…]"` → fn.apply(el, args)
      //       — preserves existing positional-arg function signatures so
      //       templates can migrate inline `onclick="foo(a,b,c)"` calls
      //       without refactoring `foo`. Per-event variants exist for
      //       elements with multiple handlers needing different args
      //       (e.g. a kanban card with onclick={openCaseDetail(id)} AND
      //       ondragstart={onDragStart(event, id)}).
      //   (b) no args attribute → fn.call(el, event, dataset)
      //       — the cleaner contract used by base.html in v0.31.4. New
      //       handler functions should prefer this shape.
      var argsAttr = hit.el.getAttribute('data-' + event.type + '-args');
      if (argsAttr === null) argsAttr = hit.el.dataset.args !== undefined ? hit.el.dataset.args : null;
      if (argsAttr !== null) {
        var parsed;
        try {
          parsed = JSON.parse(argsAttr);
        } catch (jsonErr) {
          if (window.console && console.error) {
            console.error('[delegation] invalid data-args on action', hit.name, ':', hit.el.dataset.args, jsonErr);
          }
          return;
        }
        if (!Array.isArray(parsed)) {
          if (window.console && console.error) {
            console.error('[delegation] data-args must be a JSON array, got:', typeof parsed);
          }
          return;
        }
        fn.apply(hit.el, substituteRuntimeArgs(parsed, event));
      } else {
        fn.call(hit.el, event, buildDataset(hit.el));
      }
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

  // Built-in: remove-target — DELETE the element whose id matches from the DOM
  // (not just hide). Replaces the inline
  // `onclick="document.getElementById('foo').remove()"` pattern used for
  // dynamically-injected modals that should be destroyed on close.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-remove-target]');
    if (!trigger) return;
    var targetId = trigger.getAttribute('data-remove-target');
    var target = document.getElementById(targetId);
    if (target) target.remove();
  });

  // Built-in: remove-self-on-self-click — REMOVE this element on self-click.
  // Replaces `onclick="if(event.target===this)this.remove()"` for modal
  // backdrops that are destroyed (not just hidden) on outside-click.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-remove-self-on-self-click]');
    if (!trigger) return;
    if (event.target === trigger) trigger.remove();
  });

  // Built-in: remove-parent — remove the parent element of the clicked
  // control. Replaces `onclick="this.parentElement.remove()"` used on
  // dismiss-X buttons whose parent is a self-contained banner / chip.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-remove-parent]');
    if (!trigger) return;
    if (trigger.parentElement) trigger.parentElement.remove();
  });

  // Built-in: remove-closest — remove the closest ancestor matching the
  // CSS selector. Replaces `onclick="this.closest('.foo').remove()"`.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-remove-closest]');
    if (!trigger) return;
    var selector = trigger.getAttribute('data-remove-closest');
    if (!selector) return;
    var ancestor = trigger.closest(selector);
    if (ancestor) ancestor.remove();
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
