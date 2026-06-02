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
      // v0.31.19: simple-pattern data-attributes for the P11 final-mile cleanup.
      'windowPrint', 'clickTarget', 'toggleParentClass',
      'enterKeyAction', 'escapeKeyAction',
      'validatingSubmitAction', 'clearTarget', 'toggleNextDisplay',
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

  // v0.31.23 (code review): action-name dispatch hardening. The function
  // name comes from a DOM attribute, so stored-XSS that lands inside or
  // adjacent to a real element could inject `data-click-action="eval"` or
  // `data-validating-submit-action="fetch"` to redirect dispatch onto a
  // dangerous global. Two defences:
  //
  // 1. ACTION_NAME_RE — accept only the camelCase-identifier shape that
  //    every ION action follows. Rejects things like `eval`, `Function`,
  //    `window.constructor`, `["alert"]`, etc.  Matches conservatively;
  //    legit ION functions all start with a lower-case letter or
  //    underscore and use only letters / digits / underscores.
  // 2. ACTION_DENYLIST — explicit deny for known-dangerous globals that
  //    would slip past the regex (`alert`, `fetch`, etc. are technically
  //    valid identifiers). Belt-and-braces.
  var ACTION_NAME_RE = /^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/;
  var ACTION_DENYLIST = new Set([
    'eval', 'Function', 'setTimeout', 'setInterval',
    'alert', 'confirm', 'prompt',
    'fetch', 'XMLHttpRequest', 'WebSocket',
    'open', 'close', 'postMessage',
    'location', 'history', 'navigator',
    'document', 'window', 'self', 'top', 'parent',
    'localStorage', 'sessionStorage', 'indexedDB',
    'importScripts', 'Worker', 'SharedWorker', 'ServiceWorker',
  ]);

  function resolveAction(name) {
    // Null/undefined is the "no attribute" case — return silently. The
    // dispatch path will fall through to the existing debug-log branch
    // for the "function not defined" case rather than spamming warnings.
    if (typeof name !== 'string' || !name) return null;
    if (!ACTION_NAME_RE.test(name)) {
      if (window.console && console.warn) {
        console.warn('[delegation] rejected action name (bad shape):', name);
      }
      return null;
    }
    if (ACTION_DENYLIST.has(name)) {
      if (window.console && console.warn) {
        console.warn('[delegation] rejected action name (denylist):', name);
      }
      return null;
    }
    var fn = window[name];
    return typeof fn === 'function' ? fn : null;
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
    // An element carrying `data-stop-propagation` BETWEEN the click target and
    // the action element must suppress that action — it mirrors a real
    // stopPropagation listener on that intermediate element, which would have
    // halted the bubble before it reached the ancestor's handler. Without this,
    // e.g. clicking a checkbox inside `<td data-stop-propagation>` still fires
    // the surrounding `<tr data-click-action>` (the alert row opened on a
    // checkbox click). The on-the-action-element case is handled at line ~below.
    var stopper = event.target.closest('[data-stop-propagation]');
    if (stopper && stopper !== hit.el && hit.el.contains(stopper)) {
      var pd = event.target.closest('[data-prevent-default]');
      if (pd && pd !== hit.el && hit.el.contains(pd)) event.preventDefault();
      event.stopPropagation();
      return;
    }
    // `data-only-self-click` gates the action on the click being a direct
    // hit on this element (not bubbled from a child). Mirrors the inline
    // `if(event.target===this) ...` modal-backdrop pattern.
    if (hit.el.hasAttribute('data-only-self-click') && event.target !== hit.el) return;
    if (hit.el.hasAttribute('data-prevent-default')) event.preventDefault();
    if (hit.el.hasAttribute('data-stop-propagation')) event.stopPropagation();
    var fn = resolveAction(hit.name);
    if (!fn) {
      // Surface during development; non-fatal so partial migrations don't
      // brick navigation. resolveAction emits its own warning for the
      // bad-shape / denylist rejection paths; this debug line covers the
      // "function not defined" case.
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

  // Built-in: data-window-print — fires window.print(). Replaces
  // `onclick="window.print()"` print-button pattern.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-window-print]');
    if (!trigger) return;
    window.print();
  });

  // Built-in: data-click-target — programmatically click another element
  // by id. Replaces `onclick="document.getElementById('X').click()"`
  // file-input proxy pattern (visible button delegates to a hidden input).
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-click-target]');
    if (!trigger) return;
    var targetId = trigger.getAttribute('data-click-target');
    var target = document.getElementById(targetId);
    if (target) target.click();
  });

  // Built-in: data-toggle-parent-class — toggle a class on this element's
  // parentElement. Replaces inline
  // `onclick="this.parentElement.classList.toggle('open')"` accordion /
  // disclosure pattern.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-toggle-parent-class]');
    if (!trigger) return;
    var cls = trigger.getAttribute('data-toggle-parent-class');
    if (cls && trigger.parentElement) {
      trigger.parentElement.classList.toggle(cls);
    }
  });

  // Built-in: data-enter-key-action / data-escape-key-action — fire the named
  // function when the user presses Enter / Escape on this element. Replaces
  // the inline `onkeydown="if(event.key==='Enter')fn()"` input-on-Enter
  // pattern; common on free-text inputs that submit on Enter.
  // Reads optional data-args (same JSON convention as the action dispatchers).
  function keyHandler(keyName, attr) {
    return function (event) {
      if (event.key !== keyName) return;
      var trigger = event.target.closest('[' + attr + ']');
      if (!trigger) return;
      var name = trigger.getAttribute(attr);
      var fn = resolveAction(name);
      if (!fn) return;
      var argsAttr = trigger.dataset.args;
      var args = [];
      if (argsAttr) {
        try { args = JSON.parse(argsAttr); }
        catch (e) { return; }
        args = substituteRuntimeArgs(args, event);
      }
      if (trigger.hasAttribute('data-prevent-default')) event.preventDefault();
      fn.apply(trigger, args);
    };
  }
  document.addEventListener('keydown', keyHandler('Enter', 'data-enter-key-action'));
  document.addEventListener('keydown', keyHandler('Escape', 'data-escape-key-action'));

  // Built-in: data-validating-submit-action — fire the named function on form
  // submit; if it returns falsy, call event.preventDefault(). Replaces the
  // legacy `onsubmit="return canSubmit(event)"` pattern from form validators.
  // v0.31.23: name goes through resolveAction() so the regex + denylist
  // applies here too.
  document.addEventListener('submit', function (event) {
    var trigger = event.target.closest('[data-validating-submit-action]');
    if (!trigger) return;
    var name = trigger.getAttribute('data-validating-submit-action');
    var fn = resolveAction(name);
    if (!fn) return;
    var result = fn(event);
    if (!result) event.preventDefault();
  });

  // Built-in: data-clear-target — clear the .value of the element with that id.
  // Replaces `onclick="document.getElementById('X').value = ''"`.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-clear-target]');
    if (!trigger) return;
    var targetId = trigger.getAttribute('data-clear-target');
    var target = document.getElementById(targetId);
    if (target) target.value = '';
  });

  // Built-in: data-toggle-next-display — toggle display:none / display:block on
  // this element's nextElementSibling. Replaces inline DOM-toggle pattern.
  document.addEventListener('click', function (event) {
    var trigger = event.target.closest('[data-toggle-next-display]');
    if (!trigger) return;
    var nxt = trigger.nextElementSibling;
    if (!nxt) return;
    nxt.style.display = nxt.style.display === 'none' ? 'block' : 'none';
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
