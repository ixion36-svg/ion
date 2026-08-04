/*
 * ion-dynamic-styles.js — restores the styling lost by the v0.31.21 migration.
 *
 * That migration hashed inline styles into static CSS classes. Where the style
 * was a JS template literal (`style="width:${pct}%"`), it emitted a STATIC rule
 * containing the literal `${pct}` — e.g.
 *
 *     ._ion-s-95aea49e0e { width:${pct}%; }
 *
 * which is invalid CSS. Browsers drop the bad declaration, so the dynamic part
 * silently never applied: progress bars had no width, severity text no colour,
 * collapsible panels no display toggle. 125 rules were affected across 29
 * templates and the breakage went unnoticed for ~40 releases.
 *
 * The fix moves the dynamic declarations back to the element as a
 * `data-ion-style` attribute (the template literal interpolates normally again)
 * and applies them here via `el.style.setProperty`, which is CSP-safe — it is a
 * DOM property write, not an inline `style=` attribute, so no `unsafe-inline`
 * is required.
 *
 * A MutationObserver covers every render path. ION templates build markup with
 * innerHTML in dozens of places; hunting each call site would guarantee misses,
 * and a missed site is invisible (it just doesn't style).
 */
(function () {
  "use strict";

  var ATTR = "data-ion-style";

  /* Split on ';' at depth 0 — a value may itself contain ';' inside quotes,
     e.g. background:rgba(0,0,0,.2);color:#9e9e9e emitted as one fallback. */
  function splitDecls(text) {
    var out = [];
    var buf = "";
    var quote = null;
    var depth = 0;
    for (var i = 0; i < text.length; i++) {
      var c = text.charAt(i);
      if (quote) {
        if (c === quote && text.charAt(i - 1) !== "\\") quote = null;
        buf += c;
      } else if (c === '"' || c === "'") {
        quote = c;
        buf += c;
      } else if (c === "(") {
        depth++;
        buf += c;
      } else if (c === ")") {
        depth--;
        buf += c;
      } else if (c === ";" && depth === 0) {
        if (buf.trim()) out.push(buf.trim());
        buf = "";
      } else {
        buf += c;
      }
    }
    if (buf.trim()) out.push(buf.trim());
    return out;
  }

  function applyTo(el) {
    var raw = el.getAttribute(ATTR);
    if (raw === null) return;
    var decls = splitDecls(raw);
    for (var i = 0; i < decls.length; i++) {
      var idx = decls[i].indexOf(":");
      if (idx <= 0) continue;
      var prop = decls[i].slice(0, idx).trim();
      var val = decls[i].slice(idx + 1).trim();
      if (!prop || !val) continue;
      try {
        /* setProperty validates and ignores anything malformed, so a bad value
           degrades to "unstyled" rather than throwing mid-render. Custom
           properties (--foo) are supported by the same call. */
        el.style.setProperty(prop, val);
      } catch (e) { /* ignore a single bad declaration */ }
    }
    /* Remove so re-scanning a subtree is idempotent and cheap. */
    el.removeAttribute(ATTR);
  }

  function scan(root) {
    if (!root || root.nodeType !== 1) return;
    if (root.hasAttribute && root.hasAttribute(ATTR)) applyTo(root);
    if (root.querySelectorAll) {
      var nodes = root.querySelectorAll("[" + ATTR + "]");
      for (var i = 0; i < nodes.length; i++) applyTo(nodes[i]);
    }
  }

  function start() {
    scan(document.body || document.documentElement);
    if (typeof MutationObserver === "undefined") return;
    new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) scan(added[j]);
        /* innerHTML on an existing node fires as attribute/child changes on the
           target too, so re-scan it. */
        if (records[i].type === "attributes") scan(records[i].target);
      }
    }).observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: [ATTR],
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }

  /* Exposed for templates that render before the observer attaches, or that
     want to force a pass immediately after building markup. */
  window.applyIonDynamicStyles = scan;
})();
