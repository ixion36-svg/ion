/* Arranged window: sections an analyst can move between columns, fold, hide
 * and restore, with one arrangement remembered per kind of window.
 *
 * This was written for the case window (after TIDE v6) and lived inline in
 * cases.html, addressed to #case-panel and .cpanel-section. The alert window
 * needs the same thing, and a second copy would drift, so it moved here and
 * takes what differed as configuration. The saved layout's shape is the one
 * the case window already wrote, so nobody's arrangement is lost.
 *
 *   var arranger = ionArrange.create({
 *     body:            element the sections live in; the grid is appended to it
 *     candidates:      selector for the sections to arrange, within body
 *     storageKey:      localStorage key for this kind of window
 *     columns:         { name: track width }, in order; a null width is a
 *                      row spanning every track rather than a track
 *     defaultCol:      function (key, section) -> column name
 *     presets:         [{ id, label, col: function (key, section) or null }];
 *                      a null col means defaultCol
 *     keyFor:          function (section, seen) -> stable key for the section
 *     titleOf:         function (section) -> its title element, or null
 *     headOf:          function (section) -> a head the section already has,
 *                      or null to have one built (handle, title, fold)
 *     collapsedClass:  class that folds a section (default pm-collapsed)
 *     defaultCollapsed: function (key) -> folded when a preset is applied
 *     toolsHost:       element the Sections button and menu are added to
 *     toolsBefore:     child of toolsHost to insert them before, or null
 *     nav:             [{ label, title, onClick }] buttons placed before Sections
 *     onChange:        called after any change to the arrangement
 *   });
 *   arranger.apply();   // after each render of body; safe to repeat
 *
 * A key the current window does not have keeps its saved place and flags
 * (TIDE's merge), so arranging a sparse window never forgets a fuller one.
 */
(function () {
  'use strict';

  // TIDE's merge. `now` is what this window shows; `saved` is what was
  // remembered. A key this window does not have keeps its saved column, its
  // place after the neighbour it followed, and its hidden and folded flags.
  // Returns `now`, extended.
  function mergeLayout(now, saved) {
    var present = {};
    Object.keys(now.cols).forEach(function (c) {
      now.cols[c].forEach(function (k) { present[k] = true; });
    });
    if (!saved || !saved.cols) return now;
    Object.keys(saved.cols).forEach(function (c) {
      var list = now.cols[c] || (now.cols[c] = []);
      (saved.cols[c] || []).forEach(function (k, i) {
        if (present[k] || list.indexOf(k) !== -1) return;
        var after = i > 0 ? list.indexOf(saved.cols[c][i - 1]) : -1;
        list.splice(after !== -1 ? after + 1 : Math.min(i, list.length), 0, k);
      });
    });
    (saved.hidden || []).forEach(function (k) {
      if (!present[k] && now.hidden.indexOf(k) === -1) now.hidden.push(k);
    });
    (saved.collapsed || []).forEach(function (k) {
      if (!present[k] && now.collapsed.indexOf(k) === -1) now.collapsed.push(k);
    });
    return now;
  }

  function create(cfg) {
    var body = cfg.body;
    var collapsedClass = cfg.collapsedClass || 'pm-collapsed';
    var colNames = Object.keys(cfg.columns);
    var dragging = null;
    var wired = false;
    var order = {};       // key -> position as rendered, before any arranging
    var marker = document.createElement('div');
    marker.className = 'pm-drop-marker';

    function readLayout() {
      try { return JSON.parse(localStorage.getItem(cfg.storageKey) || 'null'); }
      catch (_) { return null; }
    }
    function writeLayout(v) {
      try { localStorage.setItem(cfg.storageKey, JSON.stringify(v)); } catch (_) { /* blocked */ }
    }

    function sections() {
      return Array.prototype.slice.call(body.querySelectorAll('.pm-col > .pm-section[data-section]'));
    }
    function cols() {
      return Array.prototype.slice.call(body.querySelectorAll('.pm-col'));
    }
    function colEl(name) {
      return body.querySelector('.pm-col[data-col="' + name + '"]');
    }
    function sectionsIn(col) {
      return Array.prototype.filter.call(col.children, function (el) {
        return el.classList.contains('pm-section');
      });
    }
    function changed() { if (cfg.onChange) cfg.onChange(); }

    function currentLayout() {
      var out = { cols: {}, hidden: [], collapsed: [] };
      cols().forEach(function (col) {
        out.cols[col.dataset.col] = sectionsIn(col).map(function (sec) {
          var k = sec.dataset.section;
          if (sec.hidden) out.hidden.push(k);
          if (sec.classList.contains(collapsedClass)) out.collapsed.push(k);
          return k;
        });
      });
      return out;
    }

    function save() {
      writeLayout(mergeLayout(currentLayout(), readLayout()));
      changed();
    }

    // An empty column gives its width back, except while a drag needs
    // somewhere to drop.
    function fitCols() {
      var widths = [];
      cols().forEach(function (col) {
        var any = sectionsIn(col).some(function (sec) { return !sec.hidden; });
        col.classList.toggle('pm-col--empty', !any && !dragging);
        var width = cfg.columns[col.dataset.col];
        if (width == null) return;      // a spanning row is not a track
        if (any || dragging) widths.push(width);
      });
      body.querySelector('.pm-cols').style.setProperty('--pm-cols', widths.join(' ') || '1fr');
    }

    function arrange(layout) {
      var byKey = {};
      sections().forEach(function (sec) { byKey[sec.dataset.section] = sec; });
      cols().forEach(function (col) {
        ((layout.cols || {})[col.dataset.col] || []).forEach(function (k) {
          if (byKey[k]) { col.appendChild(byKey[k]); delete byKey[k]; }
        });
      });
      var hidden = layout.hidden || [], collapsed = layout.collapsed || [];
      sections().forEach(function (sec) {
        sec.hidden = hidden.indexOf(sec.dataset.section) !== -1;
        sec.classList.toggle(collapsedClass, collapsed.indexOf(sec.dataset.section) !== -1);
      });
      fitCols();
    }

    function presetById(id) {
      for (var i = 0; i < cfg.presets.length; i++) {
        if (cfg.presets[i].id === id) return cfg.presets[i];
      }
      return null;
    }

    function applyPreset(id) {
      var preset = presetById(id);
      var pick = (preset && preset.col) || cfg.defaultCol;
      // In rendered order, not the order a drag left them in: a preset, and
      // Reset with it, puts a section back where it started.
      sections().sort(function (a, b) {
        return order[a.dataset.section] - order[b.dataset.section];
      }).forEach(function (sec) {
        var key = sec.dataset.section;
        colEl(pick(key, sec)).appendChild(sec);
        sec.hidden = false;
        sec.classList.toggle(collapsedClass, !!(cfg.defaultCollapsed && cfg.defaultCollapsed(key)));
      });
      fitCols();
      save();
    }

    function wireDrag() {
      body.addEventListener('dragstart', function (e) {
        var h = e.target.closest && e.target.closest('.pm-handle');
        if (!h) return;
        dragging = h.closest('.pm-section');
        dragging.classList.add('pm-dragging');
        cols().forEach(function (c) { c.classList.add('pm-col--drop'); });
        fitCols();
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setDragImage(dragging, 20, 14); } catch (_) { /* optional */ }
      });
      body.addEventListener('dragover', function (e) {
        if (!dragging) return;
        var col = e.target.closest && e.target.closest('.pm-col');
        if (!col) return;
        e.preventDefault();
        var after = null;
        sectionsIn(col).some(function (sec) {
          if (sec === dragging) return false;
          if (e.clientY < sec.getBoundingClientRect().top + sec.offsetHeight / 2) { after = sec; return true; }
          return false;
        });
        if (after) col.insertBefore(marker, after); else col.appendChild(marker);
      });
      body.addEventListener('drop', function (e) {
        if (!dragging) return;
        e.preventDefault();
        if (marker.parentElement) marker.parentElement.insertBefore(dragging, marker);
      });
      body.addEventListener('dragend', function () {
        if (!dragging) return;
        dragging.classList.remove('pm-dragging');
        dragging = null;
        marker.remove();
        cols().forEach(function (c) { c.classList.remove('pm-col--drop'); });
        fitCols();
        save();
      });
    }

    function button(label, title) {
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'pm-tool-btn';
      b.textContent = label;
      if (title) b.title = title;
      return b;
    }

    function injectTools() {
      var hostEl = cfg.toolsHost;
      if (!hostEl || hostEl.querySelector('.pm-tools')) return;
      var tools = document.createElement('span');
      tools.className = 'pm-tools';

      (cfg.nav || []).forEach(function (n) {
        var b = button(n.label, n.title);
        b.addEventListener('click', n.onClick);
        tools.appendChild(b);
      });

      var btn = button('Sections ▾');
      var menu = document.createElement('div');
      menu.className = 'pm-menu';

      function rebuild() {
        menu.textContent = '';
        var presets = document.createElement('div');
        presets.className = 'pm-preset-row';
        cfg.presets.forEach(function (p) {
          var pb = button(p.label);
          pb.addEventListener('click', function () { applyPreset(p.id); rebuild(); });
          presets.appendChild(pb);
        });
        menu.appendChild(presets);
        menu.appendChild(document.createElement('hr'));
        sections().forEach(function (sec) {
          var label = document.createElement('label');
          var box = document.createElement('input');
          box.type = 'checkbox';
          box.checked = !sec.hidden;
          box.addEventListener('change', function () {
            sec.hidden = !box.checked;
            fitCols();
            save();
          });
          label.appendChild(box);
          var t = cfg.titleOf(sec);
          label.appendChild(document.createTextNode(
            (t ? t.textContent : sec.dataset.section).replace(/\s+/g, ' ').trim()));
          menu.appendChild(label);
        });
        menu.appendChild(document.createElement('hr'));
        var reset = document.createElement('button');
        reset.type = 'button';
        reset.className = 'pm-reset';
        reset.textContent = 'Reset arrangement';
        reset.addEventListener('click', function () {
          try { localStorage.removeItem(cfg.storageKey); } catch (_) { /* blocked */ }
          applyPreset(cfg.presets[0].id);
          menu.classList.remove('pm-open');
        });
        menu.appendChild(reset);
      }
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        rebuild();
        menu.classList.toggle('pm-open');
      });
      document.addEventListener('click', function (e) {
        if (!menu.contains(e.target)) menu.classList.remove('pm-open');
      });

      tools.appendChild(btn);
      tools.appendChild(menu);
      hostEl.insertBefore(tools, cfg.toolsBefore || null);
    }

    function handle() {
      var h = document.createElement('button');
      h.type = 'button';
      h.className = 'pm-handle';
      h.textContent = '≡';
      h.title = 'Drag to move this section';
      h.draggable = true;
      return h;
    }

    // Give a section its chrome. One that brings a head keeps it and gains a
    // handle; one that does not gets a head built around its title.
    function adopt(sec) {
      var head = cfg.headOf ? cfg.headOf(sec) : null;
      var grip = handle();
      if (head) {
        head.insertBefore(grip, head.firstChild);
      } else {
        var title = cfg.titleOf(sec);
        head = document.createElement('div');
        head.className = 'pm-sec-head';
        head.appendChild(grip);
        if (title) head.appendChild(title);
        var fold = document.createElement('span');
        fold.className = 'pm-fold';
        fold.textContent = '▼';
        head.appendChild(fold);
        var wrap = document.createElement('div');
        wrap.className = 'pm-sec-body';
        while (sec.firstChild) wrap.appendChild(sec.firstChild);
        sec.appendChild(head);
        sec.appendChild(wrap);
      }
      head.addEventListener('click', function (e) {
        if (e.target.closest('button:not(.pm-handle), a, select, input')) return;
        if (e.target === grip) return;
        sec.classList.toggle(collapsedClass);
        save();
      });
      sec.classList.add('pm-section');
    }

    // Returns true when it built the grid, false when one was already there.
    function apply() {
      if (body.querySelector('.pm-cols')) return false;
      var grid = document.createElement('div');
      grid.className = 'pm-cols';
      colNames.forEach(function (c) {
        var col = document.createElement('div');
        col.className = 'pm-col';
        col.dataset.col = c;
        grid.appendChild(col);
      });

      var seen = {};
      order = {};
      Array.prototype.forEach.call(body.querySelectorAll(cfg.candidates), function (sec, i) {
        var key = cfg.keyFor(sec, seen);
        sec.dataset.section = key;
        order[key] = i;
        adopt(sec);
        grid.querySelector('.pm-col[data-col="' + cfg.defaultCol(key, sec) + '"]').appendChild(sec);
      });

      body.appendChild(grid);
      if (!wired) { wireDrag(); wired = true; }
      var saved = readLayout();
      if (saved && saved.cols) arrange(saved); else fitCols();
      injectTools();
      changed();
      return true;
    }

    return { apply: apply, applyPreset: applyPreset, sections: sections };
  }

  window.ionArrange = { create: create, mergeLayout: mergeLayout };
})();
