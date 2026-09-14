/**
 * Estate switcher — which Elasticsearch/Kibana the analyst is looking at.
 *
 * Renders nothing at all unless multi-tenancy is on AND the analyst has more
 * than one estate, so a single-estate deploy and a tenant-bound analyst both
 * see an unchanged header.
 *
 * Switching sets a cookie server-side and reloads. A reload rather than a
 * re-render because every open panel on the page was populated from the
 * previous estate — leaving them would show one estate's alerts under another
 * estate's label, which is worse than a flash of loading.
 */
(function () {
    "use strict";

    var MOUNT = "tenant-switcher";

    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
    }

    function render(mount, state) {
        if (!state || !state.enabled || !state.can_switch) {
            mount.classList.add("hidden");
            mount.innerHTML = "";
            return;
        }

        var activeSlug = state.active ? state.active.slug : null;
        var html =
            '<span class="hidden lg:inline text-[11px] text-slate-500">Estate</span>';

        if (state.available.length <= 3) {
            html +=
                '<div class="flex items-center gap-0.5 rounded-md bg-white/5 p-0.5"' +
                ' role="group" aria-label="Estate">';
            state.available.forEach(function (t) {
                var on = t.slug === activeSlug;
                html +=
                    '<button type="button" class="h-7 px-2.5 rounded text-[11px] transition ' +
                    (on
                        ? "bg-white/10 text-white font-medium"
                        : "text-slate-400 hover:bg-white/5 hover:text-slate-200") +
                    '" data-tenant-slug="' + esc(t.slug) + '"' +
                    (on ? ' aria-current="true"' : "") +
                    ' title="' + esc(t.name) + '">' +
                    esc(t.name) +
                    "</button>";
            });
            html += "</div>";
        } else {
            html +=
                '<select class="h-7 rounded-md bg-white/5 px-2 text-[11px] text-slate-300"' +
                ' aria-label="Estate">';
            state.available.forEach(function (t) {
                html +=
                    '<option value="' + esc(t.slug) + '"' +
                    (t.slug === activeSlug ? " selected" : "") +
                    ">" + esc(t.name) + "</option>";
            });
            html += "</select>";
        }

        mount.innerHTML = html;
        mount.classList.remove("hidden");
        wire(mount);
    }

    function wire(mount) {
        // Listeners are attached directly: base.html's delegated dispatcher is
        // available here, but this element is rebuilt on every state fetch and
        // direct binding keeps that self-contained.
        mount.querySelectorAll("[data-tenant-slug]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                switchTo(btn.getAttribute("data-tenant-slug"), btn);
            });
        });
        var select = mount.querySelector("select");
        if (select) {
            select.addEventListener("change", function () {
                switchTo(select.value, select);
            });
        }
    }

    function switchTo(slug, el) {
        if (!slug || el.disabled) return;
        el.disabled = true;
        fetch("/api/tenants/switch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ slug: slug }),
        })
            .then(function (r) {
                if (!r.ok) {
                    return r.json().then(
                        function (b) { throw new Error(b.detail || "Switch failed"); },
                        function () { throw new Error("Switch failed (" + r.status + ")"); }
                    );
                }
                window.location.reload();
            })
            .catch(function (err) {
                el.disabled = false;
                if (typeof window.showToast === "function") {
                    window.showToast(err.message || "Could not switch estate", "error");
                } else {
                    console.error("tenant switch:", err);
                }
            });
    }

    function init() {
        var mount = document.getElementById(MOUNT);
        if (!mount) return;
        fetch("/api/tenants", { credentials: "include" })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (state) { render(mount, state); })
            .catch(function () {
                // Single-estate deploys and logged-out pages land here; the
                // switcher simply stays hidden.
                mount.classList.add("hidden");
            });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
