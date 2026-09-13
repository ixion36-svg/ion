/* Attach the CSRF token to same-origin state-changing requests.
 *
 * ION has 616 fetch call sites across templates and static JS and no central
 * wrapper. Patching window.fetch here covers every one of them, and everything
 * written later, without touching a single call site. The htmx:configRequest
 * listener does the same for hx-post / hx-put attributes.
 *
 * Cross-origin requests are deliberately left untouched, so the token is never
 * sent to a third party.
 *
 * ES5 only: no arrow functions, no short variable declarations beyond var, no
 * template literals. Matches the rest of static/js and avoids a build step.
 */
(function () {
    "use strict";

    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute("content") : "";
    if (!token) {
        return;  // Anonymous page: nothing to attach, nothing to protect.
    }

    var UNSAFE = /^(POST|PUT|PATCH|DELETE)$/i;
    var HEADER = "X-CSRF-Token";

    function sameOrigin(url) {
        try {
            return new URL(url, window.location.href).origin === window.location.origin;
        } catch (e) {
            return false;  // Unparseable: treat as foreign and send nothing.
        }
    }

    var nativeFetch = window.fetch;
    if (typeof nativeFetch === "function") {
        window.fetch = function (input, init) {
            var opts = init || {};
            var isRequest = (typeof Request !== "undefined") && (input instanceof Request);
            var url = isRequest ? input.url : String(input);
            var method = opts.method || (isRequest ? input.method : "GET");

            if (UNSAFE.test(method) && sameOrigin(url)) {
                var headers = new Headers(opts.headers || (isRequest ? input.headers : {}));
                if (!headers.has(HEADER)) {
                    headers.set(HEADER, token);
                }
                var merged = {};
                for (var key in opts) {
                    if (Object.prototype.hasOwnProperty.call(opts, key)) {
                        merged[key] = opts[key];
                    }
                }
                merged.headers = headers;
                opts = merged;
            }
            return nativeFetch.call(this, input, opts).then(function (response) {
                if (response.status === 403) {
                    // Clone before reading: the caller still needs the body.
                    response.clone().json().then(function (body) {
                        if (body && body.code === "csrf_invalid") {
                            // The token is derived from the session, so an
                            // invalid token means the session itself is gone.
                            // Nothing to refresh to — send them to re-login.
                            window.location.href = "/login?redirect=" +
                                encodeURIComponent(window.location.pathname);
                        }
                    })["catch"](function () {
                        // A 403 that is not ours (permission denied, or a
                        // non-JSON body). Leave it to the caller.
                    });
                }
                return response;
            });
        };
    }

    // Listen on document rather than document.body: this script may run from
    // <head>, before body exists. htmx events bubble to document.
    document.addEventListener("htmx:configRequest", function (evt) {
        if (evt.detail && UNSAFE.test(evt.detail.verb || "")) {
            evt.detail.headers[HEADER] = token;
        }
    });
})();
