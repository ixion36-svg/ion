/* The public scoping questionnaire.
 *
 * Shows questions one at a time, revealing the next once the current one
 * is answered, and downloads the scoping pack PDF. The PDF goes through
 * fetch so the CSRF token csrf.js attaches rides along for a signed-in
 * visitor; an anonymous one has no session, so needs none. ES5.
 */
(function () {
    "use strict";

    var form = document.getElementById("scoping-form");
    if (!form) { return; }

    function answered(fieldset) {
        var inputs = fieldset.querySelectorAll("select, input");
        for (var i = 0; i < inputs.length; i++) {
            var el = inputs[i];
            if (el.type === "checkbox" ? el.checked : el.value) { return true; }
        }
        return false;
    }

    function reveal() {
        var fields = form.querySelectorAll("fieldset.scoping-question");
        var show = true;
        for (var i = 0; i < fields.length; i++) {
            fields[i].classList.toggle("hidden", !show);
            if (!answered(fields[i])) { show = false; }
        }
    }

    function downloadPdf(button) {
        button.disabled = true;
        fetch("/api/cyab/scoping/pdf", { method: "POST", body: new FormData(form), credentials: "same-origin" })
            .then(function (res) {
                if (!res.ok) { throw new Error("HTTP " + res.status); }
                var type = res.headers.get("Content-Type") || "";
                return res.blob().then(function (blob) { return { blob: blob, pdf: type.indexOf("pdf") !== -1 }; });
            })
            .then(function (out) {
                var url = URL.createObjectURL(out.blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = out.pdf ? "cyab-scoping.pdf" : "cyab-scoping.html";
                document.body.appendChild(a);
                a.click();
                a.remove();
                setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
            })
            .catch(function () { button.textContent = "Download failed, try again"; })
            .then(function () { button.disabled = false; });
    }

    document.addEventListener("click", function (event) {
        var button = event.target.closest && event.target.closest("[data-cyab-scoping-pdf]");
        if (button) { downloadPdf(button); }
    });

    // Converting needs an account. A signed-out visitor is sent to sign in
    // and brought back here.
    document.body.addEventListener("htmx:responseError", function (event) {
        if (event.detail.xhr.status === 401 || event.detail.xhr.status === 403) {
            window.location.href = "/login?redirect=" + encodeURIComponent("/cyab/scoping");
        }
    });

    reveal();
    form.addEventListener("change", reveal);
})();
